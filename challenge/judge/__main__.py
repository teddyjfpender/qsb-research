"""QSB design judge: python3 -m judge <submission_dir> [--seed N] [--out score.json]

Gates, in order (a design is scored only if every gate passes):
  0. integrity   the judge's trusted files match MANIFEST.sha256 (ranked runs use a pristine checkout)
  1. schema      design.json is well-formed data in the DSL; claims are rejected, never read
  2. build       the judge builds production + test-mode scripts itself (judge-chosen randomness)
  3. static      Core limits recomputed from bytes; the test-mode script is the production script with
                 only the puzzle hashes stood in; design_check() passes on the production script
  4. security    frozen analyser -> 2nd-preimage / quantum / collision bits (scored, reported in the
                 result vector) above the admissibility floors; expected honest solutions per round >= 1
  5. audit       adaptive-attacker freedom audit: measured choices <= analyser's S_i in every stage
  6. consensus   honest + negative vectors + realised audit runs replayed in Bitcoin Core (and the
                 Lean model): every verdict must match; Lean builder must rebuild the same bytes
  7. cost        GPU-hours from the frozen measured rate table, bytes from the production script and
                 honest scriptSig; result = vector (total sats at frozen prices, 2nd-preimage / quantum /
                 collision bits). Designs are compared by Pareto dominance, never by a scalar.
"""
import argparse
import hashlib
import json
import math
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
import qsb_pool as q  # noqa: E402

from . import audit, checks, consensus, cost, design  # noqa: E402


def manifest_ok():
    bad = []
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        h, rel = line.split(None, 1)
        f = ROOT / rel.strip()
        if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != h:
            bad.append(rel.strip())
    return bad


def lean_builder_check(cfg, prod, test):
    sys.path.insert(0, str(ROOT / "lean"))
    try:
        import export_scripts as ex
    except Exception as e:                                   # pragma: no cover
        return None, f"lean export unavailable: {e}"
    if not consensus.LEAN.exists():
        return None, "lean/qsbcheck not built"
    ents = []
    for name, b, tm in (("prod", prod, False), ("test", test, True)):
        ents.append(dict(name=name, params=ex.params(cfg, b), test_mode=tm, real_round_puzzle=False, pad_ops=0,
                         pad_bytes=0, dummies=[[d.hex() for d in ds] for ds in b["dummies"]],
                         pre=[[p.hex() for p in ps] for ps in b["pre"]], pre_j=[[p.hex() for p in ps] for ps in b["pre_j"]],
                         pre_l=[[p.hex() for p in ps] for ps in b["pre_l"]], script=b["script"].hex(), ops=b["ops"],
                         max_stack=b["max_stack"],
                         plan=[[a, m] for rp in b["plan"]["rounds"] for a, m in zip(rp["A"], rp["m"])]))
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "s.json"
        f.write_text(json.dumps(ents))
        out = subprocess.run([str(consensus.LEAN), "--scripts", str(f)], capture_output=True, text=True).stdout
    fails = [l for l in out.splitlines() if l.startswith("FAIL")]
    return (not fails), (fails[0] if fails else "Lean builder rebuilt identical bytes")


def proof_family(cfg):
    """Confidence label for the security bits: 'proven' when a frozen Lean soundness theorem covers the
    design's family, else 'audited' (freedom audit + Core replay: strong evidence, not proof)."""
    R = sum(1 for k in cfg if k.startswith("t") and k[1:].isdigit())
    if R == 1 and cfg["chain_pin"] == 1 and cfg["chain1"] == 1 and not cfg["sign_j"] and not cfg["sign_lvl"] \
            and cfg["force_comp"] and cfg["pool_deep"] and cfg.get("b1", 0) == 0:
        return dict(label="proven", theorem="QSB.TS2.ts2_family_sound",
                    note="family theorem; the instance side condition SideTS2 is checked by native_decide")
    return dict(label="audited", theorem=None, note="no Lean soundness theorem covers this family yet (M4/M5)")


MODES = {"screen": dict(audit_seeds=0, perturb=0, honest=0, realised=0),
         "standard": dict(audit_seeds=1, perturb=1, honest=150, realised=1),
         "deep": dict(audit_seeds=3, perturb=10, honest=1000, realised=3)}


def diagnostics(C, prod, an, cost_gate):
    """Where the design's slack is, so a search loop knows which constraint binds and which way to move."""
    fee = cost_gate["total_vbytes"] * C["fee_sat_per_vbyte"]
    gpu = cost_gate["gpu_hours_rtx4090"] * C["gpu_sats_per_hour"]
    return dict(
        headroom=dict(ops=201 - prod["ops"], script_bytes=10000 - len(prod["script"]),
                      min_expected_solutions=round(min(an["E"]), 2)),
        cost_split=dict(fee_sats=round(fee), gpu_sats=round(gpu), fee_share=round(fee / (fee + gpu), 3)),
        sats_at_other_fee_rates={f"{r}_sat_per_vB": round(cost_gate["total_vbytes"] * r + gpu) for r in (1, 5, 20, 50)})


def judge(sub, seed, strict_manifest=True, log=print, mode="standard"):
    C = json.loads((HERE / "constants.json").read_text())
    M = MODES[mode]
    rep = dict(judge=C["version"], seed=seed, mode=mode, ranked=mode != "screen", gates={})
    t0 = time.time()

    def fail(gate, msg, **kw):
        rep["gates"][gate] = dict(ok=False, error=msg, **kw)
        rep["verdict"] = "rejected"
        rep["rejected_at"] = gate
        return rep

    bad = manifest_ok()
    rep["gates"]["integrity"] = dict(ok=not bad, changed=bad)
    if bad and strict_manifest:
        return fail("integrity", f"trusted files changed: {bad}")

    try:
        d, cfg = design.load(Path(sub) / "design.json")
    except design.Invalid as e:
        return fail("schema", str(e))
    floor = C["admissible"]
    cfg["seed"] = seed
    rep["gates"]["schema"] = dict(ok=True)
    rep["design"] = d

    try:
        prod = q.build(cfg)
        test = q.build(cfg, test_mode=True)
    except Exception as e:
        return fail("build", f"builder rejected the design: {type(e).__name__}: {e}")
    rep["gates"]["build"] = dict(ok=True)

    ops_p, errs = checks.limits(prod["script"])
    ops_t, errs_t = checks.limits(test["script"])
    subs, twin_err = checks.twin(prod["script"], test["script"])
    dc = q.design_check(prod)
    static = dict(ops=ops_p, bytes=len(prod["script"]), test_bytes=len(test["script"]), max_stack=prod["max_stack"],
                  puzzle_substitutions=subs, design_check_findings=len(dc))
    if errs or errs_t or twin_err or dc or prod["max_stack"] > 1000:
        return fail("static", "; ".join(errs + [f"test-mode: {e}" for e in errs_t] + ([twin_err] if twin_err else []) +
                                        ([f"design_check: {len(dc)} unsafe region items"] if dc else []) +
                                        (["max stack > 1000"] if prod["max_stack"] > 1000 else [])), **static)
    if ops_p != prod["ops"]:
        return fail("static", f"judge op count {ops_p} != builder {prod['ops']} (judge bug)", **static)
    rep["gates"]["static"] = dict(ok=True, **static)

    P = math.log2(1 / q.p_der(32 if cfg["hash"] == "sha256" else 20))
    an = q.analyse(cfg, P, prod)
    sec = dict(P=round(P, 3), preimage_bits=round(an["preimage_bits"], 2), quantum_bits=round(an["quantum_query_bits"], 2),
               collision_bits=round(an["collision_bits"], 2), E=[round(x, 3) for x in an["E"]], S=an["S"])
    why = []
    if an["preimage_bits"] < floor["min_preimage_bits"]:
        why.append(f"2nd-preimage {an['preimage_bits']:.2f} < admissibility floor {floor['min_preimage_bits']}")
    if an["quantum_query_bits"] < floor["min_quantum_bits"]:
        why.append(f"quantum {an['quantum_query_bits']:.2f} < admissibility floor {floor['min_quantum_bits']}")
    if an["collision_bits"] < floor["min_collision_bits"]:
        why.append(f"collision {an['collision_bits']:.2f} < admissibility floor {floor['min_collision_bits']}")
    if min(an["E"]) < C["min_expected_solutions_per_round"]:
        why.append(f"expected honest solutions {min(an['E']):.2f} < {C['min_expected_solutions_per_round']}")
    if why:
        return fail("security", "; ".join(why), **sec)
    rep["gates"]["security"] = dict(ok=True, **sec)

    if mode != "screen":
        stages, samples, runs = None, [], 0
        for i in range(M["audit_seeds"]):
            au = audit.run_audit(cfg, test, prod, an, random.Random(seed + 7919 * i),
                                 budget_random=C["audit_random_perturbations"] * M["perturb"])
            samples += au.pop("samples", [])
            if au.get("honest_rejected"):
                # never blame the submission for a judge fault: ask Core about the honest spend
                line = consensus.to_line("JUDGE_honest", test["script"],
                                         consensus.realise(test["script"], au.pop("honest_witness"), q.make_tx()),
                                         q.make_tx(), True)
                bad_core, _ = consensus.run_cchk([line])
                if bad_core == []:
                    rep["verdict"] = "judge-error"
                    rep["rejected_at"] = "audit"
                    rep["gates"]["audit"] = dict(ok=False, error="judge interpreter rejects an honest spend that "
                                                                 "Core accepts (judge bug; the submission is not at fault)")
                    return rep
                au.pop("honest_witness", None)
            if not au["ok"]:
                return fail("audit", "attacker has more choices than the security count assumes", audit_seed=i, **au)
            runs += au["runs"]
            stages = au["stages"] if stages is None else [
                dict(a, measured=max(a["measured"], b["measured"]), z_views=max(a["z_views"], b["z_views"]))
                for a, b in zip(stages, au["stages"])]
        hs = audit.honest_space(cfg, test, random.Random(seed ^ 0x3C3C), samples=M["honest"])
        if not hs["ok"]:
            return fail("audit", "honest search space smaller than the analyser's E assumes: " + hs["error"])
        rep["gates"]["audit"] = dict(ok=True, seeds=M["audit_seeds"], runs=runs, stages=stages, honest_space=hs)

        lines = q.vectors_for("JUDGE", cfg, random.Random(seed ^ 0x5A5A))
        lines += consensus.realised_audit_lines("JUDGE", test, samples, random.Random(seed ^ 0xA5A5),
                                                n_acc=C["realised_audit_vectors"]["accepted"] * M["realised"],
                                                n_rej=C["realised_audit_vectors"]["rejected"] * M["realised"])
        bad_core, tail = consensus.run_cchk(lines)
        if bad_core is None:
            return fail("consensus", tail)
        if strict_manifest and not consensus.LEAN.exists():
            return fail("consensus", "ranked runs require the Lean model (lean/qsbcheck): run lean/check.sh")
        with tempfile.TemporaryDirectory() as td:
            bad_lean, tail_lean = consensus.run_lean(lines, td)
        lean_ok, lean_msg = lean_builder_check(cfg, prod, test)
        cons = dict(vectors=len(lines), core=tail, lean_replay=tail_lean, lean_builder=lean_msg)
        if bad_core:
            judge_bug = [l for l in bad_core if "_audit" in l]
            if judge_bug:
                rep["verdict"] = "judge-error"
                rep["rejected_at"] = "consensus"
                rep["gates"]["consensus"] = dict(ok=False, error="audit interpreter disagrees with Core (judge bug; "
                                                 f"the submission is not at fault): {judge_bug[0]}", **cons)
                return rep
            return fail("consensus", f"Core rejected an honest spend or accepted a negative: {bad_core[0]}", **cons)
        if bad_lean:
            return fail("consensus", f"Lean model disagrees with Core: {bad_lean[0]}", **cons)
        if lean_ok is False:
            return fail("consensus", f"Lean builder differs from the Python builder: {lean_msg}", **cons)
        rep["gates"]["consensus"] = dict(ok=True, **cons)

    tbl = cost.load_table()
    try:
        hours, rates = cost.gpu_hours(cfg, prod, an, P, tbl)
    except cost.Unmeasured as e:
        return fail("cost", str(e))
    R = len(prod["ts"])
    ch = dict(jp=0, j=[1] * R, subsets=[list(range(cfg[f"t{i}"] + cfg.get(f"b{i}", 0))) for i in range(1, R + 1)],
              odd=[0] * (R + 1), lvl=[1] * (R + 1), enc=["uncomp"] + [("comp" if cfg["force_comp"] else "uncomp")] * R)
    q.spend(prod, ch)
    ss = len(prod["last_script_sig"])
    vbytes = len(prod["script"]) + ss + C["tx_overhead_vbytes"]
    sats = vbytes * C["fee_sat_per_vbyte"] + hours * C["gpu_sats_per_hour"]
    rep["gates"]["cost"] = dict(ok=True, gpu_hours_rtx4090=round(hours, 3), stage_rates=[round(r / 1e9, 3) for r in rates],
                                script_bytes=len(prod["script"]), scriptsig_bytes=ss, total_vbytes=vbytes)
    # the result is a vector: cost and security are separate objectives (compare designs by Pareto dominance)
    rep["proof"] = proof_family(cfg)
    rep["score"] = dict(sats=round(sats), preimage_bits=round(an["preimage_bits"], 2),
                        quantum_bits=round(an["quantum_query_bits"], 2), collision_bits=round(an["collision_bits"], 2),
                        bits_confidence=rep["proof"]["label"])
    rep["diagnostics"] = diagnostics(C, prod, an, rep["gates"]["cost"])
    rep["verdict"] = "accepted" if mode != "screen" else "screened"
    rep["seconds"] = round(time.time() - t0, 1)
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("submission")
    ap.add_argument("--seed", type=int, default=None, help="ranked runs: supplied by the runner after submission")
    ap.add_argument("--out", default=None)
    ap.add_argument("--dev", action="store_true", help="do not refuse on manifest mismatch (local development)")
    ap.add_argument("--mode", choices=list(MODES), default="standard",
                    help="screen: ~1 s, unranked (no audit / consensus); standard: ranked; deep: promotion")
    a = ap.parse_args()
    seed = a.seed if a.seed is not None else random.SystemRandom().randrange(2 ** 32)
    rep = judge(a.submission, seed, strict_manifest=not a.dev, mode=a.mode)
    s = json.dumps(rep, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(s)
    print(s)
    sys.exit(0 if rep["verdict"] in ("accepted", "screened") else 1)


if __name__ == "__main__":
    main()
