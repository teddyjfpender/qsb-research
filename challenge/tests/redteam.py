#!/usr/bin/env python3
"""Red-team suite for the QSB design judge. Every case is an attempt to get a bad design scored, or a
deliberately broken security model / builder / interpreter that the judge must catch.

Run: python3 challenge/tests/redteam.py [--quick]
"""
import copy
import json
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CH = HERE.parent
ROOT = CH.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(CH))
import qsb_pool as q  # noqa: E402
from judge import __main__ as J  # noqa: E402
from judge import audit, consensus, interp  # noqa: E402
from judge.interp import find_and_delete as fast_fad  # noqa: E402
from qsbcore import find_and_delete as ref_fad, push_min  # noqa: E402

BASE = json.loads((CH / "baselines/L_lean/design.json").read_text())
RESULTS = []


def judge_design(d, seed=21, raw=None):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "design.json"
        p.write_bytes(raw if raw is not None else json.dumps(d).encode())
        return J.judge(td, seed, strict_manifest=False, log=lambda *a: None)


def case(name, fn, expect):
    try:
        got = fn()
    except Exception as e:                                   # a crash is a failure of the judge
        got = f"CRASH {type(e).__name__}: {e}"
    ok = expect(got)
    if isinstance(got, dict) and "verdict" in got:
        g = got.get("rejected_at")
        detail = f"{got['verdict']}" + (f" at {g}: {got['gates'][g].get('error', '')}" if g else f", score {got.get('score')}")
    else:
        detail = got if isinstance(got, str) else json.dumps(got)
    RESULTS.append((name, ok, detail[:300]))
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail[:200]}")


def rejected_at(gate):
    return lambda r: isinstance(r, dict) and r.get("verdict") == "rejected" and r.get("rejected_at") == gate


def mod(**kw):
    d = copy.deepcopy(BASE)
    for k, v in kw.items():
        d[k] = v
    return d


# ------------------------------------------------------------------ 1. submission-format cheats
def format_cases():
    case("claimed metric in design.json", lambda: judge_design(mod(security_bits=256)), rejected_at("schema"))
    case("string number", lambda: judge_design(mod(n="64")), rejected_at("schema"))
    case("boolean posing as integer", lambda: judge_design(mod(n=True)), rejected_at("schema"))
    case("float parameter", lambda: judge_design(mod(n=64.0)), rejected_at("schema"))
    case("negative parameter", lambda: judge_design(mod(k=-1)), rejected_at("schema"))
    case("v1 design with a 'track' key (bands no longer exist)", lambda: judge_design(mod(track="t90")),
         rejected_at("schema"))
    case("wrong schema version", lambda: judge_design(mod(schema="qsb-design-v1")), rejected_at("schema"))
    case("oversized file (> 4 KiB)", lambda: judge_design(None, raw=b" " * 5000 + json.dumps(BASE).encode()),
         rejected_at("schema"))
    case("extra key inside a round", lambda: judge_design(mod(rounds=[dict(BASE["rounds"][0], S=1)])), rejected_at("schema"))
    case("three rounds", lambda: judge_design(mod(rounds=BASE["rounds"] * 3)), rejected_at("schema"))
    case("sign_j without pool-first layout", lambda: judge_design(mod(pool_deep=False)), rejected_at("schema"))
    case("t > n/2 (breaks the proof's layout condition)", lambda: judge_design(mod(n=20, rounds=[dict(t=11, b=0, k=16, chain=8)])),
         rejected_at("schema"))
    case("not JSON", lambda: judge_design(None, raw=b"{design"), rejected_at("schema"))


# ------------------------------------------------------------------ 2. security / limits / cost gates
def gate_cases():
    ts2 = dict(schema="qsb-design-v2", hash="sha256", n=150, k=300, pool_deep=True, force_comp=True,
               chain_pin=1, sign_j=False, sign_lvl=False, rounds=[dict(t=16, b=0, k=64, chain=1)])
    case("real TS2 (83.7 bits) is admissible and scored as a vector", lambda: judge_design(ts2),
         lambda r: r.get("verdict") == "accepted" and abs(r["score"]["preimage_bits"] - 83.73) < 0.01)
    weak = dict(ts2, k=96, force_comp=False, rounds=[dict(t=8, b=0, k=96, chain=8)])   # S = 2*3*96*8
    case("design below the admissibility floor (78.5 bits)", lambda: judge_design(weak),
         lambda r: rejected_at("security")(r) and "2nd-preimage" in r["gates"]["security"]["error"]
         and "expected" not in r["gates"]["security"]["error"])
    case("honest spender has < 1 expected solution", lambda: judge_design(mod(n=40, rounds=[dict(t=8, b=0, k=16, chain=8)])),
         rejected_at("security"))
    case("op count over 201", lambda: judge_design(mod(n=80, rounds=[dict(t=16, b=0, k=16, chain=8)])),
         lambda r: isinstance(r, dict) and r.get("rejected_at") in ("build", "static"))
    case("script over 10,000 bytes", lambda: judge_design(mod(n=200, k=300, rounds=[dict(t=10, b=0, k=64, chain=8)])),
         lambda r: isinstance(r, dict) and r.get("rejected_at") in ("build", "static"))
    case("unmeasured stage shape (pool of 4)", lambda: judge_design(mod(k=4, rounds=[dict(t=11, b=0, k=4, chain=8)])),
         lambda r: isinstance(r, dict) and r.get("rejected_at") in ("cost", "security"))


# ------------------------------------------------------------------ 3. the judge must catch broken models
def audit_only(cfg, patch_analyse=None):
    cfg = dict(cfg, seed=33)
    tb = q.build(cfg, test_mode=True)
    prod = q.build(cfg)
    P = math.log2(1 / q.p_der(32))
    an = q.analyse(cfg, P, prod)
    if patch_analyse:
        an = patch_analyse(an)
    r = audit.run_audit(cfg, tb, prod, an, random.Random(5), budget_random=300)
    r.pop("samples", None)
    return r


UNSIGNED = dict(hash="sha256", n=120, k=64, pool_deep=True, force_comp=True, chain_pin=8, sign_j=False, sign_lvl=False,
                t1=10, b1=0, k1=16, chain1=8, chain_r=8)
LEAN_CFG = dict(hash="sha256", n=64, k=16, pool_deep=True, force_comp=True, chain_pin=8, sign_j=True, sign_lvl=True,
                t1=11, b1=0, k1=16, chain1=8, chain_r=8)


class patched:
    """Temporarily mutate the builder (the judge must notice the security consequence)."""
    def __init__(self, kind):
        self.kind = kind

    def __enter__(self):
        B = q.Builder
        self.saved = (B._op, B.min_)
        orig_op, orig_min = B._op, B.min_
        kind = self.kind

        def _op(self_, name, count=1):
            prev = getattr(self_, "_last", None)
            self_._last = name
            if kind == "no_hors_check" and name == "OP_EQUALVERIFY" and prev == "OP_HASH160":
                return orig_op(self_, "OP_2DROP", count)
            if kind == "no_size_check" and name == "OP_EQUALVERIFY" and prev == "OP_SIZE":
                return orig_op(self_, "OP_2DROP", count)
            return orig_op(self_, name, count)

        def min_(self_, bound):
            if kind == "no_clamp":
                self_.script += q.push_num(bound)
                self_._op("OP_DROP")                           # same op count, no clamp
                return
            return orig_min(self_, bound)
        B._op, B.min_ = _op, min_
        # the builder counts OP_SIZE via _op too; track the previous opcode
        return self

    def __exit__(self, *a):
        q.Builder._op, q.Builder.min_ = self.saved


def mutation_cases():
    case("honest analyser on an unsigned design: audit agrees", lambda: audit_only(UNSIGNED)["ok"], lambda r: r is True)
    case("analyser mutated to pretend the pool index and level are signed (undercounts S by k*m)",
         lambda: audit_only(UNSIGNED, lambda an: dict(an, S=[s // (16 * 8) for s in an["S"]]))["ok"], lambda r: r is False)
    case("analyser mutated to ignore key encodings in pinning-free round (S/3)",
         lambda: audit_only(dict(UNSIGNED, force_comp=False), lambda an: dict(an, S=[s // 3 for s in an["S"]]))["ok"],
         lambda r: r is False)

    def mut(kind, cfg):
        with patched(kind):
            return audit_only(cfg)
    case("builder mutated: HORS preimage check removed (anyone can select dummies)",
         lambda: mut("no_hors_check", LEAN_CFG)["ok"], lambda r: r is False)
    case("builder mutated: OP_SIZE 33 check removed (round accepts every encoding)",
         lambda: mut("no_size_check", LEAN_CFG)["ok"], lambda r: r is False)
    def colliding_dummies():
        orig = q.der9
        q.der9 = lambda r, s_, ht: orig(2, 1 + (s_ % 3), ht)          # only 3 distinct dummies exist
        try:
            cfg = dict(LEAN_CFG, seed=8)
            return audit.honest_space(cfg, q.build(cfg, test_mode=True), random.Random(2))["ok"]
        finally:
            q.der9 = orig
    case("builder mutated: dummies collide, so honest subsets alias (E overstated)", colliding_dummies,
         lambda r: r is False)
    case("honest search space of the unmodified builder is distinct",
         lambda: audit.honest_space(dict(LEAN_CFG, seed=8), q.build(dict(LEAN_CFG, seed=8), test_mode=True),
                                    random.Random(2))["ok"], lambda r: r is True)
    case("builder mutated: OP_MIN clamps removed (indices reach past their bounds)",
         lambda: mut("no_clamp", UNSIGNED)["ok"], lambda r: r is False)


# ------------------------------------------------------------------ 4. the judge's own components
def component_cases():
    rng = random.Random(9)
    cfg = dict(LEAN_CFG, seed=4)
    b = q.build(cfg, test_mode=True)

    def fad_equiv():
        s = b["script"]
        sigs = [d for rd in b["dummies"] for d in rd] + b["pool"][:5] + [bytes([rng.randrange(256) for _ in range(rng.randrange(1, 12))]) for _ in range(40)]
        for sg in sigs:
            if fast_fad(s, sg) != ref_fad(s, sg):
                return f"mismatch for {sg.hex()}"
        # adversarial: a script made of repeated patterns
        for _ in range(200):
            pat = bytes([rng.randrange(256) for _ in range(rng.randrange(1, 6))])
            s2 = (push_min(pat) * rng.randrange(1, 5) + bytes([rng.choice([0x51, 0x76, 0x4c, 0x01])]) + bytes(rng.randrange(0, 3))) * 3
            try:
                if fast_fad(s2, pat) != ref_fad(s2, pat):
                    return f"mismatch on synthetic {s2.hex()}"
            except Exception:
                pass
        return "equivalent"
    case("judge FindAndDelete == reference FindAndDelete", fad_equiv, lambda r: r == "equivalent")

    def interp_too_strict():
        """Mutate the audit interpreter to silently refuse every attacker variant whose index path differs
        from the honest one (under-accepting = the dangerous direction: hidden freedoms go uncounted)."""
        orig = interp.run
        tb = q.build(cfg, test_mode=True)
        prod = q.build(cfg)
        an = q.analyse(cfg, math.log2(1 / q.p_der(32)), prod)
        _, W0 = audit.honest(cfg, tb, random.Random(3))
        honest_path = [e[2] for e in orig(tb["script"], W0)["events"] if e[0] in ("ROLL", "PICK")]

        def strict(script, items, oracle="attacker"):
            r = orig(script, items, oracle)
            if r["ok"] and [e[2] for e in r["events"] if e[0] in ("ROLL", "PICK")] != honest_path:
                r = dict(r, ok=False, reason="mutated: refused")
            return r
        audit.interp.run = strict                     # the same (buggy) interpreter is used throughout
        try:
            au = audit.run_audit(cfg, tb, prod, an, random.Random(3), budget_random=200)
            lines = consensus.realised_audit_lines("MUT", tb, au["samples"], random.Random(1), n_acc=30, n_rej=60)
        finally:
            audit.interp.run = orig
        bad, tail = consensus.run_cchk(lines)
        return f"{len(bad)} realised audit verdicts contradict Core"
    case("audit interpreter mutated to under-accept: Core cross-check catches it", interp_too_strict,
         lambda r: isinstance(r, str) and not r.startswith("0 ") and "contradict" in r)

    def tamper_manifest():
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "research"
            shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".lake", "target", "results*", "runs*", "real", "__pycache__"))
            (dst / "challenge/judge/constants.json").write_text(
                (dst / "challenge/judge/constants.json").read_text().replace('"fee_sat_per_vbyte": 5', '"fee_sat_per_vbyte": 0'))
            out = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, '.'); from judge.__main__ import manifest_ok; print(manifest_ok())"],
                                 cwd=dst / "challenge", capture_output=True, text=True)
            return out.stdout.strip()
    case("editing a judge constant (fee = 0) is detected by the manifest", tamper_manifest,
         lambda r: "constants.json" in r)

    def determinism():
        a = judge_design(BASE, seed=5)
        b_ = judge_design(BASE, seed=6)
        return [a.get("score"), b_.get("score"), a["verdict"], b_["verdict"]]
    case("score does not depend on the judge seed", determinism, lambda r: r[0] == r[1] and r[2] == r[3] == "accepted")


# ------------------------------------------------------------------ 5. process: modes and leaderboard
def process_cases():
    def screen_matches_ranked():
        a = J.judge_path_screen = None
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "design.json").write_text(json.dumps(BASE))
            s_ = J.judge(td, 9, strict_manifest=False, mode="screen")
        r = judge_design(BASE, seed=9)
        return [s_["verdict"], s_.get("score"), r["verdict"], r.get("score")]
    case("screen mode gives the ranked score (and is marked unranked)", screen_matches_ranked,
         lambda r: r[0] == "screened" and r[2] == "accepted" and r[1] == r[3])

    def board_rules():
        import importlib.util
        spec = importlib.util.spec_from_file_location("lb", CH / "leaderboard.py")
        lb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lb)
        base = dict(verdict="accepted", design=dict(BASE), score=dict(sats=0, preimage_bits=0, quantum_bits=40,
                    collision_bits=66, bits_confidence="audited"), gates=dict(cost=dict(total_vbytes=1, gpu_hours_rtx4090=1)))

        def mk(name, sats, bits, mode, n):
            r = dict(base, mode=mode, submission=name, manifest_digest=lb.digest,
                     design=dict(base["design"], n=n), score=dict(base["score"], sats=sats, preimage_bits=bits))
            return (f"2026_{name}.json", r)
        pts = [mk("a_cheap", 100, 90, "deep", 1), mk("b_secure", 200, 116, "deep", 2),
               mk("c_dominated", 150, 89, "deep", 3), mk("d_tie", 100, 90, "deep", 4),
               mk("e_pending", 120, 100, "standard", 5), mk("f_pend_dominated", 300, 100, "standard", 6)]
        pts[3] = ("2027_d_tie.json", pts[3][1])                           # later than a_cheap
        deep = [p for p in pts if p[1]["mode"] == "deep"]
        front = {p[1]["submission"] for p in lb.frontier(deep, "2")}
        pending = {p[1]["submission"] for p in pts if p[1]["mode"] != "deep" and not any(lb.dominates(b_, p, "2") for b_ in deep)}
        return front == {"a_cheap", "b_secure"} and pending == {"e_pending"}
    case("leaderboard: Pareto frontier over (sats, bits); dominated and later exact ties excluded; "
         "non-dominated standard runs pending", board_rules, lambda r: r is True)


if __name__ == "__main__":
    quick = "--quick" in sys.argv
    for b in ("A_TS4", "L_lean", "E_116"):
        d_ = json.loads((CH / f"baselines/{b}/design.json").read_text())
        case(f"baseline {b} is accepted", lambda d_=d_: judge_design(d_, seed=77), lambda r: r.get("verdict") == "accepted")
    format_cases()
    gate_cases()
    mutation_cases()
    component_cases()
    process_cases()
    n_ok = sum(1 for r in RESULTS if r[1])
    print(f"\n{n_ok}/{len(RESULTS)} red-team cases behaved as required")
    (HERE / "redteam_results.json").write_text(json.dumps([dict(case=a, ok=b, detail=c) for a, b, c in RESULTS], indent=1))
    sys.exit(0 if n_ok == len(RESULTS) else 1)
