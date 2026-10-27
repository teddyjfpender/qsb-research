"""Freedom audit: measure the attacker's choices in the real (test-mode) script and compare them with
the frozen analyser's S_i (judge component, frozen).

Why: the security number is P + sum(P - log2 S_i). If a design lets the attacker choose more than the
analyser counts (a deep index reaching extra items, an unclamped level, an encoding the round does not
pin, a commitment reachable from outside its region...), the claimed security is wrong. The audit is an
adaptive attacker: it knows exactly what a real attacker knows after seeing the honest spend (the
revealed HORS / pool-index / level preimages, every public script byte) and gets every signature for
free (A3). It sweeps each witness slot over its whole useful range, retries with a known preimage
whenever an OP_EQUALVERIFY compares a hash against an opened commitment, tries every key encoding, and
samples multi-slot combinations. Every accepted run is decomposed into per-round views:

    z-view  = (nonce signature, scriptCode after FindAndDelete)  -> what the round's sighash depends on
    level   = which chain level's item the round's DER check consumed (provenance)
    enc     = key encoding class accepted for the round (compressed / uncompressed / hybrid)

and the measured product 2 x |z-views| x |levels| x |encodings| must not exceed the analyser's S_i.
A violation is a concrete counterexample (the witness is returned), which the judge then replays
through Bitcoin Core with attacker-optimal real keys. Passing is evidence, not proof; the Lean proof
covers the families it covers.
"""
import hashlib
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import qsb_pool as q  # noqa: E402
from qsbcore import hash160  # noqa: E402
from trace import parse_script_sig  # noqa: E402

from . import interp  # noqa: E402

INT_EDGES = [2 ** 31 - 1, -(2 ** 31 - 1), 2 ** 31, -1, -2]


def key_classes(rng):
    x = rng.randbytes(32)
    y = rng.randbytes(32)
    return {"comp02": b"\x02" + x, "comp03": b"\x03" + x, "unc04": b"\x04" + x + y, "hyb06": b"\x06" + x + y,
            "hyb07": b"\x07" + x + y, "bad32": x, "bad34": b"\x02" + x + b"\x00", "empty": b""}


ENC_OF = {"comp02": "comp", "comp03": "comp", "unc04": "unc", "hyb06": "hyb", "hyb07": "hyb"}


def honest(cfg, tb, rng):
    R = len(tb["ts"])
    T = [cfg[f"t{i}"] + cfg.get(f"b{i}", 0) for i in range(1, R + 1)]
    ch = dict(jp=rng.randrange(cfg["k"]), j=[rng.randrange(1, cfg[f"k{i + 1}"] + 1) for i in range(R)],
              subsets=[rng.sample(range(cfg["n"]), T[i]) for i in range(R)], odd=[0] * (R + 1),
              lvl=[rng.randrange(1, cfg["chain_pin"] + 1)] + [rng.randrange(1, cfg[f"chain{i + 1}"] + 1) for i in range(R)],
              enc=["comp"] * (R + 1))
    q.spend(tb, ch)
    items = parse_script_sig(tb["last_script_sig"])
    assert len(items) == len(tb["witness"])
    return ch, items


def knowledge(cfg, tb, ch):
    """hash160 -> preimage for everything the honest spend reveals (the attacker's whole knowledge)."""
    know = {}
    R = len(tb["ts"])
    for r in range(R):
        for a in ch["subsets"][r][:tb["ts"][r]]:
            know[hash160(tb["pre"][r][a])] = tb["pre"][r][a]
        if cfg.get("sign_j"):
            s = ch["j"][r]
            know[hash160(tb["pre_j"][r][s - 1])] = tb["pre_j"][r][s - 1]
        if cfg.get("sign_lvl") and tb["chains"][r] > 1:
            v = tb["chains"][r] - ch["lvl"][r + 1]
            know[hash160(tb["pre_l"][r][v])] = tb["pre_l"][r][v]
    return know


def adaptive(script, items, know, max_fix=40):
    """Run; whenever EQUALVERIFY compares a hash of a witness item against a value the attacker can
    open, substitute the preimage into that witness slot and retry."""
    items = list(items)
    for _ in range(max_fix):
        res = interp.run(script, items)
        if res["ok"]:
            return res, items
        if res["reason"] != "EQUALVERIFY":
            return res, items
        ev = [e for e in res["events"] if e[0] == "EQ"][-1]
        hashes = {e[1]: e[3] for e in res["events"] if e[0] == "HASH"}     # hash op pos -> input prov
        a_prov, b_prov = ev[2], ev[3]
        # which side is the hash of a witness item, which is the target?
        fixed = False
        for hp, tp in ((a_prov, b_prov), (b_prov, a_prov)):
            if hp[0] == "op" and hp[1] in hashes and hashes[hp[1]][0] == "wit":
                target = _bytes_of(res, tp, script, items)
                if target is not None and target in know and items[hashes[hp[1]][1]] != know[target]:
                    items[hashes[hp[1]][1]] = know[target]
                    fixed = True
                    break
        if not fixed:
            return res, items
    return res, items


def _bytes_of(res, prov, script, items):
    if prov[0] == "push":
        pos = prov[1]
        op = script[pos]
        if op < 0x4C:
            return script[pos + 1:pos + 1 + op]
        if op == 0x4C:
            return script[pos + 2:pos + 2 + script[pos + 1]]
        if op == 0x4D:
            return script[pos + 3:pos + 3 + int.from_bytes(script[pos + 1:pos + 3], "little")]
        return None
    if prov[0] == "wit":
        return items[prov[1]]
    return None


def classify_key(b):
    if len(b) == 33 and b[0] in (2, 3):
        return "comp"
    if len(b) == 65 and b[0] == 4:
        return "unc"
    if len(b) == 65 and b[0] in (6, 7):
        return "hyb"
    return "other"


def run_audit(cfg, tb, prod, analysed, rng, budget_random=1500, log=print):
    R = len(tb["ts"])
    script = tb["script"]
    ch, W0 = honest(cfg, tb, rng)
    know = knowledge(cfg, tb, ch)
    labels = tb["witness"]
    li = {l: i for i, l in enumerate(labels)}
    res0 = interp.run(script, W0)
    if not res0["ok"]:
        return dict(ok=False, honest_rejected=True, honest_witness=W0,
                    error=f"honest witness rejected by the judge interpreter: {res0['reason']}")
    pool = set(tb["pool"])
    dummies = {d for rd in tb["dummies"] for d in rd}
    commits = {hash160(p) for rd in tb["pre"] for p in rd}
    kbound = [cfg.get("k_pin", cfg["k"])] + [cfg[f"k{i}"] for i in range(1, R + 1)]

    # measured choices per stage
    Z = [set() for _ in range(R + 1)]       # stage 0: pinning nonce; stage r: (nonce, scriptCode)
    L = [set() for _ in range(R + 1)]
    Enc = [set() for _ in range(R + 1)]
    off_pool = []                           # accepted runs whose nonce is not an in-bound pool sig
    wrong_rounds = []
    witnesses = []
    runs = 0

    key_label = ["keyp"] + [f"key{r}" for r in range(R)]

    def record(res, items):
        nonlocal runs
        ev = res["events"]
        cms = [e for e in ev if e[0] == "CMS"]
        if len(cms) != R:
            wrong_rounds.append(items)
            return
        stage, pin_puzzle = 0, False
        for e in ev:
            if e[0] == "CHECKSIG" and len(e[3][0]) == 1:          # DER-only puzzle check (OP_1 key)
                L[0 if not pin_puzzle else stage + 1].add(e[2][1])
                pin_puzzle = True
            elif e[0] == "CHECKSIG" and stage == 0 and e[4]:
                if e[2][0] in dummies or e[2][0] in commits:     # fixed-key / non-DER: design_check
                    off_pool.append((0, e[2][0], items))
                else:
                    Z[0].add(e[2][0])
            elif e[0] == "CMS":
                stage += 1
                sigs = [s[0] for s in e[2]]
                nonce = sigs[-1]                       # nonce is pushed first -> deepest -> popped last
                if nonce in dummies or nonce in commits:
                    off_pool.append((stage, nonce, items))
                else:                                  # any other nonce is an attacker option to count
                    Z[stage].add((nonce, hashlib.sha256(e[5]).hexdigest()))
        for s, lab in enumerate(key_label):
            Enc[s].add(classify_key(items[li[lab]]))
        witnesses.append(items)

    samples_acc, samples_rej, deep_rej = [], [], []
    import heapq

    def attempt(items):
        nonlocal runs
        runs += 1
        res, it2 = adaptive(script, items, know)
        if res["ok"]:
            record(res, it2)
            if len(samples_acc) < 4000:
                samples_acc.append((it2, True, len(res["events"])))
        else:
            prog = len(res["events"])                  # how far the run got before it failed
            entry = (prog, runs, it2)
            if len(deep_rej) < 400:
                heapq.heappush(deep_rej, entry)
            elif prog > deep_rej[0][0]:
                heapq.heapreplace(deep_rej, entry)
            if len(samples_rej) < 2000:
                samples_rej.append((it2, False, prog))
            elif rng.random() < 0.05:
                samples_rej[rng.randrange(2000)] = (it2, False, prog)
        return res["ok"]

    record(res0, W0)
    maxv = tb["max_stack"] + 3
    idx_labels = [l for l in labels if l in ("jp", "lp") or l.startswith(("j", "l", "x"))]
    for lab in idx_labels:
        for v in list(range(-2, maxv + 1)) + INT_EDGES:
            it = list(W0)
            it[li[lab]] = interp.enc_num(v) if abs(v) < 2 ** 31 else (v % 2 ** 40).to_bytes(5, "little")
            attempt(it)
    kc = key_classes(rng)
    for lab in key_label:
        for name, kb in kc.items():
            it = list(W0)
            it[li[lab]] = kb
            attempt(it)
    # every order of opening the revealed selections (the plan recomputes each relative index)
    for _ in range(60):
        c2 = dict(ch, subsets=[rng.sample(s[:tb["ts"][r]], tb["ts"][r]) + s[tb["ts"][r]:] for r, s in enumerate(ch["subsets"])])
        q.spend(tb, c2)
        attempt(parse_script_sig(tb["last_script_sig"]))
    # random multi-slot perturbations (2-3 index slots at once, plus a key class)
    for _ in range(budget_random):
        it = list(W0)
        for lab in rng.sample(idx_labels, min(len(idx_labels), rng.choice((2, 3)))):
            it[li[lab]] = interp.enc_num(rng.randrange(-1, maxv))
        if rng.random() < 0.3:
            it[li[rng.choice(key_label)]] = rng.choice(list(kc.values()))
        attempt(it)

    # compare with the analyser
    comps, ok = [], True
    for s in range(R + 1):
        z_n = len(Z[s])
        l_n, e_n = max(1, len(L[s])), len(Enc[s] - {"other"})
        measured = 2 * z_n * l_n * e_n
        if s == 0:
            claimed = 2 * kbound[0] * 3 * cfg["chain_pin"]              # analyser's S_pin (Theorem 2)
        else:
            claimed = analysed["S"][s - 1]
        comps.append(dict(stage=s, z_views=z_n, levels=l_n, encodings=e_n, measured=measured, claimed=claimed,
                          ok=measured <= claimed))
        ok &= measured <= claimed
    # nonces that are dummies / commitments are excluded by design_check on the production script
    bad_off = []
    ok &= not wrong_rounds
    return dict(ok=ok, runs=runs, accepted=len(witnesses), samples=samples_acc + samples_rej + [(e[2], False, e[0]) for e in deep_rej], stages=comps, off_pool_nonces=len(off_pool),
                uncovered_off_pool=len(bad_off), wrong_round_count=len(wrong_rounds),
                counterexample=None if ok else _first_violation(comps, bad_off, wrong_rounds, witnesses))


def _first_violation(comps, bad_off, wrong_rounds, witnesses):
    if bad_off:
        return dict(kind="nonce outside pool and outside design_check coverage", stage=bad_off[0][0],
                    witness=[w.hex() for w in bad_off[0][2]])
    if wrong_rounds:
        return dict(kind="accepted run with a different number of CHECKMULTISIG rounds",
                    witness=[w.hex() for w in wrong_rounds[0]])
    bad = [c for c in comps if not c["ok"]][0]
    return dict(kind="more attacker choices than the analyser counts", **bad)


def honest_space(cfg, tb, rng, samples=150):
    """The analyser's E_i assumes every (subset, pool index, level) the honest spender can choose gives a
    distinct sighash / DER-checked value. Play the honest spender with full knowledge: sample random
    choices, require every one to be accepted and all per-round (z-view, level) pairs to be distinct.
    A collision or a rejection means E_i (and therefore the cost) is overstated."""
    R = len(tb["ts"])
    seen = [set() for _ in range(R)]
    for _ in range(samples):
        T = [cfg[f"t{i}"] + cfg.get(f"b{i}", 0) for i in range(1, R + 1)]
        ch = dict(jp=rng.randrange(cfg["k"]), j=[rng.randrange(1, cfg[f"k{i + 1}"] + 1) for i in range(R)],
                  subsets=[rng.sample(range(cfg["n"]), T[i]) for i in range(R)], odd=[0] * (R + 1),
                  lvl=[rng.randrange(1, cfg["chain_pin"] + 1)] + [rng.randrange(1, cfg[f"chain{i + 1}"] + 1) for i in range(R)],
                  enc=["comp"] * (R + 1))
        q.spend(tb, ch)
        res = interp.run(tb["script"], parse_script_sig(tb["last_script_sig"]))
        if not res["ok"]:
            return dict(ok=False, error=f"an honest choice is rejected: {res['reason']}", choice=str(ch))
        cms = [e for e in res["events"] if e[0] == "CMS"]
        puz = [e for e in res["events"] if e[0] == "CHECKSIG" and len(e[3][0]) == 1][1:]
        for r in range(R):
            v = (cms[r][2][-1][0], hashlib.sha256(cms[r][5]).hexdigest(), puz[r][2][1], tuple(sorted(ch["subsets"][r])),
                 ch["j"][r], ch["lvl"][r + 1])
            key = v[:3]
            if key in {x[:3] for x in seen[r] if x[3:] != v[3:]}:
                return dict(ok=False, error=f"two different honest choices give the same round-{r + 1} view")
            seen[r].add(v)
    return dict(ok=True, samples=samples)
