#!/usr/bin/env python3
"""Security menu: the fastest valid design for each second-preimage target from 80 to 116 bits.

For every target it searches 2-stage (pinning + 1 round) and 3-stage (pinning + 2 rounds) designs over
both puzzle hashes (SHA-256, RIPEMD-160), pool sizes and bounds, hash-chain lengths, signed pool
index/level, forced-compressed rounds and bonus keys, under the 201-op / 10,000-byte limits. Winners
are rebuilt exactly with qsb_pool.build(), must pass design_check(), and get consensus vectors
(honest spends + negatives) that are run through libbitcoinconsensus.

Cost model (whole-GPU ns): per attempt = (setup/(2k) + key + blocks*H) / (e*m), where
  e = encodings the honest spender hashes (1, or 3 when rounds accept all encodings),
  m = hash-chain length, blocks = (1 if e == 1 else 5) + e*(m-1) compressions per key.
Constants are fit to the measurements in gpu/README.md (both cards within ~4%).
"""
import itertools
import json
import math
import random
import subprocess
import sys
from pathlib import Path

import qsb_pool as q

HERE = Path(__file__).resolve().parent
P = {"sha256": math.log2(1 / q.p_der(32)), "rmd": math.log2(1 / q.p_der(20))}
GPU = {  # H per compression by hash, key = EC + loop per recovered key, setup per sighash z
    "RTX 4090": dict(sha256=0.062, rmd=0.0322, key=0.080, setup_pin=3.0, setup_round=7.0),
    "RTX 5090": dict(sha256=0.0418, rmd=0.0207, key=0.056, setup_pin=2.1, setup_round=4.9),
}


def per_attempt(g, hsh, k, m, e, setup):
    blocks = (1 if e == 1 else 5) + e * (m - 1)
    return (setup / (2 * k) + g["key"] + blocks * g[hsh]) / (e * m)


def ops_est(c):
    ops = 9 + (2 * c["chain_pin"] + 1 if c["chain_pin"] > 1 else 0)
    for i in range(1, c["R"] + 1):
        t, b, m = c[f"t{i}"], c.get(f"b{i}", 0), c.get(f"chain{i}", 1)
        ops += 11 * t + 11 + 5 * b + (2 if c["force_comp"] else 0)
        ops += (2 * m + 1 + (m + 1) // 2) if m > 1 else 0
        ops += 6 if c["sign_j"] else 0
        ops += 6 if (c["sign_lvl"] and m > 1) else 0
    return ops


def bytes_est(c):
    pool = sum(11 if s < 128 else 12 for s in range(1, c["k"] + 1))
    extra = sum((21 * c[f"k{i}"] if c["sign_j"] else 0) +
                (21 * c.get(f"chain{i}", 1) if (c["sign_lvl"] and c.get(f"chain{i}", 1) > 1) else 0)
                for i in range(1, c["R"] + 1))
    return pool + c["R"] * c["n"] * 31 + 3 * ops_est(c) + extra


def quick(c):
    Pb = P[c["hash"]]
    S, E = [], []
    for i in range(1, c["R"] + 1):
        e_att = 1 if c["force_comp"] else 3
        k_, m_ = c[f"k{i}"], c.get(f"chain{i}", 1)
        honest = 2 * k_ * e_att * m_
        att = 2 * e_att * (1 if c["sign_j"] else k_) * (1 if c["sign_lvl"] else m_)
        beta = (c["n"] + c[f"t{i}"] + 2) if c.get(f"b{i}", 0) else 1
        S.append(att * beta)
        E.append(math.comb(c["n"], c[f"t{i}"]) * math.comb(c["n"] - c[f"t{i}"], c.get(f"b{i}", 0)) * honest * 2 ** -Pb)
    return Pb + sum(Pb - math.log2(x) for x in S), E


def hours(c, E, gname):
    g, Pb = GPU[gname], P[c["hash"]]
    p = [1 - math.exp(-x) for x in E]
    t = 2 ** Pb * per_attempt(g, c["hash"], c["k"], c["chain_pin"], 1, g["setup_pin"])
    reach = 1.0
    for i in range(1, c["R"] + 1):
        e_h = 1 if c["force_comp"] else c.get("enc_honest", 1)
        t += reach * 2 ** Pb * p[i - 1] * per_attempt(g, c["hash"], c[f"k{i}"], c.get(f"chain{i}", 1), e_h, g["setup_round"])
        reach *= p[i - 1]
    return t / math.prod(p) * 1e-9 / 3600


def candidates(R):
    chains = [1, 2, 4, 8, 16] if R == 1 else [1, 2]
    ns = [80, 100, 120, 140, 150] if R == 1 else [100, 120, 140]
    ks = [64, 128, 200, 300] if R == 1 else [64, 128, 200]
    cps = [1, 4, 8, 16] if R == 1 else [1, 4, 8]
    kr = [8, 16, 32, 64] if R == 1 else [16, 32, 64]
    for hsh, n, k, cp, fc, sj, sl, eh in itertools.product(
            ["sha256", "rmd"], ns, ks, cps, [True, False], [False, True], [False, True], [1, 3]):
        if fc and eh == 3:
            continue
        tr = range(5, 17) if R == 1 else range(5, 10)
        for ts in itertools.product(tr, repeat=R):
            for bs in itertools.product([0, 1], repeat=R):
                if R == 2 and bs[1]:
                    continue
                for kis in itertools.product(kr, repeat=R):
                    for ms in itertools.product(chains, repeat=R):
                        c = dict(R=R, hash=hsh, n=n, k=k, chain_pin=cp, force_comp=fc, sign_j=sj, sign_lvl=sl,
                                 enc_honest=eh, pool_deep=True)
                        for i in range(R):
                            c[f"t{i+1}"], c[f"b{i+1}"], c[f"k{i+1}"], c[f"chain{i+1}"] = ts[i], bs[i], min(kis[i], k), ms[i]
                        if sl and max(ms) == 1:
                            continue
                        if ops_est(c) > 201 or bytes_est(c) > 9800:
                            continue
                        yield c


def cfg_of(c):
    d = {k_: v for k_, v in c.items() if k_ not in ("R", "enc_honest")}
    d["chain_r"] = c.get("chain1", 1)
    return d


def main():
    targets = [80, 84, 88, 90, 92, 96, 100, 104, 108, 112, 116]
    pool = {1: [], 2: []}
    for R in (1, 2):
        for c in candidates(R):
            pre, E = quick(c)
            if min(E) < 1.5:
                continue
            pool[R].append((hours(c, E, "RTX 4090"), pre, c))
        pool[R].sort(key=lambda x: x[0])
        sys.stderr.write(f"R={R}: {len(pool[R])} feasible candidates\n")
    rows, vectors = [], []
    rng = random.Random(2026)
    for tgt in targets:
        best = None
        for R in (1, 2):
            for h, pre, c in pool[R]:
                if pre >= tgt and (best is None or h < best[0]):
                    best = (h, pre, c)
                    break
        if not best:
            rows.append(dict(target=tgt, found=False))
            continue
        h, pre, c = best
        cfg = cfg_of(c)
        # per-round chain lengths
        for i in range(1, c["R"] + 1):
            cfg[f"chain{i}"] = c.get(f"chain{i}", 1)
        b = q.build(cfg)
        r = q.analyse(cfg, P[c["hash"]], b)
        bad = q.design_check(b)
        ok = b["ops"] <= 201 and len(b["script"]) <= 10000 and not bad and min(r["E"]) >= 1.0
        tag = f"MENU{tgt}"
        vcfg = dict(cfg, seed=tgt)
        vectors += q.vectors_for(tag, vcfg, rng)
        rows.append(dict(target=tgt, found=True, stages=c["R"] + 1, hash=c["hash"], cfg=cfg, ops=b["ops"],
                         bytes=len(b["script"]), E=[round(x, 1) for x in r["E"]], preimage=round(r["preimage_bits"], 1),
                         collision=round(r["collision_bits"], 1), quantum=round(r["quantum_query_bits"], 1),
                         h4090=round(hours(c, quick(c)[1], "RTX 4090"), 2), h5090=round(hours(c, quick(c)[1], "RTX 5090"), 2),
                         valid=ok))
    (HERE / "security_menu.json").write_text(json.dumps(rows, indent=1))
    (HERE / "security_menu_vectors.txt").write_text("\n".join(vectors) + "\n")
    res = subprocess.run([str(HERE / "consensus_check/target/release/cchk")], input="\n".join(vectors) + "\n",
                         capture_output=True, text=True).stdout.strip().splitlines()
    print(f"consensus: {len(vectors)} vectors, {res[-1]}")
    print("| target | stages | hash | parameters | ops | bytes | E | 2nd-pre | collision | quantum | RTX 4090 | RTX 5090 | vs today (101 h) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for x in rows:
        if not x["found"]:
            print(f"| ≥{x['target']} | – | – | none within limits | | | | | | | | | |")
            continue
        c = x["cfg"]
        par = f"n{c['n']} pool{c['k']} pinchain{c['chain_pin']}; " + "; ".join(
            f"r{i}: t{c[f't{i}']}{'+1b' if c.get(f'b{i}') else ''} k{c[f'k{i}']} m{c.get(f'chain{i}', 1)}"
            for i in range(1, x["stages"])) + (" comp" if c["force_comp"] else "") + (" sign-j" if c["sign_j"] else "") + \
            (" sign-lvl" if c["sign_lvl"] else "")
        print(f"| ≥{x['target']} | {x['stages']} | {x['hash']} | {par} | {x['ops']} | {x['bytes']} | {x['E']} | "
              f"**{x['preimage']}** | {x['collision']} | {x['quantum']} | {x['h4090']} h | {x['h5090']} h | "
              f"{101.3 / x['h4090']:.0f}x |")


if __name__ == "__main__":
    main()
