#!/usr/bin/env python3
"""Search QSB pool/chain designs: minimize honest GPU time at a target security, within 201 ops / 10 kB.

Cost model per attempt on one GPU (fit to RTX 4090 measurements, gpu/README.md; within ~2%):
    c = (setup_z / (2k) + key_cost) / m + hash_cost
      setup_z  : per sighash z (sighash + fixed-base mult + inversion share): 3.0 ns pinning, 4.4 ns round
      key_cost : EC + loop overhead per recovered key: 0.080 ns
      hash_cost: one SHA-256 compression in-kernel: 0.063 ns
Security from qsb_pool.analyse() (Theorems 1-3 of SECURITY_PROOF.md). Candidates are enumerated with
analytic op/byte counts, then the best ones are rebuilt with qsb_pool.build() for exact numbers.
"""
import itertools
import math
import sys

import qsb_pool as q

P = math.log2(1 / q.p_der(32))                     # SHA-256 puzzle
HASH, KEY, SETUP_PIN, SETUP_ROUND = 0.062, 0.080, 3.0, 7.0   # recalibrated on real TS2 shapes (results4/)
GPU_SCALE = {"RTX 4090": 1.0, "RTX 5090": 0.68}


def ops_estimate(c):
    ops = 9 + (2 * c["chain_pin"] + 1 if c["chain_pin"] > 1 else 0)
    for i in range(1, c["R"] + 1):
        t, b, m = c[f"t{i}"], c.get(f"b{i}", 0), c.get(f"chain{i}", 1)
        ops += 11 * t + 11 + 5 * b + (2 if c["force_comp"] else 0)
        ops += (2 * m + 1 + (m + 1) // 2) if m > 1 else 0
        ops += 6 if c.get("sign_j") else 0
        ops += 6 if (c.get("sign_lvl") and m > 1) else 0
    return ops


def bytes_estimate(c):
    pool = sum(11 if s < 128 else 12 for s in range(1, c["k"] + 1))
    extra = 0
    for i in range(1, c["R"] + 1):
        extra += 21 * c[f"k{i}"] if c.get("sign_j") else 0
        extra += 21 * c.get(f"chain{i}", 1) if (c.get("sign_lvl") and c.get(f"chain{i}", 1) > 1) else 0
    return pool + c["R"] * c["n"] * 31 + 3 * ops_estimate(c) + extra


def per_attempt(k, m, setup):
    return (setup / (2 * k) + KEY) / m + HASH


def quick_security(c):
    """analytic version of analyse() without building (bonus options ~ n + t + 2 in round 1)"""
    S, E = [], []
    for i in range(1, c["R"] + 1):
        base = 2 * c[f"k{i}"] * (1 if c["force_comp"] else 3) * c.get(f"chain{i}", 1)
        att = base // (c[f"k{i}"] if c.get("sign_j") else 1) // (c.get(f"chain{i}", 1) if c.get("sign_lvl") else 1)
        beta = (c["n"] + c[f"t{i}"] + 2) if c.get(f"b{i}", 0) else 1
        S.append(att * beta)
        E.append(math.comb(c["n"], c[f"t{i}"]) * math.comb(c["n"] - c[f"t{i}"], c.get(f"b{i}", 0)) * base * 2 ** -P)
    pre = P + sum(P - math.log2(s) for s in S)
    return pre, E


def hours(c, E):
    p = [1 - math.exp(-e) for e in E]
    t = 2 ** P * per_attempt(c["k"], c["chain_pin"], SETUP_PIN)
    reach = 1.0
    for i in range(1, c["R"] + 1):
        t += reach * 2 ** P * p[i - 1] * per_attempt(c[f"k{i}"], c.get(f"chain{i}", 1), SETUP_ROUND)
        reach *= p[i - 1]
    return t / math.prod(p) * 1e-9 / 3600


def search(R, target):
    best = []
    ks = [64, 128, 200, 300]
    chains = [1, 2, 4, 8, 12, 16]
    rchains = chains if R == 1 else [1, 2, 4, 8]
    kr = [4, 8, 16, 32, 64] if R == 1 else [8, 16, 32, 64]
    for n, k, cp, fc, sj, sl in itertools.product([80, 100, 120, 140], ks, chains, [True, False], [False, True], [False, True]):
        tr = range(4, 17) if R == 1 else range(5, 10)
        for ts in itertools.product(tr, repeat=R):
            for bs in itertools.product([0, 1], repeat=R):
                if R == 2 and bs[1]:
                    continue                       # round-2 bonus reaches round-1 remnants: skip
                for kis in itertools.product(kr, repeat=R):
                    for ms in itertools.product(rchains, repeat=R):
                        c = dict(R=R, n=n, k=k, chain_pin=cp, force_comp=fc, pool_deep=True, hash="sha256",
                                 sign_j=sj, sign_lvl=sl)
                        for i in range(R):
                            c[f"t{i+1}"], c[f"b{i+1}"], c[f"k{i+1}"], c[f"chain{i+1}"] = ts[i], bs[i], min(kis[i], k), ms[i]
                        if ops_estimate(c) > 201 or bytes_estimate(c) > 9900:
                            continue
                        pre, E = quick_security(c)
                        if pre < target or min(E) < 1.5:
                            continue
                        best.append((hours(c, E), pre, c))
    best.sort(key=lambda x: x[0])
    return best[:5]


def exact(c):
    cfg = {k_: v for k_, v in c.items() if k_ != "R"}
    b = q.build(cfg)
    r = q.analyse(cfg, P, b)
    return b, r


if __name__ == "__main__":
    targets = [(1, 84), (1, 88), (2, 100), (2, 110), (2, 114), (2, 120)]
    for R, tgt in targets:
        res = search(R, tgt)
        print(f"\n=== {R + 1}-stage, second-preimage >= {tgt} bits ===")
        for h, pre, c in res[:3]:
            b, r = exact(c)
            ok = b["ops"] <= 201 and len(b["script"]) <= 10000
            keys = {k_: c[k_] for k_ in c if k_ not in ("pool_deep", "hash", "R") and c[k_] not in (False, 0)}
            print(f"  4090 {h:5.2f} h | 5090 {h * GPU_SCALE['RTX 5090']:5.2f} h | exact: ops {b['ops']} bytes {len(b['script'])} "
                  f"pre {r['preimage_bits']:.1f} coll {r['collision_bits']:.1f} Q {r['quantum_query_bits']:.1f} "
                  f"E {[round(e, 1) for e in r['E']]} {'OK' if ok else 'OVER'} | {keys}")
        sys.stdout.flush()
