#!/usr/bin/env python3
"""The final security menu: five exact QSB designs covering second-preimage security up to 116 bits.

Each tier is rebuilt with qsb_pool.build(), must pass design_check() and the op/byte limits, gets
consensus vectors run through libbitcoinconsensus, and is costed with MEASURED stage rates
(gpu/results4, gpu/results5; RTX 4090). RTX 5090 times use its measured TS4 rates where they apply
and a x0.69 scale (the measured TS4 4090->5090 ratio) otherwise.
"""
import json
import math
import random
import subprocess
from pathlib import Path

import qsb_pool as q

HERE = Path(__file__).resolve().parent
P = {"sha256": math.log2(1 / q.p_der(32)), "rmd": math.log2(1 / q.p_der(20))}

# measured attempts/s on an RTX 4090 (real TS2 problem shapes), keyed by (stage, hash, pool bound, chain, encodings)
R4090 = {("pin", "sha256", 300, 16, 1): 14.28e9, ("rnd", "sha256", 64, 16, 1): 14.42e9,
         ("pin", "rmd", 300, 16, 1): 25.51e9, ("rnd", "rmd", 64, 16, 1): 25.17e9,
         ("pin", "sha256", 96, 3, 1): 10.634e9, ("pin", "sha256", 96, 1, 1): 6.549e9, ("pin", "sha256", 32, 3, 1): 9.385e9,
         ("rnd", "sha256", 96, 2, 3): 8.642e9, ("rnd", "sha256", 96, 3, 3): 10.130e9, ("rnd", "sha256", 48, 3, 3): 9.811e9,
         ("rnd", "sha256", 16, 2, 3): 7.125e9, ("rnd", "sha256", 32, 3, 3): 9.460e9}
R5090 = {("pin", "sha256", 300, 16, 1): 21.13e9, ("rnd", "sha256", 64, 16, 1): 20.59e9}

TIERS = [
    ("A", "up to 89.7 bits (2-stage, SHA-256): TS4",
     dict(hash="sha256", n=120, t1=8, k=300, k1=64, force_comp=True, pool_deep=True,
          chain_pin=16, chain_r=16, sign_j=True, sign_lvl=True), 1),
    ("B", "up to 91.6 bits (2-stage, RIPEMD-160): TS4-R",
     dict(hash="rmd", n=120, t1=8, k=300, k1=64, force_comp=True, pool_deep=True,
          chain_pin=16, chain_r=16, sign_j=True, sign_lvl=True), 1),
    ("C", "up to 108 bits (3-stage)",
     dict(hash="sha256", n=130, k=96, chain_pin=3, pool_deep=True, t1=6, b1=1, k1=96, chain1=2, t2=7, k2=96, chain2=3), 3),
    ("D", "up to 112 bits (3-stage)",
     dict(hash="sha256", n=140, k=32, chain_pin=3, pool_deep=True, t1=6, b1=1, k1=16, chain1=2, t2=7, k2=32, chain2=3), 3),
    ("E", "up to 116 bits (3-stage)",
     dict(hash="sha256", n=130, k=96, chain_pin=1, pool_deep=True, t1=7, k1=48, chain1=3, t2=7, k2=96, chain2=2), 3),
]


def hours(cfg, enc_h, E, rates):
    hsh = cfg["hash"]
    R = 2 if "t2" in cfg else 1
    p = [1 - math.exp(-x) for x in E]
    def rate(stage, k_, m_, e_):
        key = (stage, hsh, k_, m_, e_)
        return rates[key]                      # KeyError -> caller falls back to the scaled estimate
    t = 2 ** P[hsh] / rate("pin", cfg["k"], cfg.get("chain_pin", 1), 1)
    reach = 1.0
    for i in range(1, R + 1):
        m_ = cfg.get(f"chain{i}", cfg.get("chain_r", 1))
        t += reach * p[i - 1] * 2 ** P[hsh] / rate("rnd", cfg[f"k{i}"], m_, 1 if cfg.get("force_comp") else enc_h)
        reach *= p[i - 1]
    return t / math.prod(p) / 3600


def main():
    rng = random.Random(116)
    vectors, rows = [], []
    for tag, desc, cfg, enc_h in TIERS:
        b = q.build(cfg)
        r = q.analyse(cfg, P[cfg["hash"]], b)
        bad = q.design_check(b)
        assert b["ops"] <= 201 and len(b["script"]) <= 10000 and not bad and min(r["E"]) >= 1, (tag, b["ops"], len(b["script"]))
        vectors += q.vectors_for(f"TIER{tag}", dict(cfg, seed=ord(tag)), rng)
        h4 = hours(cfg, enc_h, r["E"], R4090)
        try:
            h5, h5src = hours(cfg, enc_h, r["E"], R5090), "measured"
        except KeyError:
            h5, h5src = h4 * 0.69, "est"
        rows.append(dict(tier=tag, desc=desc, cfg=cfg, enc_honest=enc_h, ops=b["ops"], bytes=len(b["script"]),
                         E=[round(x, 1) for x in r["E"]], preimage=round(r["preimage_bits"], 1),
                         quantum=round(r["quantum_query_bits"], 1), collision=round(r["collision_bits"], 1),
                         h4090=round(h4, 2), h5090=round(h5, 2), h5090_source=h5src))
    out = subprocess.run([str(HERE / "consensus_check/target/release/cchk")], input="\n".join(vectors) + "\n",
                         capture_output=True, text=True).stdout.strip().splitlines()
    (HERE / "final_menu.json").write_text(json.dumps(rows, indent=1))
    (HERE / "final_menu_vectors.txt").write_text("\n".join(vectors) + "\n")
    print(f"consensus: {len(vectors)} vectors, {out[-1]}")
    for x in rows:
        print(json.dumps(x))


if __name__ == "__main__":
    main()
