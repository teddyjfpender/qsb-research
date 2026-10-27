#!/usr/bin/env python3
"""Finer 3-stage search for the 100-116 bit tier (security_menu.py's R=2 grid is coarse)."""
import itertools, math, sys, json
import security_menu as M, qsb_pool as q
best = {t: None for t in (100, 104, 108, 112, 116)}
cnt = 0
for hsh, n, k, cp, fc, eh in itertools.product(["sha256", "rmd"], [100, 110, 120, 130, 140, 150], [32, 64, 96, 128, 160, 200],
                                               [1, 2, 3, 4, 6, 8], [True, False], [1, 3]):
    if fc and eh == 3:
        continue
    for t1, t2 in itertools.product(range(5, 10), range(5, 10)):
        for b1 in (0, 1):
            for k1, k2 in itertools.product([8, 16, 24, 32, 48, 64, 96], repeat=2):
                if k1 > k or k2 > k:
                    continue
                for m1, m2 in itertools.product([1, 2, 3], repeat=2):
                    c = dict(R=2, hash=hsh, n=n, k=k, chain_pin=cp, force_comp=fc, sign_j=False, sign_lvl=False,
                             enc_honest=eh, pool_deep=True, t1=t1, b1=b1, k1=k1, chain1=m1, t2=t2, b2=0, k2=k2, chain2=m2)
                    if M.ops_est(c) > 201 or M.bytes_est(c) > 9800:
                        continue
                    pre, E = M.quick(c)
                    if min(E) < 1.5:
                        continue
                    cnt += 1
                    h = M.hours(c, E, "RTX 4090")
                    for t in best:
                        if pre >= t and (best[t] is None or h < best[t][0]):
                            best[t] = (h, pre, c)
sys.stderr.write(f"feasible 3-stage candidates: {cnt}\n")
out = {}
for t, v in best.items():
    h, pre, c = v
    cfg = M.cfg_of(c); cfg["chain1"], cfg["chain2"] = c["chain1"], c["chain2"]
    b = q.build(cfg); r = q.analyse(cfg, M.P[c["hash"]], b)
    ok = b["ops"] <= 201 and len(b["script"]) <= 10000 and not q.design_check(b) and min(r["E"]) >= 1
    out[t] = dict(cfg=cfg, enc_honest=c["enc_honest"], h4090=round(h, 2), h5090=round(M.hours(c, M.quick(c)[1], "RTX 5090"), 2),
                  ops=b["ops"], bytes=len(b["script"]), pre=round(r["preimage_bits"], 1), coll=round(r["collision_bits"], 1),
                  Q=round(r["quantum_query_bits"], 1), E=[round(x, 1) for x in r["E"]], valid=ok)
    print(t, json.dumps(out[t]))
json.dump(out, open("menu_fine3.json", "w"), indent=1)
