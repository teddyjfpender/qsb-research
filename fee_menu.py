#!/usr/bin/env python3
"""Round 7: total-cost (GPU + fees) frontier for 2-stage designs.

Legacy script bytes are non-witness data (1 vB per byte). The script sits in the funding output and the
witness sits in the spending scriptSig, so a 9 kB QSB script costs ~10 kvB of fees over its life. This
searches TS4-family designs (pinning + one round; SHA-1 and SHA-256) for the byte / GPU-hour Pareto
frontier at fixed security, rebuilds frontier points exactly, measures the real scriptSig of an honest
spend, and runs consensus vectors on them.
"""
import itertools, json, math, random, subprocess, sys
from pathlib import Path
import qsb_pool as q
import security_menu as M
import menu_sha1 as S

HERE = Path(__file__).resolve().parent
M.P["sha1"] = S.P1
R4 = S.load(HERE / "gpu/results6/rtx4090")
FIT = {st: S.fit(R4, st)[0] for st in ("pin", "rnd")}
G = M.GPU["RTX 4090"]


def ns_per(hsh, stage, k, m):
    if hsh == "sha1":
        return 1e9 / S.rate(R4, FIT, stage, k, m, 1)
    return M.per_attempt(G, "sha256", k, m, 1, G["setup_pin" if stage == "pin" else "setup_round"])


def hours(c, E):
    Pb = M.P[c["hash"]]
    p = 1 - math.exp(-E)
    t = 2 ** Pb * ns_per(c["hash"], "pin", c["k"], c["chain_pin"]) + p * 2 ** Pb * ns_per(c["hash"], "rnd", c["k1"], c["chain1"])
    return t / p * 1e-9 / 3600


def cands():
    for hsh, n, t1, k, cp, m, sj, sl in itertools.product(
            ["sha1", "sha256"], range(16, 161, 8), range(5, 21), [8, 16, 32, 64, 128, 300], [1, 2, 4, 8, 16],
            [1, 2, 4, 8, 16], [True, False], [True, False]):
        if sl and m == 1:
            continue
        for k1 in (8, 16, 32, 64):
            if k1 > k:
                continue
            c = dict(R=1, hash=hsh, n=n, k=k, chain_pin=cp, force_comp=True, sign_j=sj, sign_lvl=sl, enc_honest=1,
                     pool_deep=True, t1=t1, b1=0, k1=k1, chain1=m)
            if M.ops_est(c) <= 201 and M.bytes_est(c) <= 9800:
                yield c


def exact(c):
    cfg = {k_: v for k_, v in c.items() if k_ not in ("R", "enc_honest", "b1")}
    cfg["chain_r"] = c["chain1"]
    b = q.build(cfg)
    r = q.analyse(cfg, M.P[c["hash"]], b)
    rng = random.Random(7)
    ch = dict(jp=rng.randrange(c["k"]), j=[rng.randrange(1, c["k1"] + 1)], subsets=[rng.sample(range(c["n"]), c["t1"])],
              odd=[0, 0], lvl=[c["chain_pin"], c["chain1"]], enc=["comp", "comp"])
    q.spend(b, ch)
    ok = b["ops"] <= 201 and len(b["script"]) <= 10000 and not q.design_check(b) and r["E"][0] >= 1
    return cfg, b, r, len(b["last_script_sig"]), ok


def main():
    target = float(sys.argv[1]) if len(sys.argv) > 1 else 89.5
    pts = []
    for c in cands():
        pre, E = M.quick(c)
        if pre < target or E[0] < 3:
            continue
        pts.append((M.bytes_est(c), hours(c, E[0]), pre, c))
    sys.stderr.write(f"{len(pts)} designs at >= {target} bits\n")
    pts.sort(key=lambda x: (x[0], x[1]))
    front, best_h = [], 1e9
    for p in pts:                                     # Pareto: fewer bytes, then fewer hours
        if p[1] < best_h - 1e-9:
            front.append(p)
            best_h = p[1]
    rows, vectors, rng = [], [], random.Random(70)
    for est_b, h, pre, c in front:
        cfg, b, r, ss, ok = exact(c)
        total = len(b["script"]) + ss + 60                # + funding output / input / OP_RETURN overhead
        rows.append(dict(hash=c["hash"], n=c["n"], t1=c["t1"], k=c["k"], k1=c["k1"], chain_pin=c["chain_pin"],
                         chain1=c["chain1"], sign_j=c["sign_j"], sign_lvl=c["sign_lvl"], ops=b["ops"],
                         script_bytes=len(b["script"]), scriptsig_bytes=ss, total_vbytes=total,
                         E=round(r["E"][0], 1), preimage=round(r["preimage_bits"], 1),
                         quantum=round(r["quantum_query_bits"], 1), collision=round(r["collision_bits"], 1),
                         h4090=round(h, 2), valid=ok))
        vectors += q.vectors_for(f"FEE{len(rows)}", dict(cfg, seed=len(rows)), rng)
    res = subprocess.run([str(HERE / "consensus_check/target/release/cchk")], input="\n".join(vectors) + "\n",
                         capture_output=True, text=True).stdout.strip().splitlines()
    print(f"consensus: {len(vectors)} vectors, {res[-1]}")
    print("| hash | n | t | pool k | k1 | chain pin/round | signed j/lvl | ops | script B | scriptSig B | total vB | E | 2nd-pre | RTX 4090 h |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for x in rows:
        print(f"| {x['hash']} | {x['n']} | {x['t1']} | {x['k']} | {x['k1']} | {x['chain_pin']}/{x['chain1']} | "
              f"{'Y' if x['sign_j'] else 'n'}/{'Y' if x['sign_lvl'] else 'n'} | {x['ops']} | {x['script_bytes']} | "
              f"{x['scriptsig_bytes']} | {x['total_vbytes']} | {x['E']} | {x['preimage']} | {x['h4090']} |")
    (HERE / f"fee_menu_{int(target)}.json").write_text(json.dumps(rows, indent=1))
    (HERE / f"fee_menu_{int(target)}_vectors.txt").write_text("\n".join(vectors) + "\n")


if __name__ == "__main__":
    main()
