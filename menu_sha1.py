#!/usr/bin/env python3
"""Round 6: OP_SHA1 designs. Refit the per-attempt cost model to measured SHA-1 stage rates (gpu/results6),
then search 2- and 3-stage designs for every security target from 90 to 120 bits, rebuild the winners exactly,
design_check them, and run consensus vectors.

Cost model per attempt (ns, whole GPU): (setup/(2k) + key + blocks*H) / (e*m), blocks = (1 if e == 1 else 5) + e*(m-1),
with setup/key/H fitted separately for pinning and round stages (least squares on log error).
"""
import itertools, json, math, random, subprocess, sys
from pathlib import Path
import qsb_pool as q
import security_menu as M

HERE = Path(__file__).resolve().parent
M.P["sha1"] = math.log2(1 / q.p_der(20))
P1 = M.P["sha1"]


def load(gpu_dir):
    rows = [json.loads(l) for l in open(gpu_dir / "rates.jsonl")]
    out = {}
    for d in rows:
        if d.get("hash") != "sha1":
            continue
        stage = "pin" if d["tag"].startswith("pin") else "rnd"
        out[(stage, d["K"], d["chain"], d["enc"])] = d["shots_per_s"]
    return out


def model_ns(c, k, m, e):
    blocks = (1 if e == 1 else 5) + e * (m - 1)
    return (c[0] / (2 * k) + c[1] + blocks * c[2]) / (e * m)


def fit(rates, stage):
    """Linear least squares on ns*e*m = setup/(2k) + key + blocks*H, weighted by relative error."""
    import numpy as np
    pts = [(k, m, e, 1e9 / r) for (s, k, m, e), r in rates.items() if s == stage]
    A = np.array([[1 / (2 * k), 1, (1 if e == 1 else 5) + e * (m - 1)] for k, m, e, _ in pts])
    y = np.array([ns * e * m for k, m, e, ns in pts])
    c, *_ = np.linalg.lstsq(A / y[:, None], np.ones(len(y)), rcond=None)
    c = tuple(float(x) for x in c)
    worst = max(abs(model_ns(c, k, m, e) / ns - 1) for k, m, e, ns in pts)
    return c, worst, len(pts)


def rate(rates, fitc, stage, k, m, e):
    return rates.get((stage, k, m, e)) or 1e9 / model_ns(fitc[stage], k, m, e)


def hours(c, E, rates, fitc):
    p = [1 - math.exp(-x) for x in E]
    t = 2 ** P1 / rate(rates, fitc, "pin", c["k"], c["chain_pin"], c.get("enc_pin", 1))
    reach = 1.0
    for i in range(1, c["R"] + 1):
        e_h = 1 if c["force_comp"] else c.get("enc_honest", 1)
        t += reach * p[i - 1] * 2 ** P1 / rate(rates, fitc, "rnd", c[f"k{i}"], c.get(f"chain{i}", 1), e_h)
        reach *= p[i - 1]
    return t / math.prod(p) / 3600


def candidates3():
    for n, k, cp, ep, fc, eh in itertools.product([100, 110, 120, 130, 140, 150], [16, 32, 48, 64, 96, 128],
                                                 [1, 2, 3, 4], [1, 3], [False], [1, 3]):
        for t1, t2 in itertools.product(range(5, 10), repeat=2):
            for b1 in (0, 1):
                for k1, k2 in itertools.product([16, 32, 48, 64, 96], repeat=2):
                    if k1 > k or k2 > k:
                        continue
                    for m1, m2 in itertools.product([1, 2, 3], repeat=2):
                        c = dict(R=2, hash="sha1", n=n, k=k, chain_pin=cp, enc_pin=ep, force_comp=fc, sign_j=False,
                                 sign_lvl=False, enc_honest=eh, pool_deep=True, t1=t1, b1=b1, k1=k1, chain1=m1,
                                 t2=t2, b2=0, k2=k2, chain2=m2)
                        if M.ops_est(c) <= 201 and M.bytes_est(c) <= 9800:
                            yield c


def main():
    gdir = HERE / "gpu/results6"
    out = {}
    # rtx5090/rates.jsonl holds only the clean sweep5 shapes (the 5090 sweep6 run overlapped a second copy of
    # itself; see rates_all_contaminated.jsonl), so the 5090 fit uses the 4090 fit scaled by the measured ratio.
    for gpu, sub in (("RTX 4090", "rtx4090"), ("RTX 5090", "rtx5090")):
        rates = load(gdir / sub)
        if gpu == "RTX 5090":
            r4, f4 = out["RTX 4090"]
            ratio = sum(rates[k] / r4[k] for k in rates if k in r4) / sum(1 for k in rates if k in r4)
            sys.stderr.write(f"RTX 5090 / RTX 4090 measured SHA-1 rate ratio: {ratio:.3f}\n")
            out[gpu] = (rates, {st: tuple(x / ratio for x in f4[st]) for st in f4})
            continue
        fitc = {}
        for st in ("pin", "rnd"):
            fitc[st], worst, npts = fit(rates, st)
            sys.stderr.write(f"{gpu} {st}: setup/key/H = {fitc[st]}  worst fit error {worst:.1%} over {npts} shapes\n")
        out[gpu] = (rates, fitc)
    targets = [100, 104, 108, 112, 116, 120]
    best = {t: None for t in targets}
    cnt = 0
    for c in candidates3():
        pre, E = M.quick(c)
        if min(E) < 1.5:
            continue
        cnt += 1
        h = hours(c, E, *out["RTX 4090"])
        for t in targets:
            if pre >= t and (best[t] is None or h < best[t][0]):
                best[t] = (h, pre, c)
    sys.stderr.write(f"feasible 3-stage SHA-1 candidates: {cnt}\n")
    rng = random.Random(61)
    vectors, rows = [], []
    for t in targets:
        if not best[t]:
            continue
        h, pre, c = best[t]
        cfg = M.cfg_of(c)
        cfg["chain1"], cfg["chain2"] = c["chain1"], c["chain2"]
        cfg.pop("enc_pin", None)
        b = q.build(cfg)
        r = q.analyse(cfg, P1, b)
        bad = q.design_check(b)
        ok = b["ops"] <= 201 and len(b["script"]) <= 10000 and not bad and min(r["E"]) >= 1
        vectors += q.vectors_for(f"SHA1_{t}", dict(cfg, seed=t), rng)
        rows.append(dict(target=t, cfg=cfg, enc_pin=c["enc_pin"], enc_honest=c["enc_honest"], ops=b["ops"],
                         bytes=len(b["script"]), E=[round(x, 1) for x in r["E"]], preimage=round(r["preimage_bits"], 1),
                         quantum=round(r["quantum_query_bits"], 1), collision=round(r["collision_bits"], 1),
                         h4090=round(h, 2), h5090=round(hours(c, r["E"], *out["RTX 5090"]), 2), valid=ok))
        print(json.dumps(rows[-1]))
    # 2-stage TS4 with SHA-1 (tier B config, OP_SHA1)
    ts4 = dict(hash="sha1", n=120, t1=8, k=300, k1=64, force_comp=True, pool_deep=True, chain_pin=16, chain_r=16,
               sign_j=True, sign_lvl=True)
    b = q.build(ts4)
    r = q.analyse(ts4, P1, b)
    assert not q.design_check(b) and b["ops"] <= 201 and len(b["script"]) <= 10000
    vectors += q.vectors_for("TS4_SHA1", dict(ts4, seed=41), rng)
    c = dict(R=1, k=300, chain_pin=16, force_comp=True, k1=64, chain1=16)
    rows.insert(0, dict(target="TS4-SHA1", cfg=ts4, ops=b["ops"], bytes=len(b["script"]), E=[round(x, 1) for x in r["E"]],
                        preimage=round(r["preimage_bits"], 1), quantum=round(r["quantum_query_bits"], 1),
                        collision=round(r["collision_bits"], 1), h4090=round(hours(c, r["E"], *out["RTX 4090"]), 2),
                        h5090=round(hours(c, r["E"], *out["RTX 5090"]), 2), valid=True))
    print(json.dumps(rows[0]))
    res = subprocess.run([str(HERE / "consensus_check/target/release/cchk")], input="\n".join(vectors) + "\n",
                         capture_output=True, text=True).stdout.strip().splitlines()
    print(f"consensus: {len(vectors)} vectors, {res[-1]}")
    (HERE / "menu_sha1.json").write_text(json.dumps(rows, indent=1))
    (HERE / "menu_sha1_vectors.txt").write_text("\n".join(vectors) + "\n")


if __name__ == "__main__":
    main()
