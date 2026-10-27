#!/usr/bin/env python3
"""Inner loop (no LLM needed): map the design language's cost/security Pareto frontier with the judge's
own screen mode.

  python3 tools/optimize.py [--per-bucket 3] [--rounds 3] [--out submissions/front]

1. enumerate 1- and 2-round designs on a grid, prefilter with cheap op/byte/security estimates (only
   designs above the judge's admissibility floors);
2. bucket them by estimated 2nd-preimage bits (1-bit buckets) and screen the proxy-cheapest few per
   bucket with `judge --mode screen` (the judge's real gates, unranked);
3. local search: screen every one-step neighbour of every frontier design (n, t, k, k_r, chains, hash,
   encodings, signing) until the frontier stops moving, which gets off the grid;
4. print the frontier (sats vs bits) and write each frontier design as a submission for run_ranked.sh.

Whatever this finds is the frontier of the current design language. Moving it further needs a new
mechanism (AGENT.md, MECHANISMS.md).
"""
import argparse
import itertools
import json
import math
import sys
import tempfile
from pathlib import Path

CH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CH))
sys.path.insert(0, str(CH.parent))
import security_menu as M  # noqa: E402
import qsb_pool as q  # noqa: E402
from judge import __main__ as J  # noqa: E402

M.P["sha1"] = math.log2(1 / q.p_der(20))
M.GPU["RTX 4090"]["sha1"] = 0.0275                     # proxy only; the judge prices from measurements
C = json.loads((CH / "judge/constants.json").read_text())
FLOOR = C["admissible"]["min_preimage_bits"]
GRID = {1: dict(n=range(24, 161, 8), k=[8, 16, 32, 64, 96, 128, 300], cp=[1, 2, 4, 8, 16], t=range(5, 21),
                kr=[8, 16, 32, 64, 96], m=[1, 2, 4, 8, 16]),
        2: dict(n=range(40, 161, 10), k=[16, 32, 64, 96], cp=[1, 2, 3, 4], t=range(4, 10),
                kr=[16, 32, 64, 96], m=[1, 2, 3])}
KS = [8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 300]
KRS = [8, 12, 16, 24, 32, 48, 64, 96]


def cfg_ok(c):
    if any(2 * (c[f"t{i}"] + c.get(f"b{i}", 0)) > c["n"] for i in range(1, c["R"] + 1)):
        return False
    if any(c[f"k{i}"] > min(c["k"], 96) for i in range(1, c["R"] + 1)):
        return False
    if c["sign_lvl"] and max(c[f"chain{i}"] for i in range(1, c["R"] + 1)) == 1:
        return False
    return M.ops_est(c) <= 201 and M.bytes_est(c) <= 9800


def proxy(c):
    pre, E = M.quick(c)
    if pre < FLOOR + 0.05 or min(E) < 1.2:
        return None
    h = M.hours(c, E, "RTX 4090")
    return M.bytes_est(c) * C["fee_sat_per_vbyte"] + h * C["gpu_sats_per_hour"], pre


def grid():
    for R in (1, 2):
        g = GRID[R]
        for hsh, n, k, cp, fc, sj, sl in itertools.product(["sha256", "sha1"], g["n"], g["k"], g["cp"], [True, False],
                                                           [True, False], [True, False]):
            for ts in itertools.product(g["t"], repeat=R):
                for kr in itertools.product(g["kr"], repeat=R):
                    for ms in itertools.product(g["m"], repeat=R):
                        c = dict(R=R, hash=hsh, n=n, k=k, chain_pin=cp, force_comp=fc, sign_j=sj, sign_lvl=sl,
                                 enc_honest=1 if fc else 3, pool_deep=True)
                        for i in range(R):
                            c[f"t{i+1}"], c[f"b{i+1}"], c[f"k{i+1}"], c[f"chain{i+1}"] = ts[i], 0, kr[i], ms[i]
                        if cfg_ok(c):
                            yield c


def neighbours(c):
    def step(v, vals, d):
        if v in vals:
            i = vals.index(v) + d
            return vals[i] if 0 <= i < len(vals) else None
        return None
    R = c["R"]
    out = []
    for field, vals in (("n", list(range(8, 301, 4))), ("k", KS), ("chain_pin", list(range(1, 17)))):
        for d in (-1, 1):
            v = step(c[field], vals, d)
            if v is not None:
                out.append(dict(c, **{field: v}))
    for i in range(1, R + 1):
        for field, vals in ((f"t{i}", list(range(1, 41))), (f"b{i}", [0, 1, 2]), (f"k{i}", KRS),
                            (f"chain{i}", list(range(1, 17)))):
            for d in (-1, 1):
                v = step(c[field], vals, d)
                if v is not None:
                    out.append(dict(c, **{field: v}))
    out.append(dict(c, hash="sha1" if c["hash"] == "sha256" else "sha256"))
    out.append(dict(c, force_comp=not c["force_comp"], enc_honest=1 if not c["force_comp"] else 3))
    out.append(dict(c, sign_j=not c["sign_j"]))
    out.append(dict(c, sign_lvl=not c["sign_lvl"]))
    return [x for x in out if cfg_ok(x)]


def to_design(c):
    return dict(schema="qsb-design-v2", hash=c["hash"], n=c["n"], k=c["k"], pool_deep=True,
                force_comp=c["force_comp"], chain_pin=c["chain_pin"], sign_j=c["sign_j"], sign_lvl=c["sign_lvl"],
                rounds=[dict(t=c[f"t{i}"], b=c.get(f"b{i}", 0), k=c[f"k{i}"], chain=c[f"chain{i}"])
                        for i in range(1, c["R"] + 1)])


SCREENED = {}


def screen(c):
    d = to_design(c)
    key = json.dumps(d, sort_keys=True)
    if key not in SCREENED:
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "design.json").write_text(key)
            r = J.judge(td, 1, strict_manifest=False, mode="screen")
        SCREENED[key] = (c, d, r if r["verdict"] == "screened" else None)
    return SCREENED[key]


def pareto():
    pts = [(v[2]["score"]["sats"], v[2]["score"]["preimage_bits"], v) for v in SCREENED.values() if v[2]]
    return sorted([p for p in pts if not any(o[0] <= p[0] and o[1] >= p[1] and (o[0], o[1]) != (p[0], p[1])
                                             for o in pts)], key=lambda p: p[0])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-bucket", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=3, help="local-search passes")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    buckets = {}
    n = 0
    for c in grid():
        pr = proxy(c)
        if pr is None:
            continue
        n += 1
        b = int(pr[1])
        buckets.setdefault(b, []).append((pr[0], c))
    sys.stderr.write(f"{n} admissible grid designs in {len(buckets)} 1-bit buckets\n")
    for b, lst in sorted(buckets.items()):
        lst.sort(key=lambda x: x[0])
        for _, c in lst[:a.per_bucket]:
            screen(c)
    sys.stderr.write(f"grid: {len(SCREENED)} screened, frontier {len(pareto())}\n")
    for it in range(a.rounds):
        before = {json.dumps(p[2][1], sort_keys=True) for p in pareto()}
        for p in pareto():
            for nb in neighbours(p[2][0]):
                screen(nb)
        after = {json.dumps(p[2][1], sort_keys=True) for p in pareto()}
        sys.stderr.write(f"local search pass {it + 1}: {len(SCREENED)} screened, frontier {len(after)}\n")
        if after == before:
            break
    front = pareto()
    print(f"== design-language frontier: {len(front)} designs (of {len(SCREENED)} screened)")
    for sats, bits, (c, d, r) in front:
        cg = r["gates"]["cost"]
        print(f"   {sats:>7} sats  {bits:>6} bits  {cg['gpu_hours_rtx4090']:>6} h {cg['total_vbytes']:>6} vB  "
              f"{d['hash']} n{d['n']} k{d['k']} pin-chain{d['chain_pin']} sign{int(d['sign_j'])}{int(d['sign_lvl'])} "
              f"comp{int(d['force_comp'])} " + " | ".join(f"t{x['t']}+{x['b']} k{x['k']} m{x['chain']}" for x in d["rounds"]))
    if a.out:
        for i, (_, bits, (c, d, r)) in enumerate(front):
            out = Path(f"{a.out}_{int(bits)}b_{i:02d}")
            out.mkdir(parents=True, exist_ok=True)
            (out / "design.json").write_text(json.dumps(d, indent=1))
        print(f"wrote {len(front)} submissions {a.out}_*")


if __name__ == "__main__":
    main()
