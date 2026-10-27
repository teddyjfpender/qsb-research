#!/usr/bin/env python3
"""Leaderboard for the QSB design challenge: a Pareto frontier, not a ranking.

Each accepted run is a vector: cost (total sats, lower is better) and security (2nd-preimage bits, higher is
better). Design A dominates B if it costs no more and gives no fewer bits (strictly better in one; for an
exact tie the earlier run dominates). The board is the set of deep-verified designs nothing dominates.

  python3 leaderboard.py              the frontier, pending entries, and progress summaries
  python3 leaderboard.py --dims all   dominance over (sats, 2nd-preimage, quantum, collision bits)
  python3 leaderboard.py --dims split dominance over (vB, GPU-hours, bits): independent of the fee rate
  python3 leaderboard.py --proven     the frontier of designs whose bits are proven (Lean), not only audited
  python3 leaderboard.py --history    every design ever run (any verdict), so a loop never repeats one
  python3 leaderboard.py --pending    submission dirs whose standard run would join the frontier (one per line)

A submission improves the board if no deep-verified design dominates it. Standard runs that would join
the frontier are listed as pending until deep-verified (run_ranked.sh --deep). Only runs under the current
judge manifest count.

Summaries:
  * cheapest design with at least b bits, for several b (the cost-security curve);
  * hypervolume: area of the (bits above 80) x (sats below 250,000) region the frontier dominates, as one
    number for "did the board move", never used to compare two individual designs.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
digest = hashlib.sha256((HERE / "judge/MANIFEST.sha256").read_bytes()).hexdigest()[:16]
REF_SATS, REF_BITS = 250000, 80.0


def runs():
    out = []
    for f in sorted((HERE / "leaderboard/runs").glob("*.json")):
        r = json.loads(f.read_text())
        if r.get("verdict") == "accepted" and r.get("manifest_digest") == digest and "score" in r:
            out.append((f.name, r))
    return out


def vec(r, dims):
    s = r["score"]
    if dims == "split":                       # fee-rate independent: bytes and GPU time as separate costs
        c = r["gates"]["cost"]
        return [c["total_vbytes"], c["gpu_hours_rtx4090"], -s["preimage_bits"]]
    v = [s["sats"], -s["preimage_bits"]]
    if dims == "all":
        v += [-s["quantum_bits"], -s["collision_bits"]]
    return v


def dominates(a, b, dims):
    """a = (name, run). Ties go to the earlier run (names start with a UTC timestamp)."""
    va, vb = vec(a[1], dims), vec(b[1], dims)
    if any(x > y for x, y in zip(va, vb)):
        return False
    return va != vb or a[0] < b[0]


def frontier(pts, dims):
    return [p for p in pts if not any(dominates(o, p, dims) for o in pts if o is not p)]


def row(r):
    c, s = r["gates"]["cost"], r["score"]
    d = r["design"]
    desc = (f"{d['hash']} n{d['n']} k{d['k']} pin-chain{d['chain_pin']} sign{int(d['sign_j'])}{int(d['sign_lvl'])} "
            f"comp{int(d['force_comp'])} " + " | ".join(f"t{x['t']}+{x['b']} k{x['k']} m{x['chain']}" for x in d["rounds"]))
    return (f"{s['sats']:>8} sats  {s['preimage_bits']:>6} bits [{s.get('bits_confidence', '?'):<7}] "
            f"(q {s['quantum_bits']:>5}, coll {s['collision_bits']:>5})  "
            f"{c['gpu_hours_rtx4090']:>6} h {c['total_vbytes']:>6} vB  {r['submission']:<14} {desc}")


def hypervolume(front):
    pts = sorted(((r["score"]["preimage_bits"], r["score"]["sats"]) for _, r in front), reverse=True)
    hv, best_sats = 0.0, REF_SATS
    for i, (bits, sats) in enumerate(pts):            # sweep from high bits to low bits
        best_sats = min(best_sats, sats)
        nxt = pts[i + 1][0] if i + 1 < len(pts) else REF_BITS
        if bits > REF_BITS and best_sats < REF_SATS:
            hv += (min(bits, 200) - max(nxt, REF_BITS)) * (REF_SATS - best_sats)
    return hv


def main():
    dims = "all" if "all" in sys.argv else "split" if "split" in sys.argv else "2"
    R = runs()
    # one entry per distinct design: prefer its deep run, then the earliest
    by_design = {}
    for name, r in R:
        k = json.dumps(r["design"], sort_keys=True)
        cur = by_design.get(k)
        if cur is None or (r.get("mode") == "deep" and cur[1].get("mode") != "deep"):
            by_design[k] = (name, r)
    pts = list(by_design.values())
    deep = [p for p in pts if p[1].get("mode") == "deep"]
    if "--proven" in sys.argv:
        deep = [p for p in deep if p[1]["score"].get("bits_confidence") == "proven"]
        pts = [p for p in pts if p[1]["score"].get("bits_confidence") == "proven"]
        print("(proven-bits designs only)")
    board = sorted(frontier(deep, dims), key=lambda p: p[1]["score"]["sats"])
    pending = [p for p in pts if p[1].get("mode") != "deep" and not any(dominates(b, p, dims) for b in deep)]
    print(f"== frontier ({dict(all='sats, 2nd-pre, quantum, collision', split='vB, GPU-h, 2nd-pre').get(dims, 'sats, 2nd-preimage bits')}): "
          f"{len(board)} deep-verified designs")
    for _, r in board:
        print("   " + row(r))
    if pending:
        print("== pending deep verification (would join the frontier):")
        for _, r in sorted(pending, key=lambda p: p[1]["score"]["sats"]):
            print("   " + row(r))
    print("== cheapest deep-verified design with at least b bits:")
    for b in (85, 90, 100, 110, 116, 120, 128):
        ok = [p for p in deep if p[1]["score"]["preimage_bits"] >= b]
        best = min(ok, key=lambda p: p[1]["score"]["sats"]) if ok else None
        print(f"   >= {b:>3} bits: " + (f"{best[1]['score']['sats']:>7} sats  ({best[1]['submission']})" if best else "   none yet"))
    print(f"== hypervolume (bits > {REF_BITS:.0f}, sats < {REF_SATS}): {hypervolume(frontier(deep, '2')):.4g}")


def history():
    seen = {}
    for f in sorted((HERE / "leaderboard/runs").glob("*.json")):
        r = json.loads(f.read_text())
        k = json.dumps(r.get("design"), sort_keys=True)
        seen.setdefault(k, []).append((r.get("verdict"), r.get("rejected_at"), r.get("mode"), (r.get("score") or {}).get("sats"),
                                       (r.get("score") or {}).get("preimage_bits"), r.get("submission")))
    for k, v in seen.items():
        last = v[-1]
        print(f"{len(v)} run(s)  last: {last[0]}{' at ' + last[1] if last[1] else ''} ({last[2]})  "
              f"{last[3]} sats {last[4]} bits  {last[5]}  {k}")


def pending_dirs():
    R = runs()
    deep = [p for p in R if p[1].get("mode") == "deep"]
    deep_designs = {json.dumps(p[1]["design"], sort_keys=True) for p in deep}
    out = set()
    for p in R:
        if p[1].get("mode") != "deep" and json.dumps(p[1]["design"], sort_keys=True) not in deep_designs \
                and not any(dominates(b, p, "2") for b in deep):
            out.add(p[1]["submission"])
    for s in sorted(out):
        print(s)


if __name__ == "__main__":
    if "--history" in sys.argv:
        history()
    elif "--pending" in sys.argv:
        pending_dirs()
    else:
        main()


def status(r):
    """For run_ranked.sh: would this run join the current deep-verified frontier?"""
    R = runs()
    deep = [p for p in R if p[1].get("mode") == "deep"]
    me = ("~now.json", r)
    doms = [p for p in deep if dominates(p, me, "2") and json.dumps(p[1]["design"], sort_keys=True) != json.dumps(r["design"], sort_keys=True)]
    if doms:
        best = min(doms, key=lambda p: p[1]["score"]["sats"])[1]
        return f"dominated by {best['submission']} ({best['score']['sats']} sats, {best['score']['preimage_bits']} bits)"
    return "joins the frontier" + ("" if r.get("mode") == "deep" else " once deep-verified (run_ranked.sh --deep)")
