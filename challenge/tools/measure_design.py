#!/usr/bin/env python3
"""Organizer tool (promotion): re-measure a leading design's exact stage shapes on an RTX 4090.

  python3 tools/measure_design.py plan <design.json>             > measure.sh   (run in research/gpu/)
  python3 tools/measure_design.py compare <design.json> <rates.jsonl>

`plan` prints pool2 runs (30 s each, the design's exact k / chain / encodings) for pinning and every
round. `compare` checks every measured rate against the rate the judge's table used to price the
design. If any stage measured slower than priced, it prints the repriced GPU-hours and score. That
means the table was optimistic for this shape: add the shape to the table and re-release the judge.
"""
import json
import math
import sys
from pathlib import Path

CH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CH))
sys.path.insert(0, str(CH.parent))
from judge import cost, design  # noqa: E402

HASH = {"sha256": "sha", "rmd": "rmd", "sha1": "sha1"}


def shapes(cfg):
    out = [("pin", cfg["k"], cfg["chain_pin"], e) for e in (1, 3)]
    R = 1 + ("t2" in cfg)
    for i in range(1, R + 1):
        for e in ((1,) if cfg["force_comp"] else (1, 3)):
            out.append(("rnd", cfg[f"k{i}"], cfg[f"chain{i}"], e))
    return sorted(set(out))


def main():
    d, cfg = design.load(sys.argv[2])
    if cfg.get("spacer_selection") or cfg.get("destructive_chain"):
        raise SystemExit("This construction requires the exact-layout renderer, not real/round.bin. "
                         "Use challenge/mechanisms/spacer_selection/gpu_validation.py and "
                         "run_gpu_validation.py; freeze verified results with tools/build_exact_rates.py. "
                         "See judge/releases/qsb-judge-3.md.")
    if sys.argv[1] == "plan":
        print("#!/bin/bash\ncd \"$(dirname \"$0\")\"; : > measured.jsonl")
        for st, k, m, e in shapes(cfg):
            b, prob = ("./pool2", "../real/pin.bin") if st == "pin" else ("./pool2_round", "../real/round.bin")
            print(f"POOL_CHAIN={m} {b} {prob} {k} {HASH[cfg['hash']]} zeros 30 30 0 /dev/null {e} 0 2>/dev/null "
                  f"| sed 's/^{{/{{\"tag\":\"{st}_k{k}_m{m}_e{e}\",/' >> measured.jsonl")
        return
    tbl = cost.load_table()
    meas = {}
    for l in open(sys.argv[3]):
        r = json.loads(l)
        meas[("pin" if r["tag"].startswith("pin") else "rnd", r["K"], r["chain"], r["enc"])] = r["shots_per_s"]
    worst = 1.0
    for key in shapes(cfg):
        st, k, m, e = key
        priced = cost.lookup(tbl, st, cfg["hash"], k, m, e)
        got = meas.get(key)
        if got is None:
            print(f"{key}: not measured")
            continue
        ratio = got / priced
        worst = min(worst, ratio)
        print(f"{st} k={k} m={m} e={e}: priced {priced / 1e9:.3f} G/s, measured {got / 1e9:.3f} G/s "
              f"({'OK' if ratio >= 1 else 'TABLE OPTIMISTIC'} x{ratio:.3f})")
    print("promotion check:", "pass (every stage at least as fast as priced)" if worst >= 1 else
          f"FAIL: re-price with measured rates (worst stage x{worst:.3f}) and re-release the rate table")


if __name__ == "__main__":
    main()
