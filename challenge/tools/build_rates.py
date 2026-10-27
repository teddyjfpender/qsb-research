#!/usr/bin/env python3
"""Organizer tool: freeze the judge's cost table (judge/rates.json) from a measured sweep.

Input: gpu/results7/rtx4090/rates.jsonl (gpu/sweep7.sh: pool2 over the stage-shape grid, RTX 4090).
Also records the measured round problem's rehash size (real/round.bin), so the judge can charge
designs that rehash more per candidate sighash.
"""
import json
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import real_spend as rs  # noqa: E402
from qsbcore import push_min  # noqa: E402

rows = []
for l in open(ROOT / "gpu/results7/rtx4090/rates.jsonl"):
    d = json.loads(l)
    st = "pin" if d["tag"].startswith("pin") else "rnd"
    hsh = {"sha": "sha256", "rmd": "rmd", "sha1": "sha1"}[d["hash"]]
    rows.append(dict(stage=st, hash=hsh, k=d["K"], m=d["chain"], e=d["enc"], rate=d["shots_per_s"], gpu=d["gpu"]))
assert all("4090" in r["gpu"] for r in rows)
b = open(ROOT / "real/round.bin", "rb").read()
plen, rplen = struct.unpack("<II", b[36:44])
tail = struct.unpack("<I", b[44 + 64 + 480:48 + 64 + 480])[0]
built = rs.built()
script = built["script"]
off = script.index(push_min(built["dummies"][0][rs.REGION - 1]))
script_after_region = len(script) - off - 10 * rs.REGION
tx_tail = tail - script_after_region
stream = rplen + 10 * (rs.REGION - rs.T_SIGNED) + tail
out = dict(source="gpu/results7/rtx4090/rates.jsonl (pool2.cu, RTX 4090, RunPod secure cloud)",
           noise_margin=0.95, sha256_block_ns=0.0615, round_tx_tail=tx_tail + rplen,
           measured_round_blocks=math.ceil((stream + 9) / 64), rates=sorted(rows, key=lambda r: (r["stage"], r["hash"], r["e"], r["k"], r["m"])))
(ROOT / "challenge/judge/rates.json").write_text(json.dumps(out, indent=0))
print(f"{len(rows)} shapes; measured round stream {stream} B = {out['measured_round_blocks']} blocks; tx tail {tx_tail} B")
