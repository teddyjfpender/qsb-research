#!/usr/bin/env python3
"""Independently re-derive every hit reported by pool.cu (anti-cheat style, like Layr's verify.py).

hit line: "seq lt j sign"  ->  preimage = pin_prefix || X(lt, extra) || suffix(seq, lt)
z = SHA256d(preimage);  Q = recover(r=1, s=j, z, odd=sign)  (sign 0: +jA - B, sign 1: -jA - B)
h = SHA256 or RIPEMD160 of compressed Q;  require leading_zero_bits(h) >= N.
Also checks hit count against expectation and runs a negative control (j+1) that must fail.
"""
import argparse
import hashlib
import json
import math
import sys
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qsbcore import enc, recover  # noqa: E402
from ripemd160 import ripemd160  # noqa: E402

PROB = None


def xblocks(lt, extra):
    out = bytearray()
    for b in range(extra):
        blk = bytearray(((i * 7 + 13) & 0xFF) for i in range(64))
        if b == 0:
            blk[0:4] = lt.to_bytes(4, "little")
        out += blk
    return bytes(out)


def lzbits(h):
    n = 0
    for byte in h:
        if byte == 0:
            n += 8
            continue
        return n + 8 - byte.bit_length()
    return n


def derive(args):
    seq, lt, j, sign, extra, hname, kind = (args + ("comp",))[:7]
    suf = bytearray(PROB["suffix"])
    suf[PROB["seq_offset"]:PROB["seq_offset"] + 4] = seq.to_bytes(4, "little")
    suf[PROB["lt_offset"]:PROB["lt_offset"] + 4] = lt.to_bytes(4, "little")
    pre = PROB["prefix"] + xblocks(lt, extra) + bytes(suf)
    z = int.from_bytes(hashlib.sha256(hashlib.sha256(pre).digest()).digest(), "big")
    pk = enc(recover(1, j, z, sign), kind)
    h = hashlib.sha256(pk).digest() if hname == "sha" else ripemd160(pk)
    return lzbits(h)


def init(p):
    global PROB
    PROB = p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("problem_json")
    ap.add_argument("hits")
    ap.add_argument("--summary", required=True, help="JSON line printed by pool")
    ap.add_argument("--max", type=int, default=3000)
    a = ap.parse_args()
    s = json.loads(Path(a.summary).read_text().strip().splitlines()[-1])
    pj = json.loads(Path(a.problem_json).read_text())
    prob = dict(prefix=bytes.fromhex(pj["pin_prefix"]), suffix=bytes.fromhex(pj["suffix"]),
                seq_offset=pj["seq_offset"], lt_offset=pj["lt_offset"])
    hits = [tuple(map(int, l.split())) for l in Path(a.hits).read_text().split("\n") if l.strip()]
    hits = [h if len(h) == 5 else h + (0,) for h in hits]         # pool.cu lines have no encoding field
    KINDS = ["comp", "uncomp", "hybrid"]
    uniq = set(hits)
    sample = sorted(uniq)[: a.max]
    N = s["N"]
    with Pool(initializer=init, initargs=(prob,)) as pool:
        lz = pool.map(derive, [(q, lt, j, sg, s["extra_blocks"], s["hash"], KINDS[e]) for (q, lt, j, sg, e) in sample])
        ctrl = pool.map(derive, [(q, lt, j % s["K"] + 1 if s["K"] > 1 else j, 1 - sg, s["extra_blocks"], s["hash"],
                                  KINDS[e]) for (q, lt, j, sg, e) in sample[:200]])
    bad = sum(1 for v in lz if v < N)
    ctrl_pass = sum(1 for v in ctrl if v >= N)
    exp = s["expected_hits"]
    z = (s["hits"] - exp) / math.sqrt(exp) if exp else float("nan")
    by_enc = [sum(1 for h in uniq if h[4] == e) for e in range(3)]
    res = dict(K=s["K"], enc=s.get("enc", 1), hits_by_encoding=by_enc, hash=s["hash"], extra=s["extra_blocks"], N=N, reported=s["hits"], unique=len(uniq),
               duplicates=len(hits) - len(uniq), verified=len(sample) - bad, failed=bad,
               expected=round(exp, 1), poisson_z=round(z, 2), control_false_pass=ctrl_pass,
               ok=bad == 0 and len(hits) == len(uniq) and abs(z) < 5
               and ctrl_pass <= 2 + 4 * len(ctrl) * 2.0 ** -N)
    print(json.dumps(res))
    sys.exit(0 if res["ok"] else 1)


if __name__ == "__main__":
    main()
