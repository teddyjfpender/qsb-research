"""Compare a pool2 POOL_DUMP (x, y, first hash word per encoding) against the CPU, exactly."""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qsbcore import enc, recover
from ripemd160 import ripemd160
import verify_pool_hits as v
pj = json.loads(Path(sys.argv[1]).read_text()); hname = sys.argv[3]
v.init(dict(prefix=bytes.fromhex(pj["pin_prefix"]), suffix=bytes.fromhex(pj["suffix"]),
            seq_offset=pj["seq_offset"], lt_offset=pj["lt_offset"]))
extra = int(sys.argv[4]) if len(sys.argv) > 4 else 0
rows = [l.split() for l in Path(sys.argv[2]).read_text().splitlines() if l.startswith("DUMP2")]
bad = checks = 0
for r in rows:
    seq, lt, j, sg = map(int, r[1:5]); xh, yh, words = r[5], r[6], r[7:]
    suf = bytearray(v.PROB["suffix"]); suf[v.PROB["seq_offset"]:v.PROB["seq_offset"] + 4] = seq.to_bytes(4, "little")
    suf[v.PROB["lt_offset"]:v.PROB["lt_offset"] + 4] = lt.to_bytes(4, "little")
    z = int.from_bytes(hashlib.sha256(hashlib.sha256(v.PROB["prefix"] + v.xblocks(lt, extra) + bytes(suf)).digest()).digest(), "big")
    Q = recover(1, j, z, sg)
    ok = int(xh, 16) == Q[0] and int(yh, 16) == Q[1]
    for e, w in enumerate(words):
        pk = enc(Q, ["comp", "uncomp", "hybrid"][e])
        h = hashlib.sha256(pk).digest() if hname == "sha" else ripemd160(pk)
        ok &= int(w, 16) == int.from_bytes(h[:4], "big")
    checks += 2 + len(words)
    if not ok:
        bad += 1
        if bad <= 4: print("mismatch", r[1:5])
print(f"{len(rows)} points, {checks} values compared, {bad} mismatching points")
