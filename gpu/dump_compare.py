"""Compare a POOL_DUMP from pool.cu against CPU values for the same candidate."""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qsbcore import recover
from ripemd160 import ripemd160
import verify_pool_hits as v
pj = json.loads(Path(sys.argv[1]).read_text()); hname = sys.argv[3]
v.init(dict(prefix=bytes.fromhex(pj["pin_prefix"]), suffix=bytes.fromhex(pj["suffix"]),
            seq_offset=pj["seq_offset"], lt_offset=pj["lt_offset"]))
bad = 0; rows = [l.split() for l in Path(sys.argv[2]).read_text().splitlines() if l.startswith("DUMP")]
for _, seq, lt, j, sg, xh, par, h0 in rows:
    seq, lt, j, sg = int(seq), int(lt), int(j), int(sg)
    suf = bytearray(v.PROB["suffix"]); suf[v.PROB["seq_offset"]:v.PROB["seq_offset"]+4] = seq.to_bytes(4, "little")
    suf[v.PROB["lt_offset"]:v.PROB["lt_offset"]+4] = lt.to_bytes(4, "little")
    z = int.from_bytes(hashlib.sha256(hashlib.sha256(v.PROB["prefix"] + bytes(suf)).digest()).digest(), "big")
    Q = recover(1, j, z, sg); pk = bytes([2 + (Q[1] & 1)]) + Q[0].to_bytes(32, "big")
    h = hashlib.sha256(pk).digest() if hname == "sha" else ripemd160(pk)
    ok_x = int(xh, 16) == Q[0]; ok_p = int(par) == (Q[1] & 1); ok_h = int(h0, 16) == int.from_bytes(h[:4], "big")
    if not (ok_x and ok_p and ok_h):
        bad += 1
        if bad <= 6: print(f"j={j} sg={sg} x_ok={ok_x} parity_ok={ok_p} hash_ok={ok_h}")
print(f"{len(rows)} dumped, {bad} mismatches")
