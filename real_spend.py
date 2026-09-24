#!/usr/bin/env python3
"""A real (no stand-ins) TS2 QSB spend: production script, real SHA-256 DER puzzles, found on a GPU.

  setup                      production TS2 script + spend template; writes real/pin.bin (Layr format)
  check-pin H S N            CPU re-derivation of zeros-gate pinning hits (pipeline check)
  round-problem SEQ LT       fix the tx from a pinning hit; writes real/round.bin
  check-round SEQ LT H S N   CPU re-derivation of zeros-gate round hits (pipeline check)
  assemble PINHIT ROUNDHIT   build the witness; print a consensus vector (production script)

The QSB input is input 2 of 3 (two ordinary funding inputs first), so with 2 outputs the dummies'
SIGHASH_SINGLE bug applies. The spend carries an 8-byte OP_RETURN nonce as the pinning search field, so nSequence = 0xffffffff
and nLockTime = 0 (final). The GPU patches the nonce as two LE u32 words (the kernel's seq, lt).
Round search: 16 signed selections from dummy indices 0..47 (the last 48 pushes before the code),
counter -> subset by lexicographic unranking, identical to pool2.cu ROUND_MODE.
"""
import hashlib
import json
import math
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qsb_pool as q
from qsbcore import (Z_SINGLE_BUG, enc, find_and_delete, is_valid_der, push_min, recover, ser_tx, sighash_all)

CFG = dict(n=150, t1=16, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256", seed=2026)
OUT = Path(__file__).resolve().parent / "real"
IDX = 2          # SIGHASH_SINGLE bug for the dummies needs input index >= number of outputs (2)
TXIDS = [hashlib.sha256(b"qsb-real-funding-%d" % i).digest() for i in range(3)]
DEST = bytes([0x76, 0xA9, 0x14]) + hashlib.new("sha256", b"qsb-dest").digest()[:20] + bytes([0x88, 0xAC])
T_SIGNED, REGION = 16, 48

# ---------------------------------------------------------------- SHA-256 midstate (pure Python)
_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def midstate(data):
    assert len(data) % 64 == 0
    h = list(_IV)
    for off in range(0, len(data), 64):
        w = list(struct.unpack(">16I", data[off:off + 64]))
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            t1 = (hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g)) + _K[i] + w[i]) & 0xFFFFFFFF
            t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xFFFFFFFF
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return h


# ---------------------------------------------------------------- transaction
def tx_parts(nonce8):
    ins = [(TXIDS[i], 0, b"", 0xFFFFFFFF) for i in range(3)]
    outs = [(9000, DEST), (0, bytes([0x6A, 0x08]) + nonce8)]
    return ins, outs, IDX, 0


def nonce_of(seq, lt):
    return struct.pack("<II", seq, lt)


def built(test_mode=False):
    return q.build(CFG, test_mode=test_mode)


def binom_table():
    return [[math.comb(n, k) for k in range(17)] for n in range(49)]


def unrank(counter):
    """lexicographic 16-subset of positions 0..47 (matches pool2.cu ROUND_MODE)"""
    B = binom_table(); sel = []; need = T_SIGNED; r = counter
    for pos in range(REGION):
        if not need:
            break
        c = B[47 - pos][need - 1]
        if r < c:
            sel.append(pos); need -= 1
        else:
            r -= c
    return sel


def pos_to_dummy(pos):
    return REGION - 1 - pos          # script order D_47 .. D_0 at the end of the region


def lz(h):
    n = 0
    for byte in h:
        if byte == 0:
            n += 8; continue
        return n + 8 - byte.bit_length()
    return n


# ---------------------------------------------------------------- commands
def cmd_setup():
    OUT.mkdir(exist_ok=True)
    b = built()
    assert not q.design_check(b), "designer check failed"
    ins, outs, idx, lt = tx_parts(b"\x00" * 8)
    ins2 = [(t, v, (b["script"] if i == idx else b""), s) for i, (t, v, _, s) in enumerate(ins)]
    pre = ser_tx(ins2, outs, lt) + (1).to_bytes(4, "little")
    total = len(pre)
    nonce_off = total - 16                     # outs[1] nonce, then locktime (4), hashtype (4)
    assert pre[nonce_off - 2:nonce_off] == b"\x6a\x08"
    plen = ((total - 20) // 64) * 64
    suffix = pre[plen:]
    assert len(suffix) <= 119
    ms = midstate(pre[:plen])
    binf = b"".join(struct.pack(">I", v) for v in ms) + struct.pack("<I", len(suffix)) + suffix
    binf += struct.pack("<III", total, nonce_off - plen, nonce_off - plen + 4)
    (OUT / "pin.bin").write_bytes(binf)
    meta = dict(script_len=len(b["script"]), ops=b["ops"], total_preimage=total, midstate_bytes=plen,
                cfg=CFG, script_sha256=hashlib.sha256(b["script"]).hexdigest())
    (OUT / "meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta))


def pin_derive(seq, lt, s, sg, e=0):
    b = built()
    ins, outs, idx, locktime = tx_parts(nonce_of(seq, lt))
    z = sighash_all(ins, outs, idx, b["script"], locktime=locktime)
    return hashlib.sha256(enc(recover(1, s, z, sg), ["comp", "uncomp", "hybrid"][e])).digest()


def cmd_check_pin(hits, summary, N):
    rows = [tuple(map(int, l.split())) for l in Path(hits).read_text().splitlines() if l.strip()][:200]
    ok = sum(lz(pin_derive(q_, lt, j, sg, e)) >= N for (q_, lt, j, sg, e) in rows)
    s = json.loads(Path(summary).read_text().splitlines()[-1])
    print(json.dumps(dict(stage="pinning", checked=len(rows), ok=ok, reported=s["hits"], expected=s["expected_hits"])))


def round_scriptcode(b, sel_pos):
    sc = b["script"]
    for pos in sel_pos:
        sc = find_and_delete(sc, b["dummies"][0][pos_to_dummy(pos)])
    return sc


def cmd_round_problem(seq, lt):
    b = built()
    ins, outs, idx, locktime = tx_parts(nonce_of(seq, lt))
    script = b["script"]
    d47 = push_min(b["dummies"][0][REGION - 1])
    off = script.index(d47)
    region = script[off:off + 10 * REGION]
    assert all(region[10 * p:10 * p + 10] == push_min(b["dummies"][0][pos_to_dummy(p)]) for p in range(REGION))
    sc_len = len(script) - 10 * T_SIGNED
    sc_dummy = script[:off] + region[:10 * (REGION - T_SIGNED)] + script[off + 10 * REGION:]   # length-correct stand-in
    ins2 = [(t, v, (sc_dummy if i == idx else b""), s) for i, (t, v, _, s) in enumerate(ins)]
    full = ser_tx(ins2, outs, locktime) + (1).to_bytes(4, "little")
    head = full[:full.index(sc_dummy)]                                   # up to and including the varint
    assert len(sc_dummy) == sc_len
    const = head + script[:off]
    plen = (len(const) // 64) * 64
    rp = const[plen:]
    tail = script[off + 10 * REGION:] + full[len(head) + sc_len:]
    assert len(rp) < 64 and len(tail) <= 1024
    ms = midstate(const[:plen])
    binf = b"RND1" + b"".join(struct.pack(">I", v) for v in ms) + struct.pack("<II", plen, len(rp))
    binf += rp.ljust(64, b"\0") + region + struct.pack("<I", len(tail)) + tail
    binf += b"".join(struct.pack("<Q", v) for row in binom_table() for v in row)
    (OUT / "round.bin").write_bytes(binf)
    # self-check: the stream model equals the real sighash for a sample subset
    sel = unrank(123456789)
    stream = rp + b"".join(region[10 * p:10 * p + 10] for p in range(REGION) if p not in sel) + tail
    z_model = int.from_bytes(hashlib.sha256(hashlib.sha256(const[:plen] + stream).digest()).digest(), "big")
    z_real = sighash_all(ins, outs, idx, round_scriptcode(b, sel), locktime=locktime)
    assert z_model == z_real, "round stream model mismatch"
    print(json.dumps(dict(round_problem="ok", midstate_bytes=plen, rp=len(rp), tail=len(tail),
                          subsets=math.comb(REGION, T_SIGNED), stream_model_check="z matches sighash_all")))


def round_derive(seq, lt, counter, s, sg):
    b = built()
    ins, outs, idx, locktime = tx_parts(nonce_of(seq, lt))
    z = sighash_all(ins, outs, idx, round_scriptcode(b, unrank(counter)), locktime=locktime)
    return hashlib.sha256(enc(recover(1, s, z, sg))).digest()


def cmd_check_round(seq, lt, hits, summary, N):
    rows = [tuple(map(int, l.split())) for l in Path(hits).read_text().splitlines() if l.strip()][:200]
    ok = sum(lz(round_derive(seq, lt, (hq << 32) | hl, j, sg)) >= N for (hq, hl, j, sg, e) in rows)
    s = json.loads(Path(summary).read_text().splitlines()[-1])
    print(json.dumps(dict(stage="round", checked=len(rows), ok=ok, reported=s["hits"], expected=s["expected_hits"])))


def cmd_assemble(pinhit, roundhit):
    pseq, plt, ps, psg, pe = map(int, pinhit.split())
    rhq, rhl, rs, rsg, re_ = map(int, roundhit.split())
    b = built()
    tx = tx_parts(nonce_of(pseq, plt))
    counter = (rhq << 32) | rhl
    sel = [pos_to_dummy(p) for p in unrank(counter)]
    # the real puzzles, recomputed on CPU first
    hp = pin_derive(pseq, plt, ps, psg, pe)
    hr = round_derive(pseq, plt, counter, rs, rsg)
    sys.stderr.write(f"pinning SHA256(key) = {hp.hex()}  strict DER: {is_valid_der(hp)}\n")
    sys.stderr.write(f"round   SHA256(key) = {hr.hex()}  strict DER: {is_valid_der(hr)}\n")
    choice = dict(jp=ps - 1, j=[rs], subsets=[sel], odd=[psg, rsg], enc=[["comp", "uncomp", "hybrid"][pe], "comp"])
    txb, idx, zs = q.spend(b, choice, tx=tx)
    (OUT / "spend_tx.hex").write_text(txb.hex())
    (OUT / "script.hex").write_text(b["script"].hex())
    print(f"REAL_TS2_production_spend {b['script'].hex()} {txb.hex()} {idx} 1")


if __name__ == "__main__":
    a = sys.argv[1:]
    {"setup": lambda: cmd_setup(),
     "check-pin": lambda: cmd_check_pin(a[1], a[2], int(a[3])),
     "round-problem": lambda: cmd_round_problem(int(a[1]), int(a[2])),
     "check-round": lambda: cmd_check_round(int(a[1]), int(a[2]), a[3], a[4], int(a[5])),
     "assemble": lambda: cmd_assemble(a[1], a[2])}[a[0]]()
