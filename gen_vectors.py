#!/usr/bin/env python3
"""Mechanism-level consensus vectors. Pipe into consensus_check (Bitcoin Core libbitcoinconsensus).

  T1  C1+C2+C3  Nonce pool pushed with OP_PUSHDATA1: one z serves every pool sig; the keys are
                +-s_j*A - B; compressed/uncompressed/hybrid encodings are all consensus-valid.
  T2  C4        Control: a minimally pushed pool sig IS deleted by FindAndDelete (z depends on j).
  T3  C5        CHECKMULTISIG: minimal dummy sigs are deleted (the subset changes z), the
                non-minimal nonce sig is not; dummy keys use the SINGLE-bug value z = 2^248.
  T4            Sanity: the non-minimal pattern is not matched by FindAndDelete.
  T5  C6        DER-only puzzle check `<20B> OP_1 OP_CHECKSIG OP_DROP`: any strict-DER 20-byte
                string passes (arbitrary hashtype byte, r not an x-coordinate), non-DER aborts.
  T6  C7        OP_SHA1 is enabled in legacy script.
"""
import hashlib
import random
import sys

from qsbcore import (G, N, OP, Z_SINGLE_BUG, add, der9, enc, find_and_delete, inv, is_valid_der,
                     lift_x, mul, neg, push_min, push_nonmin, push_num, recover, ser_tx, sighash_all)

rng = random.Random(7)
INS = [(rng.randbytes(32), 0, b"", 0xFFFFFFFF), (rng.randbytes(32), 1, b"", 0xFFFFFFFE)]
OUTS = [(5000, bytes([0x6A, 4]) + b"qsb!")]   # 1 output, spend input 1 => SIGHASH_SINGLE bug
IDX, LOCKTIME = 1, 777


def spend(items):
    ss = b"".join(push_min(x) if isinstance(x, bytes) else push_num(x) for x in items)
    ins = [(t, v, (ss if i == IDX else b""), s) for i, (t, v, _, s) in enumerate(INS)]
    return ser_tx(ins, OUTS, LOCKTIME)


def zof(script_code):
    return sighash_all(INS, OUTS, IDX, script_code, locktime=LOCKTIME)


vec = []


def emit(name, spk, tx, ok):
    vec.append(f"{name} {spk.hex()} {tx.hex()} {IDX} {1 if ok else 0}")


R_OK = [x for x in range(1, 0x80) if lift_x(x, 0)]
r = R_OK[0]                                    # r = 1 lies on secp256k1 (8 is a QR mod p)
K = 4
S_POOL = list(range(1, K + 1))
POOL = [der9(r, s, 0x01) for s in S_POOL]
A = mul(inv(r, N), lift_x(r, 0))
o = lambda name: bytes([OP[name]])

# ---------------------------------------------------------------- T1 / T2
def t1_script(nonminimal):
    p = push_nonmin if nonminimal else push_min
    s = b"".join(p(x) for x in POOL)            # stack: key jd S1..S4
    s += push_num(K) + o("OP_ROLL")             # key S1..S4 jd
    s += o("OP_PICK")                           # key S1..S4 Sj
    s += push_num(K + 1) + o("OP_ROLL")         # S1..S4 Sj key
    return s + o("OP_CHECKSIG")


spk1 = t1_script(True)
z1 = zof(spk1)
B1 = mul(z1 * inv(r, N), G)
n_alg = 0
for j, s in enumerate(S_POOL):
    for odd in (0, 1):
        Q = recover(r, s, z1, odd)
        assert Q == add(mul(s, A) if odd == 0 else neg(mul(s, A)), neg(B1))
        n_alg += 1
        for kind in ("comp", "uncomp", "hybrid"):
            emit(f"T1_nonmin_pool_j{j}_R{'odd' if odd else 'even'}_{kind}", spk1,
                 spend([enc(Q, kind), K - 1 - j]), True)

spk2 = t1_script(False)
for j, s in enumerate(S_POOL[:2]):
    emit(f"T2_min_pool_j{j}_z_without_deletion", spk2,
         spend([enc(recover(r, s, zof(spk2), 0)), K - 1 - j]), False)
    emit(f"T2_min_pool_j{j}_z_with_deletion", spk2,
         spend([enc(recover(r, s, zof(find_and_delete(spk2, POOL[j])), 0)), K - 1 - j]), True)

# ---------------------------------------------------------------- T3 / T4
DUMMY_SIGS = [der9(r2, s2, 0x03) for r2, s2 in [(R_OK[1], 5), (R_OK[2], 9), (R_OK[3], 11)]]


def t3_script():
    # scriptSig (bottom->top): KD KEY adepth jdepth
    s = b"".join(push_min(d) for d in DUMMY_SIGS)
    s += b"".join(push_nonmin(x) for x in POOL)
    s += push_num(0)                                     # KD KEY ad jd D0 D1 D2 S1..S4 NULL
    s += push_num(8) + o("OP_ROLL") + o("OP_PICK")       # ... NULL Sj
    s += push_num(9) + o("OP_ROLL") + o("OP_PICK")       # ... NULL Sj Da
    s += push_num(2)
    s += push_num(11) + o("OP_ROLL")                     # ... 2 KEY
    s += push_num(12) + o("OP_ROLL")                     # ... 2 KEY KD
    return s + push_num(2) + o("OP_CHECKMULTISIG")


spk3 = t3_script()
zs = {}
for a, dsig in enumerate(DUMMY_SIGS):
    sc = find_and_delete(spk3, dsig)
    assert len(sc) == len(spk3) - 10
    zs[a] = z3 = zof(sc)
    for zname, zone in {"z=1": 1, "z=2^248": Z_SINGLE_BUG}.items():
        KD = recover(dsig[4], dsig[7], zone, 0)
        for j, s in enumerate(S_POOL):
            for odd in (0, 1):
                Q = recover(r, s, z3, odd)
                kinds = ("comp", "uncomp", "hybrid") if (a == 0 and zone == Z_SINGLE_BUG) else ("comp",)
                for kind in kinds:
                    emit(f"T3_cms_dummy{a}_{zname}_j{j}_R{'odd' if odd else 'even'}_{kind}", spk3,
                         spend([enc(KD), enc(Q, kind), 2 - a + K + 2, K - j]), zone == Z_SINGLE_BUG)
assert len(set(zs.values())) == 3
emit("T4_sanity_nonmin_really_not_matched", spk3,
     spend([enc(recover(DUMMY_SIGS[0][4], DUMMY_SIGS[0][7], Z_SINGLE_BUG, 0)),
            enc(recover(r, 1, zs[0], 0)), 2 + K + 2, K]), True)

# ---------------------------------------------------------------- T5: DER-only puzzle check
# scriptPubKey: <candidate 20B sig> OP_1 OP_CHECKSIG OP_DROP OP_1
# OP_1 pushes a 1-byte "pubkey": not a valid key, so CHECKSIG returns false WITHOUT failing
# (STRICTENC and NULLFAIL are policy only). DERSIG is consensus, so non-DER aborts the script.
def der20(len_r, ht, rng_):
    while True:
        len_s = 13 - len_r
        rb = bytes([rng_.randrange(1, 0x80)]) + rng_.randbytes(len_r - 1)
        sb = bytes([rng_.randrange(1, 0x80)]) + rng_.randbytes(len_s - 1)
        sig = bytes([0x30, 17, 2, len_r]) + rb + bytes([2, len_s]) + sb + bytes([ht])
        if is_valid_der(sig):
            return sig


def t5_spk(candidate):
    return push_min(candidate) + push_num(1) + o("OP_CHECKSIG") + o("OP_DROP") + push_num(1)


n_offcurve = 0
for len_r in (1, 5, 12):
    for ht in (0x00, 0x01, 0x03, 0x80, 0xFF):
        sig = der20(len_r, ht, rng)
        rv = int.from_bytes(sig[4:4 + len_r], "big")
        on_curve = lift_x(rv, 0) is not None
        n_offcurve += not on_curve
        emit(f"T5_der_only_lenR{len_r}_ht{ht:02x}_{'oncurve' if on_curve else 'OFFcurve'}",
             t5_spk(sig), spend([]), True)
# an r that is not an x-coordinate, explicitly
r_bad = next(x for x in range(2, 0x80) if lift_x(x, 0) is None)
sig_bad_r = bytes([0x30, 17, 2, 1, r_bad, 2, 12]) + bytes([0x11]) + rng.randbytes(11) + b"\x01"
assert is_valid_der(sig_bad_r)
emit(f"T5_der_only_r{r_bad}_not_x_coordinate", t5_spk(sig_bad_r), spend([]), True)
for label, bad in [("first_byte", b"\x31" + sig_bad_r[1:]), ("len_byte", sig_bad_r[:1] + b"\x12" + sig_bad_r[2:]),
                   ("negative_s", sig_bad_r[:7] + b"\x91" + sig_bad_r[8:])]:
    assert not is_valid_der(bad)
    emit(f"T5_non_der_{label}_aborts", t5_spk(bad), spend([]), False)

# ---------------------------------------------------------------- T6: OP_SHA1 available
m = b"qsb"
emit("T6_op_sha1_enabled", push_min(m) + o("OP_SHA1") + push_min(hashlib.sha1(m).digest()) + bytes([0x87]),
     spend([]), True)
emit("T6_op_sha1_wrong_digest", push_min(m) + o("OP_SHA1") + push_min(hashlib.sha1(b"x").digest()) + bytes([0x87]),
     spend([]), False)

sys.stderr.write(f"r={r}; algebra checks (Q == +-s*A - B): {n_alg}; off-curve DER samples: {n_offcurve + 1}; "
                 f"vectors: {len(vec)}\n")
print("\n".join(vec))
