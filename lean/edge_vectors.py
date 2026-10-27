#!/usr/bin/env python3
"""Edge-case consensus vectors for the Lean script model, labelled by Bitcoin Core itself.

Each case is a small bare scriptPubKey + spending tx aimed at one rule the model must get right
(limits, CScriptNum, ROLL/PICK bounds, strict DER, CHECKMULTISIG loop/NULLDUMMY/key count, sighash
types incl. the SIGHASH_SINGLE bug, pubkey encodings, FindAndDelete, CastToBool). The expected
verdict is NOT written here: every vector is run through libbitcoinconsensus (consensus_check/cchk)
and the file records Core's answer. The Lean replay must then agree with Core on every line.
Cases also carry the verdict we *intend*; a mismatch there means the case does not test what it
says and is reported (not silently kept).
"""
import hashlib
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from qsbcore import G, N, P, add, enc, mul, push_min, push_num, ser_tx, varint, der_sig  # noqa: E402

CCHK = HERE.parent / "consensus_check/target/release/cchk"
rng = random.Random(1234)
INS = [(rng.randbytes(32), 0, b"", 0xFFFFFFFF), (rng.randbytes(32), 1, b"", 0xFFFFFFFE),
       (rng.randbytes(32), 2, b"", 0xFFFFFFFD)]
OUTS = [(5000, bytes([0x6A, 4]) + b"qsb!"), (6000, bytes([0x6A, 3]) + b"two")]
LT = 99


def op(name):
    from qsbcore import OP
    extra = dict(OP_NOP=0x61, OP_EQUAL=0x87, OP_1NEGATE=0x4F, OP_CHECKSIG=0xAC, OP_VERIFY=0x69)
    return bytes([OP.get(name, extra.get(name))])


def sighash(script_code, idx, ht):
    """Core's legacy SignatureHash (no OP_CODESEPARATOR in our scripts)."""
    base, acp = ht & 0x1F, ht & 0x80
    if base == 3 and idx >= len(OUTS):
        return 1 << 248
    ins = [INS[idx]] if acp else INS
    b = (1).to_bytes(4, "little") + varint(len(ins))
    for i, (t, v, _, s) in enumerate(ins):
        real = idx if acp else i
        sc = script_code if real == idx else b""
        seq = 0 if (real != idx and base in (2, 3)) else s
        b += t + v.to_bytes(4, "little") + varint(len(sc)) + sc + seq.to_bytes(4, "little")
    outs = [] if base == 2 else (OUTS[:idx + 1] if base == 3 else OUTS)
    b += varint(len(outs))
    for i, (val, spk) in enumerate(outs):
        if base == 3 and i != idx:
            b += (2**64 - 1).to_bytes(8, "little") + b"\x00"
        else:
            b += val.to_bytes(8, "little") + varint(len(spk)) + spk
    b += LT.to_bytes(4, "little") + ht.to_bytes(4, "little")
    return int.from_bytes(hashlib.sha256(hashlib.sha256(b).digest()).digest(), "big")


def sign(d, z, ht, high_s=False):
    k = int.from_bytes(hashlib.sha256(d.to_bytes(32, "big") + z.to_bytes(32, "big")).digest(), "big") % N
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    if (s > N // 2) != high_s:
        s = N - s
    return der_sig(r, s, ht)


def tx_with(script_sig, idx=1):
    ins = [(t, v, (script_sig if i == idx else b""), s) for i, (t, v, _, s) in enumerate(INS)]
    return ser_tx(ins, OUTS, LT)


def pushes(items):
    return b"".join(push_min(x) if isinstance(x, bytes) else push_num(x) for x in items)


cases = []   # (name, spk, tx, idx, intended)


def case(name, spk, items, intended, idx=1):
    cases.append((name, spk, tx_with(pushes(items), idx), idx, intended))


D1, D2, D3 = 0xA11CE, 0xB0B, 0xCAFE
K1, K2, K3 = (mul(d, G) for d in (D1, D2, D3))

# --- CHECKSIG, sighash types, pubkey encodings
spk = push_min(enc(K1)) + op("OP_CHECKSIG")
for ht, nm in ((1, "all"), (2, "none"), (3, "single"), (0x81, "all_acp"), (0x83, "single_acp"), (0x42, "odd_type")):
    case(f"checksig_{nm}", spk, [sign(D1, sighash(spk, 1, ht), ht)], True)
case("checksig_single_bug_idx2", spk, [sign(D1, sighash(spk, 2, 3), 3)], True, idx=2)
case("checksig_high_s_is_consensus_valid", spk, [sign(D1, sighash(spk, 1, 1), 1, high_s=True)], True)
case("checksig_wrong_key_false", push_min(enc(K2)) + op("OP_CHECKSIG"), [sign(D1, sighash(spk, 1, 1), 1)], False)
case("checksig_empty_sig_false_not_error", spk + push_num(0) + op("OP_EQUAL"), [b""], True)
bad_der = bytearray(sign(D1, sighash(spk, 1, 1), 1)); bad_der[0] = 0x31
case("checksig_nonDER_aborts_even_if_result_dropped", spk + op("OP_DROP") + push_num(1), [bytes(bad_der)], False)
for kind in ("uncomp", "hybrid"):
    s2 = push_min(enc(K1, kind)) + op("OP_CHECKSIG")
    case(f"checksig_pubkey_{kind}", s2, [sign(D1, sighash(s2, 1, 1), 1)], True)
hyb_bad = bytearray(enc(K1, "hybrid")); hyb_bad[0] ^= 1
s3 = push_min(bytes(hyb_bad)) + op("OP_CHECKSIG")
case("checksig_hybrid_wrong_parity_false", s3, [sign(D1, sighash(s3, 1, 1), 1)], False)
off = bytearray(enc(K1, "uncomp")); off[-1] ^= 1
s4 = push_min(bytes(off)) + op("OP_CHECKSIG")
case("checksig_point_off_curve_false", s4, [sign(D1, sighash(s4, 1, 1), 1)], False)
s5 = push_min(b"\x05" + bytes(32)) + op("OP_CHECKSIG") + push_num(0) + op("OP_EQUAL")
case("checksig_garbage_pubkey_false_not_error", s5, [sign(D1, sighash(s5, 1, 1), 1)], True)

# --- FindAndDelete: the sig inside scriptCode is deleted before hashing
sigz = sign(D1, 12345, 1)          # placeholder to size the script, replaced below
def fad_case(nonmin):
    for _ in range(3):
        global sigz
        body = (bytes([0x4C, len(sigz)]) + sigz if nonmin else push_min(sigz)) + op("OP_DROP") + spk
        from qsbcore import find_and_delete
        z = sighash(find_and_delete(body, sigz), 1, 1)
        new = sign(D1, z, 1)
        if len(new) == len(sigz):
            sigz = new
            body = (bytes([0x4C, len(sigz)]) + sigz if nonmin else push_min(sigz)) + op("OP_DROP") + spk
            return body
        sigz = new
    raise RuntimeError("size did not settle")
b1 = fad_case(False)
case("findanddelete_minimal_copy_is_removed", b1, [sigz], True)

# --- CHECKMULTISIG
ms = push_num(2) + push_min(enc(K1)) + push_min(enc(K2)) + push_min(enc(K3)) + push_num(3) + op("OP_CHECKMULTISIG")
sg1, sg3 = sign(D1, sighash(ms, 1, 1), 1), sign(D3, sighash(ms, 1, 1), 1)
case("cms_2of3_ok", ms, [b"", sg1, sg3], True)
case("cms_2of3_wrong_order_fails", ms, [b"", sg3, sg1], False)
case("cms_nulldummy_nonempty_fails", ms, [b"\x01", sg1, sg3], False)
case("cms_nulldummy_zero_byte_fails", ms, [b"\x00", sg1, sg3], False)
bad = bytearray(sg3); bad[0] = 0x31
case("cms_reached_nonDER_sig_aborts", ms, [b"", bytes(bad), sg3], False)
junk = sign(D2, 777, 1)            # strict DER, verifies under no key here
case("cms_unreached_nonDER_sig_ignored", ms + push_num(0) + op("OP_EQUAL"), [b"", bytes(bad), junk], True)
ms1 = push_num(1) + push_min(enc(K1)) + push_min(enc(K2)) + push_num(2) + op("OP_CHECKMULTISIG")
s_1 = sign(D2, sighash(ms1, 1, 1), 1)
case("cms_1of2_second_key", ms1, [b"", s_1], True)
keys21 = b"".join(push_min(enc(K1)) for _ in range(21))
case("cms_21_keys_pubkey_count", push_num(0) + keys21 + push_min(bytes([21])) + op("OP_CHECKMULTISIG"), [b""], False)
keys20 = b"".join(push_min(enc(K1)) for _ in range(20))
for nops, ok in ((180, True), (181, False)):
    s_ = op("OP_NOP") * nops + push_num(0) + keys20 + push_min(bytes([20])) + op("OP_CHECKMULTISIG")
    case(f"cms_20_keys_after_{nops}_nops", s_, [b""], ok)
case("cms_nsigs_gt_nkeys", push_num(2) + push_min(enc(K1)) + push_num(1) + op("OP_CHECKMULTISIG"), [b"", sg1, sg1], False)

# --- limits
case("ops_201_ok", op("OP_NOP") * 200 + push_num(1) + op("OP_NOP"), [], True)
case("ops_202_fail", op("OP_NOP") * 202 + push_num(1), [], False)
case("push_520_ok", push_min(bytes(520)) + op("OP_DROP") + push_num(1), [], True)
case("push_521_fail", push_min(bytes(521)) + op("OP_DROP") + push_num(1), [], False)
case("stack_1000_ok", push_num(1), [1] * 999, True)
case("stack_1001_fail", push_num(1), [1] * 1000, False)
big = b"".join(push_min(bytes(500)) + op("OP_DROP") for _ in range(19))
def sized(total):
    for x in range(1, 521):
        sc = big + push_min(bytes(x)) + op("OP_DROP") + push_num(1)
        if len(sc) == total:
            return sc
    raise ValueError(total)
case("script_10000_ok", sized(10000), [], True)
case("script_10001_fail", sized(10001), [], False)

# --- numbers, ROLL/PICK
case("roll_negative_fails", op("OP_ROLL") + push_num(1), [5, -1], False)
case("roll_too_deep_fails", op("OP_ROLL"), [7, 2], False)
case("roll_deepest_ok", op("OP_ROLL") + op("OP_DROP") + op("OP_DROP") + push_num(1), [7, 8, 1], True)
case("pick_ok", op("OP_PICK") + push_num(7) + op("OP_EQUALVERIFY") + op("OP_DROP") + push_num(1), [7, 8, 1], True)
case("nonminimal_number_ok", op("OP_ADD") + push_num(3) + op("OP_EQUAL"), [b"\x01\x00", 2], True)
case("negative_zero_is_zero", op("OP_ADD") + push_num(2) + op("OP_EQUAL"), [b"\x80", 2], True)
case("five_byte_operand_fails", op("OP_ADD") + op("OP_DROP") + push_num(1), [b"\x01\x00\x00\x00\x00", 1], False)
case("four_byte_operand_ok", op("OP_ADD") + op("OP_DROP") + push_num(1), [b"\xff\xff\xff\x7f", 1], True)
case("add_overflow_result_5_bytes_ok", op("OP_ADD") + op("OP_SIZE") + push_num(5) + op("OP_EQUALVERIFY") + op("OP_DROP") + push_num(1),
     [b"\xff\xff\xff\x7f", b"\xff\xff\xff\x7f"], True)
case("min_negative", op("OP_MIN") + push_min(b"\x85") + op("OP_EQUAL"), [5, -5], True)
case("sub_order", op("OP_SUB") + push_num(3) + op("OP_EQUAL"), [5, 2], True)
case("size_empty", op("OP_SIZE") + push_num(0) + op("OP_EQUALVERIFY") + op("OP_DROP") + push_num(1), [b""], True)
case("final_negative_zero_is_false", op("OP_NOP"), [b"\x00\x80"], False)
case("final_nonzero_is_true", op("OP_NOP"), [b"\x00\x81"], True)
case("sha1_256_ripemd", op("OP_SHA1") + op("OP_SHA256") + op("OP_RIPEMD160") + op("OP_HASH160") + op("OP_SIZE") +
     push_num(20) + op("OP_EQUALVERIFY") + op("OP_DROP") + push_num(1), [b"abc"], True)
case("hash160_value", op("OP_HASH160") + push_min(bytes.fromhex("bb1be98c142444d7a56aa3981c3942a978e4dc33")) +
     op("OP_EQUALVERIFY") + push_num(1), [b"abc"], True)
# a bare `HASH160 <20> EQUAL` is P2SH under Core's flags: the top item then runs as a script
redeem_ok, redeem_bad = push_num(1), push_num(0)
from qsbcore import hash160 as _h160
p2sh = lambda rs: op("OP_HASH160") + push_min(_h160(rs)) + op("OP_EQUAL")
case("p2sh_redeem_true", p2sh(redeem_ok), [redeem_ok], True)
case("p2sh_redeem_false", p2sh(redeem_bad), [redeem_bad], False)
case("2drop_swap_dup", op("OP_SWAP") + op("OP_2DROP") + op("OP_DUP") + op("OP_EQUAL"), [3, 4, 5], True)

# DER edge cases through the puzzle check `<x> OP_1 OP_CHECKSIG OP_DROP`
dcheck = lambda x: push_min(x) + push_num(1) + op("OP_CHECKSIG") + op("OP_DROP") + push_num(1)
cases.append(("der_20_ok", dcheck(bytes.fromhex("3011020101020c0102030405060708090a0b7f01")), tx_with(b""), 1, True))
for nm, hx in (("der_r_negative", "3011020181020c0102030405060708090a0b7f01"),
               ("der_r_padded", "30120202000102" + "0c0102030405060708090a0b7f01"),
               ("der_s_padded", "3012020101020d000102030405060708090a0b7f01"),
               ("der_len_mismatch", "3012020101020c0102030405060708090a0b7f01"),
               ("der_short_8", "3005020101020101")):
    cases.append((nm, dcheck(bytes.fromhex(hx)), tx_with(b""), 1, False))
cases.append(("der_r_needed_pad_ok", dcheck(bytes.fromhex("30120202008102" + "0c0102030405060708090a0b7f01")), tx_with(b""), 1, True))


def main():
    lines = [f"EDGE_{n} {spk.hex()} {tx.hex()} {i} {1 if ok else 0}" for n, spk, tx, i, ok in cases]
    out = subprocess.run([str(CCHK)], input="\n".join(lines) + "\n", capture_output=True, text=True).stdout.splitlines()
    verdict = {}
    for l in out:
        f = l.split()
        if len(f) >= 3 and f[0] in ("PASS", "FAIL"):
            verdict[f[1]] = "consensus=VALID" in l
    res, surprises = [], []
    for (n, spk, tx, i, ok) in cases:
        core = verdict[f"EDGE_{n}"]
        if core != ok:
            surprises.append(f"EDGE_{n}: intended {ok}, Core says {core}")
        res.append(f"EDGE_{n} {spk.hex()} {tx.hex()} {i} {1 if core else 0}")
    (HERE / "vectors/edge.txt").write_text("\n".join(res) + "\n")
    print(f"edge vectors: {len(res)} written with Core's verdicts; {len(surprises)} differ from the intended verdict")
    for s in surprises:
        print("  " + s)
    sys.exit(1 if surprises else 0)


if __name__ == "__main__":
    main()
