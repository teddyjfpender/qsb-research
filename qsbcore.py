"""Shared helpers: secp256k1, DER, legacy script/tx serialization, FindAndDelete, legacy sighash.

Pure Python and written for clarity, not speed. Everything that matters for consensus is
cross-checked against Bitcoin Core's libbitcoinconsensus by the vector generators.
"""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# The SIGHASH_SINGLE bug returns uint256::ONE, whose bytes (01 00 .. 00) are read big-endian
# by secp256k1 as the message scalar. The effective z is therefore 2^248, not 1.
Z_SINGLE_BUG = 1 << 248


# ---------------------------------------------------------------- curve
def inv(a, m):
    return pow(a, -1, m)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = 3 * x1 * x1 * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def mul(k, pt):
    k %= N
    acc = None
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def lift_x(x, odd):
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, y if (y & 1) == odd else P - y)


def recover(r, s, z, odd):
    """Public key Q with ECDSA-verify(Q, z, (r, s)) true, using the R with y parity `odd`."""
    R = lift_x(r, odd)
    ri = inv(r, N)
    return add(mul(s * ri, R), neg(mul(z * ri, G)))


def recover_all(r, s, z):
    """Every key Q with ECDSA-verify(Q, z, (r, s)) true: R may have x = r or x = r + n (if < p), either parity."""
    out = []
    ri = inv(r, N)
    for x in (r, r + N):
        if x >= P:
            continue
        for odd in (0, 1):
            R = lift_x(x, odd)
            if R is not None:
                out.append(add(mul(s * ri, R), neg(mul(z * ri, G))))
    return out


def enc(Q, kind="comp"):
    x, y = Q
    if kind == "comp":
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    if kind == "uncomp":
        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    if kind == "hybrid":
        return bytes([6 + (y & 1)]) + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    raise ValueError(kind)


def der9(r, s, ht):
    """Minimal 9-byte DER signature with one-byte r and s."""
    assert 0 < r < 0x80 and 0 < s < 0x80
    return bytes([0x30, 6, 2, 1, r, 2, 1, s, ht])


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    return b"\x00" + b if b[0] & 0x80 else b


def der_sig(r, s, ht):
    """Minimal strict-DER signature for any r, s (9 bytes when both < 128, 10 when s < 2^15, ...)."""
    rb, sb = der_int(r), der_int(s)
    body = bytes([2, len(rb)]) + rb + bytes([2, len(sb)]) + sb
    return bytes([0x30, len(body)]) + body + bytes([ht])


def is_valid_der(sig):
    """Bitcoin Core IsValidSignatureEncoding (BIP66), including the trailing hashtype byte."""
    n = len(sig)
    if n < 9 or n > 73 or sig[0] != 0x30 or sig[1] != n - 3:
        return False
    len_r = sig[3]
    if 5 + len_r >= n:
        return False
    len_s = sig[5 + len_r]
    if len_r + len_s + 7 != n:
        return False
    if sig[2] != 0x02 or len_r == 0 or sig[4] & 0x80:
        return False
    if len_r > 1 and sig[4] == 0 and not sig[5] & 0x80:
        return False
    if sig[len_r + 4] != 0x02 or len_s == 0 or sig[len_r + 6] & 0x80:
        return False
    if len_s > 1 and sig[len_r + 6] == 0 and not sig[len_r + 7] & 0x80:
        return False
    return True


def ripemd160(b):
    from ripemd160 import ripemd160 as _r      # hashlib, or pure-Python fallback on OpenSSL 3
    return _r(b)


def hash160(b):
    return ripemd160(hashlib.sha256(b).digest())


# ---------------------------------------------------------------- script
OP = dict(OP_0=0x00, OP_PUSHDATA1=0x4C, OP_PUSHDATA2=0x4D, OP_1=0x51, OP_16=0x60,
          OP_DROP=0x75, OP_SIZE=0x82, OP_DUP=0x76, OP_SWAP=0x7C, OP_TUCK=0x7D, OP_PICK=0x79, OP_ROLL=0x7A,
          OP_EQUALVERIFY=0x88, OP_MIN=0xA3, OP_ADD=0x93,
          OP_RIPEMD160=0xA6, OP_SHA1=0xA7, OP_SHA256=0xA8, OP_HASH160=0xA9,
          OP_CHECKSIG=0xAC, OP_CHECKSIGVERIFY=0xAD, OP_CHECKMULTISIG=0xAE,
          OP_CHECKMULTISIGVERIFY=0xAF)


def push_min(b):
    if len(b) == 0:
        return bytes([OP["OP_0"]])
    if len(b) < 0x4C:
        return bytes([len(b)]) + b
    if len(b) <= 0xFF:
        return bytes([OP["OP_PUSHDATA1"], len(b)]) + b
    return bytes([OP["OP_PUSHDATA2"]]) + len(b).to_bytes(2, "little") + b


def push_nonmin(b):
    """PUSHDATA1 encoding of a short element: consensus-valid, invisible to FindAndDelete."""
    assert len(b) < 0x4C
    return bytes([OP["OP_PUSHDATA1"], len(b)]) + b


def scriptnum(v):
    if v == 0:
        return b""
    neg_ = v < 0
    v = abs(v)
    out = []
    while v:
        out.append(v & 0xFF)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg_ else 0)
    elif neg_:
        out[-1] |= 0x80
    return bytes(out)


def push_num(v):
    if v == 0:
        return bytes([OP["OP_0"]])
    if 1 <= v <= 16:
        return bytes([0x50 + v])
    return push_min(scriptnum(v))


def get_ops(script):
    """Offsets of each opcode (Core's GetOp boundaries)."""
    i, out = 0, []
    while i < len(script):
        out.append(i)
        op = script[i]
        i += 1
        if 1 <= op < 0x4C:
            i += op
        elif op == 0x4C:
            i += 1 + script[i]
        elif op == 0x4D:
            i += 2 + int.from_bytes(script[i:i + 2], "little")
        elif op == 0x4E:
            i += 4 + int.from_bytes(script[i:i + 4], "little")
    return out


def find_and_delete(script, sig):
    """Core's FindAndDelete(scriptCode, CScript() << sig): minimal push pattern, opcode boundaries only."""
    pat = push_min(sig)
    bounds = get_ops(script) + [len(script)]
    out, i = bytearray(), 0
    while i < len(script):
        while script[i:i + len(pat)] == pat:
            i += len(pat)
        if i >= len(script):
            break
        nxt = next(b for b in bounds if b > i)
        out += script[i:nxt]
        i = nxt
    return bytes(out)


# ---------------------------------------------------------------- transactions (legacy, no witness)
def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def ser_tx(ins, outs, locktime=0, version=1):
    b = version.to_bytes(4, "little") + varint(len(ins))
    for (txid, vout, ss, seq) in ins:
        b += txid + vout.to_bytes(4, "little") + varint(len(ss)) + ss + seq.to_bytes(4, "little")
    b += varint(len(outs))
    for (val, spk) in outs:
        b += val.to_bytes(8, "little") + varint(len(spk)) + spk
    return b + locktime.to_bytes(4, "little")


def sighash_all(ins, outs, idx, script_code, ht=1, locktime=0):
    """Legacy SignatureHash for SIGHASH_ALL-family hashtypes (script_code already FindAndDelete'd)."""
    ins2 = [(t, v, (script_code if i == idx else b""), s) for i, (t, v, _, s) in enumerate(ins)]
    pre = ser_tx(ins2, outs, locktime) + ht.to_bytes(4, "little")
    return int.from_bytes(hashlib.sha256(hashlib.sha256(pre).digest()).digest(), "big")
