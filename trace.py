"""Minimal legacy-script tracer for the opcode subset used by qsb_pool (debugging aid, not consensus).

Consensus answers come from consensus_check (libbitcoinconsensus). This tracer shows *why*
a spend passes or fails: which items CHECKMULTISIG received and which pairs verified.
"""
import hashlib

from qsbcore import G, N, OP, add, find_and_delete, get_ops, inv, is_valid_der, lift_x, mul, sighash_all


def num(b):
    if not b:
        return 0
    v = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


def enc_num(v):
    from qsbcore import scriptnum
    return scriptnum(v)


def parse_pubkey(b):
    if len(b) == 33 and b[0] in (2, 3):
        return lift_x(int.from_bytes(b[1:], "big"), b[0] & 1)
    if len(b) == 65 and b[0] in (4, 6, 7):
        return (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
    return None


def parse_der(sig):
    lr = sig[3]
    r = int.from_bytes(sig[4:4 + lr], "big")
    ls = sig[5 + lr]
    s = int.from_bytes(sig[6 + lr:6 + lr + ls], "big")
    return r, s


def ecdsa_ok(z, sig, pub):
    Q = parse_pubkey(pub)
    if Q is None:
        return False
    r, s = parse_der(sig)
    if not (0 < r < N and 0 < s < N):
        return False
    w = inv(s, N)
    R = add(mul(z * w, G), mul(r * w, Q))
    return R is not None and R[0] % N == r


def run(script, stack, sighash_fn, log=print):
    """sighash_fn(script_code, hashtype) -> z. Returns (ok, reason)."""
    bounds = get_ops(script)
    for pos in bounds:
        op = script[pos]
        if 1 <= op <= 0x4E:
            if op < 0x4C:
                stack.append(script[pos + 1:pos + 1 + op])
            elif op == 0x4C:
                stack.append(script[pos + 2:pos + 2 + script[pos + 1]])
            else:
                ln = int.from_bytes(script[pos + 1:pos + 3], "little")
                stack.append(script[pos + 3:pos + 3 + ln])
            continue
        if op == 0:
            stack.append(b"")
        elif 0x51 <= op <= 0x60:
            stack.append(bytes([op - 0x50]))
        elif op == OP["OP_ROLL"] or op == OP["OP_PICK"]:
            d = num(stack.pop())
            if d < 0 or d >= len(stack):
                return False, f"{'ROLL' if op == OP['OP_ROLL'] else 'PICK'} out of range {d} @{pos}"
            item = stack[-1 - d]
            if op == OP["OP_ROLL"]:
                del stack[-1 - d]
            stack.append(item)
        elif op == OP["OP_MIN"]:
            b_, a_ = num(stack.pop()), num(stack.pop())
            stack.append(enc_num(min(a_, b_)))
        elif op == OP["OP_ADD"]:
            b_, a_ = num(stack.pop()), num(stack.pop())
            stack.append(enc_num(a_ + b_))
        elif op == OP["OP_DUP"]:
            stack.append(stack[-1])
        elif op == OP["OP_DROP"]:
            stack.pop()
        elif op == OP["OP_SWAP"]:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 0x61:
            pass
        elif op == OP["OP_HASH160"]:
            stack.append(hashlib.new("ripemd160", hashlib.sha256(stack.pop()).digest()).digest())
        elif op == OP["OP_RIPEMD160"]:
            stack.append(hashlib.new("ripemd160", stack.pop()).digest())
        elif op == OP["OP_EQUALVERIFY"]:
            if stack.pop() != stack.pop():
                return False, f"EQUALVERIFY @{pos}"
        elif op in (OP["OP_CHECKSIG"], OP["OP_CHECKSIGVERIFY"]):
            pub, sig = stack.pop(), stack.pop()
            if sig and not is_valid_der(sig):
                return False, f"non-DER sig @{pos}"
            ok = bool(sig) and ecdsa_ok(sighash_fn(find_and_delete(script, sig), sig[-1]), sig[:-1], pub)
            if op == OP["OP_CHECKSIGVERIFY"]:
                if not ok:
                    return False, f"CHECKSIGVERIFY @{pos}"
            else:
                stack.append(b"\x01" if ok else b"")
        elif op in (OP["OP_CHECKMULTISIG"], OP["OP_CHECKMULTISIGVERIFY"]):
            nk = num(stack.pop())
            keys = [stack.pop() for _ in range(nk)]          # top first
            ns = num(stack.pop())
            sigs = [stack.pop() for _ in range(ns)]          # top first
            dummy = stack.pop()
            if dummy:
                return False, "NULLDUMMY"
            sc = script
            for sg in sigs:
                sc = find_and_delete(sc, sg)
            ok, ik, is_ = True, 0, 0
            while ok and is_ < ns:
                sg, pk = sigs[is_], keys[ik]
                if sg and not is_valid_der(sg):
                    return False, f"non-DER sig in CMS @{pos}"
                good = bool(sg) and ecdsa_ok(sighash_fn(sc, sg[-1]), sg[:-1], pk)
                log(f"  CMS@{pos} sig#{is_} {sg.hex()} key#{ik} {pk[:5].hex()}.. -> {good}")
                if good:
                    is_ += 1
                ik += 1
                if ns - is_ > nk - ik:
                    ok = False
            if op == OP["OP_CHECKMULTISIGVERIFY"]:
                if not ok:
                    return False, f"CHECKMULTISIGVERIFY @{pos}"
            else:
                stack.append(b"\x01" if ok else b"")
        else:
            return False, f"unsupported opcode {op:#x} @{pos}"
    return bool(stack) and any(stack[-1]), "end"


def parse_script_sig(ss):
    out = []
    for pos in get_ops(ss):
        op = ss[pos]
        if op == 0:
            out.append(b"")
        elif op < 0x4C:
            out.append(ss[pos + 1:pos + 1 + op])
        elif op == 0x4C:
            out.append(ss[pos + 2:pos + 2 + ss[pos + 1]])
        elif 0x51 <= op <= 0x60:
            out.append(bytes([op - 0x50]))
        elif op == 0x4D:
            ln = int.from_bytes(ss[pos + 1:pos + 3], "little")
            out.append(ss[pos + 3:pos + 3 + ln])
    return out
