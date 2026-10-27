"""Attacker-model interpreter for legacy script, with provenance tracking (judge component, frozen).

Two signature modes:
  * oracle="attacker": every DER-valid non-empty signature verifies under any 33/65-byte key. Keys
    are free for the attacker (A3: discrete logs are free), so this over-approximates what an
    attacker can make pass. The judge only uses it to *count* choices; fixed-key signatures (the
    SIGHASH_SINGLE dummies) are tagged so the audit can apply design_check().
  * oracle=callable(sig, pubkey, script_code) -> bool: real verification (the judge passes secp256k1
    ECDSA over the real sighash), used to cross-check this interpreter against Bitcoin Core.

Each stack item is (bytes, prov). prov is ("push", pos) for script pushes, ("wit", i) for scriptSig
items and ("op", pos) for computed items. OP_PICK / OP_DUP copies keep the source's prov, so the
audit can tell which script push (pool signature, dummy, chain level) a value came from.
Consensus rules modelled (Bitcoin Core, legacy, BIP66 + BIP147): 201-op limit (CHECKMULTISIG adds
nKeys), 520-byte pushes, 1000-item stack, 4-byte CScriptNum operands, strict DER on checked
signatures, NULLDUMMY, lazy CHECKMULTISIG loop order, FindAndDelete of every signature in the call.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from qsbcore import get_ops, is_valid_der, push_min, ripemd160  # noqa: E402

_OPS_CACHE, _FAD_CACHE = {}, {}


def ops_of(script):
    v = _OPS_CACHE.get(script)
    if v is None:
        v = _OPS_CACHE[script] = get_ops(script)
    return v


def find_and_delete(script, sig):
    """Core's FindAndDelete(scriptCode, CScript() << sig), linear time and memoised. Equivalent to
    qsbcore.find_and_delete (tests/test_judge.py checks this on random and adversarial inputs)."""
    key = (script, sig)
    v = _FAD_CACHE.get(key)
    if v is not None:
        return v
    pat = push_min(sig)
    bounds = ops_of(script)
    out, i, bi, L = bytearray(), 0, 0, len(script)
    while i < L:
        while script[i:i + len(pat)] == pat:
            i += len(pat)
        if i >= L:
            break
        while bi < len(bounds) and bounds[bi] <= i:
            bi += 1
        nxt = bounds[bi] if bi < len(bounds) else L
        out += script[i:nxt]
        i = nxt
    v = bytes(out)
    if len(_FAD_CACHE) > 200000:
        _FAD_CACHE.clear()
    _FAD_CACHE[key] = v
    return v

OPS = {0x75: "DROP", 0x6D: "2DROP", 0x76: "DUP", 0x7C: "SWAP", 0x79: "PICK", 0x7A: "ROLL", 0x82: "SIZE",
       0x88: "EQUALVERIFY", 0x87: "EQUAL", 0x93: "ADD", 0x94: "SUB", 0xA3: "MIN", 0x61: "NOP", 0x69: "VERIFY",
       0xA6: "RIPEMD160", 0xA7: "SHA1", 0xA8: "SHA256", 0xA9: "HASH160", 0xAA: "HASH256",
       0xAC: "CHECKSIG", 0xAD: "CHECKSIGVERIFY", 0xAE: "CHECKMULTISIG", 0xAF: "CHECKMULTISIGVERIFY"}


class Fail(Exception):
    pass


def num(b):
    if len(b) > 4:
        raise Fail("numeric operand > 4 bytes")
    if not b:
        return 0
    v = int.from_bytes(b, "little")
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


def enc_num(v):
    if v == 0:
        return b""
    neg, a, out = v < 0, abs(v), bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def truthy(b):
    for i, x in enumerate(b):
        if x:
            return not (i == len(b) - 1 and x == 0x80)
    return False


def run(script, witness, oracle="attacker"):
    """witness: list of bytes (bottom -> top). Returns dict(ok, reason, events, final)."""
    st = [(w, ("wit", i)) for i, w in enumerate(witness)]
    ev, nops = [], 0

    def pop():
        if not st:
            raise Fail("stack underflow")
        return st.pop()

    def verify_sig(sig, key, sc):
        if not sig:
            return False
        if not is_valid_der(sig):
            raise Fail("non-DER signature")                        # BIP66: consensus abort
        if len(key) not in (33, 65):
            return False                                           # unparsable pubkey: false, no abort
        if oracle == "attacker":
            return True
        return oracle(sig, key, sc)

    try:
        for pos in ops_of(script):
            op = script[pos]
            if op <= 0x4E:
                if op == 0:
                    d = b""
                elif op < 0x4C:
                    d = script[pos + 1:pos + 1 + op]
                elif op == 0x4C:
                    d = script[pos + 2:pos + 2 + script[pos + 1]]
                else:
                    d = script[pos + 3:pos + 3 + int.from_bytes(script[pos + 1:pos + 3], "little")]
                if len(d) > 520:
                    raise Fail("push > 520")
                st.append((d, ("push", pos)))
            elif 0x51 <= op <= 0x60:
                st.append((bytes([op - 0x50]), ("push", pos)))
            else:
                nops += 1
                name = OPS.get(op)
                if name is None:
                    raise Fail(f"opcode {op:#x} outside the judge's model")
                if name == "NOP":
                    pass
                elif name in ("PICK", "ROLL"):
                    n_ = num(pop()[0])
                    if n_ < 0 or n_ >= len(st):
                        raise Fail(f"{name} out of range")
                    it = st[-1 - n_]
                    if name == "ROLL":
                        del st[-1 - n_]
                    st.append(it)
                    ev.append((name, pos, n_, it[1]))
                elif name == "MIN":
                    b_, a_ = num(pop()[0]), num(pop()[0])
                    st.append((enc_num(min(a_, b_)), ("op", pos)))
                elif name in ("ADD", "SUB"):
                    b_, a_ = num(pop()[0]), num(pop()[0])
                    st.append((enc_num(a_ + b_ if name == "ADD" else a_ - b_), ("op", pos)))
                elif name == "DUP":
                    st.append(st[-1] if st else pop())
                elif name == "DROP":
                    pop()
                elif name == "2DROP":
                    pop(); pop()
                elif name == "SWAP":
                    if len(st) < 2:
                        raise Fail("stack underflow")
                    st[-1], st[-2] = st[-2], st[-1]
                elif name == "SIZE":
                    if not st:
                        raise Fail("stack underflow")
                    st.append((enc_num(len(st[-1][0])), ("op", pos)))
                elif name in ("EQUAL", "EQUALVERIFY"):
                    a1, a2 = pop(), pop()
                    ev.append(("EQ", pos, a2[1], a1[1], a1[0] == a2[0]))
                    if name == "EQUALVERIFY":
                        if a1[0] != a2[0]:
                            raise Fail("EQUALVERIFY")
                    else:
                        st.append((b"\x01" if a1[0] == a2[0] else b"", ("op", pos)))
                elif name == "VERIFY":
                    if not truthy(pop()[0]):
                        raise Fail("VERIFY")
                elif name in ("RIPEMD160", "SHA1", "SHA256", "HASH160", "HASH256"):
                    x, pv = pop()
                    h = {"RIPEMD160": ripemd160, "SHA1": lambda b: hashlib.sha1(b).digest(),
                         "SHA256": lambda b: hashlib.sha256(b).digest(),
                         "HASH160": lambda b: ripemd160(hashlib.sha256(b).digest()),
                         "HASH256": lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()}[name](x)
                    st.append((h, ("op", pos)))
                    ev.append(("HASH", pos, name, pv))
                elif name in ("CHECKSIG", "CHECKSIGVERIFY"):
                    key, sig = pop(), pop()
                    sc = find_and_delete(script, sig[0]) if sig[0] else script
                    ok = verify_sig(sig[0], key[0], sc)
                    ev.append(("CHECKSIG", pos, sig, key, ok, sc))
                    if name == "CHECKSIGVERIFY":
                        if not ok:
                            raise Fail("CHECKSIGVERIFY")
                    else:
                        st.append((b"\x01" if ok else b"", ("op", pos)))
                elif name in ("CHECKMULTISIG", "CHECKMULTISIGVERIFY"):
                    nk = num(pop()[0])
                    if nk < 0 or nk > 20:
                        raise Fail("CHECKMULTISIG key count")
                    nops += nk
                    if nops > 201:
                        raise Fail("op count > 201")
                    keys = [pop() for _ in range(nk)]
                    ns = num(pop()[0])
                    if ns < 0 or ns > nk:
                        raise Fail("CHECKMULTISIG sig count")
                    sigs = [pop() for _ in range(ns)]
                    dummy = pop()
                    sc = script
                    for sg in sigs:
                        sc = find_and_delete(sc, sg[0])
                    ok, ik, is_ = True, 0, 0
                    while ok and is_ < ns:
                        good = verify_sig(sigs[is_][0], keys[ik][0], sc)
                        if good:
                            is_ += 1
                        ik += 1
                        if ns - is_ > nk - ik:
                            ok = False
                    if dummy[0]:
                        raise Fail("NULLDUMMY")
                    ev.append(("CMS", pos, sigs, keys, ok, sc))
                    if name == "CHECKMULTISIGVERIFY":
                        if not ok:
                            raise Fail("CHECKMULTISIGVERIFY")
                    else:
                        st.append((b"\x01" if ok else b"", ("op", pos)))
                if nops > 201:
                    raise Fail("op count > 201")
            if len(st) > 1000:
                raise Fail("stack > 1000")
    except Fail as e:
        return dict(ok=False, reason=str(e), events=ev, final=st)
    ok = bool(st) and truthy(st[-1][0])
    return dict(ok=ok, reason="end" if ok else "false on top", events=ev, final=st)
