#!/usr/bin/env python3
"""Full QSB-with-nonce-pool locking script: generator, op/byte accounting, honest spend builder.

Layout (pushed once, bottom -> top, above the scriptSig items):
    C2[n] D2[n] C1[n] D1[n] POOL[k]
  C = HORS commitments HASH160(pre_i) (20 B), D = dummy sigs (9 B, SIGHASH_SINGLE, minimal push),
  POOL = nonce sigs (r=1, s=1..k, SIGHASH_ALL, PUSHDATA1 so FindAndDelete never removes them).
  Round 1's regions sit ABOVE round 2's; see the lower-bound safety note in QSB_IMPROVEMENTS.md.

Code:
  pinning  roll jp, MIN, PICK psig | PICK key, CHECKSIGVERIFY | ROLL key, H, OP_1 CHECKSIG DROP   (9 ops)
  round r  OP_0 | roll j, MIN, PICK nsig                                                          (3 ops)
           t x [roll x, MIN, DUP, ADD, ROLL C, roll pre, HASH160, EQUALVERIFY, ROLL D]             (9t ops)
           roll key, DUP, H, OP_1 CHECKSIG DROP | m SWAP | t x roll KD | n CHECKMULTISIG[VERIFY]  (5+1+t+1 ops, +t+1 keys)
  H is the puzzle hash opcode. The DER-only puzzle check `H OP_1 OP_CHECKSIG OP_DROP` needs no
  key_puzzle: a 1-byte pubkey makes CHECKSIG return false without failing, while strict DER
  (BIP66, consensus) still aborts on a non-DER hash.

test_mode=True replaces H with `OP_DROP <fixed 20-byte DER sig>` (same op count), so the rest of
the script can be spent end-to-end without solving the 2^46 puzzles.
"""
import argparse
import hashlib
import math
import random
import sys

from qsbcore import (G, N, OP, Z_SINGLE_BUG, add, der9, der_sig, enc, find_and_delete, hash160, inv,
                     is_valid_der, lift_x, mul, neg, push_min, push_nonmin, push_num, recover,
                     ser_tx, sighash_all)

TEST_DER20 = bytes.fromhex("3011020101020c") + bytes(range(1, 12)) + b"\x7f" + b"\x01"
assert len(TEST_DER20) == 20 and is_valid_der(TEST_DER20)
POOL_R = 1


class Builder:
    """Emits script bytes while tracking a symbolic stack, so every depth constant is derived, not hand-typed."""

    def __init__(self, witness_labels, hash_op, test_mode):
        self.stack = list(witness_labels)          # bottom -> top
        self.script = bytearray()
        self.ops = 0
        self.max_stack = len(self.stack)
        self.hash_op, self.test_mode = hash_op, test_mode

    def _op(self, name, count=1):
        self.script.append(OP[name])
        self.ops += count

    def _track(self):
        self.max_stack = max(self.max_stack, len(self.stack))

    def depth(self, label):
        return len(self.stack) - 1 - self.stack.index(label)

    def push(self, label, data, nonmin=False):
        self.script += push_nonmin(data) if nonmin else push_min(data)
        self.stack.append(label)
        self._track()

    def push_n(self, label, v):
        self.script += push_num(v)
        self.stack.append(label)
        self._track()

    def roll(self, label):
        self.script += push_num(self.depth(label))
        self._op("OP_ROLL")
        self.stack.remove(label)
        self.stack.append(label)

    def pick(self, label, new):
        self.script += push_num(self.depth(label))
        self._op("OP_PICK")
        self.stack.append(new)
        self._track()

    def min_(self, bound):
        self.script += push_num(bound)
        self._op("OP_MIN")

    def puzzle(self, key_label, m=1, lvl_label=None, cleanup=False, sign_lvl=None):
        """[.., key] -> [..]: some H-chain level must be strict DER (else abort).

        m == 1:  H OP_1 OP_CHECKSIG OP_DROP  (3 ops).
        m  > 1:  hash-chain OR. h1 = H(key), h_i = H(h_{i-1}) via OP_DUP H; the witness level index
                 (OP_MIN-clamped) OP_PICKs one h to DER-check. Extra ops 2m+1 (+ceil(m/2) cleanup).
        """
        def H():
            if self.test_mode:                      # stand-in: every level is the fixed DER string
                self._op("OP_DROP")
                self.script += push_min(TEST_DER20)
            else:
                self._op(self.hash_op)
        if m == 1:
            H()
            self.script += push_num(1)
            self._op("OP_CHECKSIG")
            self._op("OP_DROP")
            self.stack.pop()
            return
        H()
        self.stack[-1] = "h1"
        for i in range(2, m + 1):
            self._op("OP_DUP")
            self.stack.append(f"h{i}")
            H()
        self.roll(lvl_label)
        self.min_(m - 1)
        if sign_lvl:                                # Lamport-sign the level: open commitment CL_v
            cl0, pre_label = sign_lvl
            self._op("OP_DUP")
            self.stack.append("v_copy")
            off = self.depth(cl0) - 1               # depth of CL_0 once v_copy+off is popped by PICK
            self.script += push_num(off)
            self._op("OP_ADD")
            self._op("OP_PICK")
            self.stack.pop()
            self.stack.append("cl_sel")
            self.roll(pre_label)
            self._op("OP_HASH160")
            self._op("OP_EQUALVERIFY")
            self.stack.pop()
            self.stack.pop()
        self._op("OP_PICK")                         # witness value v picks h_{m-v}
        self.stack.pop()
        self.stack.append("hsel")
        self.script += push_num(1)
        self._op("OP_CHECKSIG")
        self._op("OP_DROP")
        self.stack.pop()
        if cleanup:
            left = m
            while left >= 2:
                self._op("OP_2DROP")
                del self.stack[-2:]
                left -= 2
            if left:
                self._op("OP_DROP")
                self.stack.pop()


def build(cfg, hash_op=None, test_mode=False, pad_ops=0, pad_bytes=0, real_round_puzzle=False):
    hash_op = hash_op or {"sha256": "OP_SHA256", "rmd": "OP_RIPEMD160", "sha1": "OP_SHA1"}[cfg.get("hash", "rmd")]
    n, k = cfg["n"], cfg["k"]
    ts = [cfg["t1"]] + ([cfg["t2"]] if "t2" in cfg else [])       # one or two digest rounds
    R = len(ts)
    bs = [cfg.get(f"b{i + 1}", 0) for i in range(R)]
    kbound = [cfg.get("k_pin", k)] + [cfg.get(f"k{i + 1}", k) for i in range(R)]
    chain_pin = cfg.get("chain_pin", 1)
    chains = [cfg.get(f"chain{i + 1}", cfg.get("chain_r", 1)) for i in range(R)]
    rng = random.Random(cfg.get("seed", 1))

    # ---- keys and constants
    on_curve_r = [x for x in range(2, 0x80) if lift_x(x, 0)]
    dummy_rs = [(rr, ss) for rr in on_curve_r for ss in range(1, 0x80)]
    rng.shuffle(dummy_rs)
    dummies = [[der9(rr, ss, 0x03) for rr, ss in dummy_rs[rd * n:(rd + 1) * n]] for rd in range(R)]
    pre = [[rng.randbytes(20) for _ in range(n)] for _ in range(R)]
    comm = [[hash160(p) for p in pre[rd]] for rd in range(R)]
    sign_j, sign_lvl = cfg.get("sign_j", False), cfg.get("sign_lvl", False)
    assert not (sign_j or sign_lvl) or cfg.get("pool_deep"), "signed j/level implemented for the pool-first layout"
    pre_j = [[rng.randbytes(20) for _ in range(cfg.get(f"k{rd + 1}", k))] for rd in range(R)]
    pre_l = [[rng.randbytes(20) for _ in range(16)] for rd in range(R)]
    pool = [der_sig(POOL_R, s, 0x01) for s in range(1, k + 1)]   # pool[s-1]; 10 bytes once s >= 128

    # ---- witness layout (bottom -> top): round 2 items, round 1 items, pinning items
    wit = []
    for rd in reversed(range(R)):
        wit += [f"KD{rd}_{i}" for i in range(ts[rd] + bs[rd])] + [f"key{rd}"]
        wit += [f"pre{rd}_{i}" for i in range(ts[rd])]
        wit += [f"x{rd}_{i}" for i in range(ts[rd] + bs[rd])] + [f"j{rd}"]
        if chains[rd] > 1:
            wit += [f"l{rd}"]
        if sign_j:
            wit += [f"prej{rd}"]
        if sign_lvl and chains[rd] > 1:
            wit += [f"prel{rd}"]
    wit += ["keyp", "jp"] + (["lp"] if chain_pin > 1 else [])

    b = Builder(wit, hash_op, test_mode)
    plan = {"pin": {}, "rounds": [{} for _ in range(R)]}
    if pad_bytes:
        b.push("pad", bytes(pad_bytes))
        b._op("OP_DROP")
        b.stack.pop()
    pool_deep = cfg.get("pool_deep", False)
    if pool_deep:            # pool first in the script: round sighashes then never rehash the pool bytes
        for s in range(k, 0, -1):
            b.push(f"P{s}", pool[s - 1], nonmin=True)
        for rd in range(R):  # signed pool index / chain level commitments (same orientation as the pool)
            if sign_j:
                for s_ in range(kbound[rd + 1], 0, -1):
                    b.push(f"CJ{rd}_{s_}", hash160(pre_j[rd][s_ - 1]))
            if sign_lvl and chains[rd] > 1:
                for v in range(chains[rd] - 1, -1, -1):
                    b.push(f"CL{rd}_{v}", hash160(pre_l[rd][v]))
    for rd in reversed(range(R)):
        for i in reversed(range(n)):
            b.push(f"C{rd}_{i}", comm[rd][i])
        for i in reversed(range(n)):
            b.push(f"D{rd}_{i}", dummies[rd][i])
    if not pool_deep:
        for s in range(k, 0, -1):                                 # s=1 ends on top
            b.push(f"P{s}", pool[s - 1], nonmin=True)

    # ---- pinning
    b.roll("jp")
    d1 = b.depth("P1") - 1                                        # depth of P1 once jp is popped
    plan["pin"]["P1"] = d1
    b.min_(d1 + kbound[0] - 1)
    b._op("OP_PICK")                                              # witness jp = d1 + (s-1)
    b.stack.pop()
    b.stack.append("psig")
    b.pick("keyp", "keyp_copy")
    b._op("OP_CHECKSIGVERIFY")
    b.stack.pop()
    b.stack.pop()
    b.roll("keyp")
    b.puzzle("keyp", m=chain_pin, lvl_label="lp")
    assert pool_deep or chain_pin > 1 or b.stack[-1] == "P1"

    # ---- rounds
    if real_round_puzzle:
        b.test_mode = False
    for rd in range(R):
        t = ts[rd]
        rp = plan["rounds"][rd]
        rp["bonus_options"] = []
        b.push_n(f"NULL{rd}", 0)
        b.roll(f"j{rd}")
        d1 = b.depth("P1") - 1
        rp["P1"] = d1
        b.min_(d1 + kbound[rd + 1] - 1)
        if sign_j:                          # open CJ_s: commitment sits a constant offset above P_s
            b._op("OP_DUP")
            b.stack.append("j_copy")
            # PICK runs with j still on the stack: CJ_s depth = (P_s depth w/o j) - delta + 1
            off = (b.depth("P1") - b.depth(f"CJ{rd}_1")) - 1
            b.script += push_num(off)
            b._op("OP_SUB")
            b._op("OP_PICK")
            b.stack.pop()
            b.stack.append("cj_sel")
            b.roll(f"prej{rd}")
            b._op("OP_HASH160")
            b._op("OP_EQUALVERIFY")
            b.stack.pop()
            b.stack.pop()
        b._op("OP_PICK")                                          # witness j = d1 + (s-1)
        b.stack.pop()
        b.stack.append(f"nsig{rd}")
        remaining = [f"D{rd}_{i}" for i in range(n)]              # region order, rel 0 = topmost
        rp["A"], rp["m"] = [], []
        for i in range(t):
            b.roll(f"x{rd}_{i}")
            top_region = remaining[0]
            A = b.depth(top_region) - 1                           # items above region, excluding x'
            m = len(remaining)
            b.min_(A + m - 1)
            b._op("OP_DUP")
            b.script += push_num(1 + m)
            b._op("OP_ADD")
            b._op("OP_ROLL")                                      # commitment -> top (reference: rel 0)
            cref = next(l for l in reversed(b.stack) if l.startswith(f"C{rd}_"))
            b.stack.remove(cref)
            b.stack.append("csel")
            b.roll(f"pre{rd}_{i}")
            b._op("OP_HASH160")
            b._op("OP_EQUALVERIFY")
            b.stack.pop()
            b.stack.pop()
            b._op("OP_ROLL")                                      # dummy -> top (reference: rel 0)
            b.stack.pop()
            b.stack.remove(remaining.pop(0))
            b.stack.append(f"dsel{rd}_{i}")
            rp["A"].append(A)
            rp["m"].append(m)
        rp.setdefault("bonus_options", [])
        for i in range(t, t + bs[rd]):
            # bonus key: selects a dummy with no HORS check. x' below the region reaches items
            # above it (pool sigs, earlier selections); those still verify, so count them as options.
            b.roll(f"x{rd}_{i}")
            A = b.depth(remaining[0]) - 1
            m = len(remaining)
            b.min_(A + m - 1)
            b._op("OP_ROLL")
            b.stack.pop()
            b.stack.remove(remaining.pop(0))
            b.stack.append(f"dsel{rd}_{i}")
            rp["A"].append(A)
            rp["m"].append(m)
            rp["bonus_options"].append(A + m - 1)          # depths 0..A+m-1 minus the NULL sig
        t = t + bs[rd]
        b.roll(f"key{rd}")
        if cfg.get("force_comp"):          # OP_SIZE 33 OP_EQUALVERIFY: only compressed keys (2 ops)
            b._op("OP_SIZE")
            b.script += push_num(33)
            b._op("OP_EQUALVERIFY")
        b._op("OP_DUP")
        b.stack.append(f"key{rd}_copy")
        b.puzzle(f"key{rd}_copy", m=chains[rd], lvl_label=f"l{rd}", cleanup=True,
                 sign_lvl=(f"CL{rd}_0", f"prel{rd}") if (sign_lvl and chains[rd] > 1) else None)
        b.push_n("m", t + 1)
        b._op("OP_SWAP")
        b.stack[-2:] = b.stack[-2:][::-1]
        for i in range(t):
            b.roll(f"KD{rd}_{i}")
        b.push_n("n", t + 1)
        b._op("OP_CHECKMULTISIGVERIFY" if rd < R - 1 else "OP_CHECKMULTISIG", count=1 + (t + 1))
        del b.stack[-(2 * t + 5):]
        if rd == R - 1:
            b.stack.append("TRUE")
    for _ in range(pad_ops):
        b.script.append(0x61)                                     # OP_NOP
        b.ops += 1
    assert not any(l.startswith(("x", "pre", "KD", "key", "j")) for l in b.stack), b.stack
    return dict(script=bytes(b.script), ops=b.ops, max_stack=b.max_stack, plan=plan, dummies=dummies,
                pre=pre, pool=pool, cfg=cfg, witness=wit, ts=ts, bs=bs, chain_pin=chain_pin, chains=chains,
                pre_j=pre_j, pre_l=pre_l)


def design_check(built):
    """One-time checks the script creator runs (needed when pool_deep lets a low j reach region items).

    A dummy picked as a nonce sig verifies under a FIXED key (SIGHASH_SINGLE bug, z = 2^248); the
    puzzle then hashes that fixed key, so no such key may hash to valid DER in any encoding. A
    commitment picked as a sig must not itself be valid DER. Each event has probability ~2^-45.
    """
    import hashlib as _h
    from qsbcore import ripemd160 as _r, recover_all
    H = {"sha256": lambda b: _h.sha256(b).digest(), "sha1": lambda b: _h.sha1(b).digest()}.get(built["cfg"].get("hash"), _r)
    bad = []
    for rd, ds in enumerate(built["dummies"]):
        for i, d in enumerate(ds):
            mmax = max([built["chain_pin"]] + built["chains"])
            for Q in recover_all(d[4], d[7], Z_SINGLE_BUG):       # includes x = r + n points when on-curve
                for kind in ("comp", "uncomp", "hybrid"):
                    h = H(enc(Q, kind))
                    for lvl in range(mmax):                        # every hash-chain level
                        if is_valid_der(h):
                            bad.append(("dummy", rd, i, kind, lvl + 1))
                        h = H(h)
    for rd, ps in enumerate(built["pre"] + built.get("pre_j", []) + built.get("pre_l", [])):
        for i, p_ in enumerate(ps):
            if is_valid_der(hash160(p_)):
                bad.append(("commitment", rd, i))
    return bad


# ---------------------------------------------------------------- honest spend (test mode or real hit)
def make_tx(seq=0xFFFFFFFE, locktime=0):
    rng = random.Random(99)
    ins = [(rng.randbytes(32), 0, b"", 0xFFFFFFFF), (rng.randbytes(32), 0, b"", seq)]
    outs = [(10000, bytes([0x76, 0xA9, 0x14]) + rng.randbytes(20) + bytes([0x88, 0xAC]))]
    return ins, outs, 1, locktime      # QSB input at index 1 >= #outputs: SIGHASH_SINGLE bug for dummies


def spend(built, choice, tx=None, tamper=None):
    """choice = {'jp':int, 'j':[j1,j2], 'subsets':[[abs ids in selection order], ...], 'odd':[..3], 'enc':[..3]}"""
    tamper = tamper or {}
    ins, outs, idx, lt = tx or make_tx()
    script, n = built["script"], built["cfg"]["n"]
    wit = {}
    # pinning
    s_p = choice["jp"] + 1 if choice["jp"] < built["cfg"].get("k_pin", built["cfg"]["k"]) else built["cfg"].get("k_pin", built["cfg"]["k"])
    z_p = sighash_all(ins, outs, idx, script, locktime=lt)
    wit["jp"] = built["plan"]["pin"]["P1"] + choice["jp"]
    lvls = choice.get("lvl", [1] * (1 + len(built["ts"])))
    if built["chain_pin"] > 1:
        wit["lp"] = built["chain_pin"] - lvls[0]
    wit["keyp"] = enc(recover(POOL_R, s_p, z_p, choice["odd"][0]), choice["enc"][0])
    zs = [z_p]
    for rd in range(len(built["ts"])):
        sub = choice["subsets"][rd]
        kb = built["cfg"].get(f"k{rd + 1}", built["cfg"]["k"])
        j = choice["j"][rd]
        s = max(0, min(j, kb))
        if rd >= 1 and choice.get("bonus_pool_s") and s >= choice["bonus_pool_s"]:
            s += 1          # round 1's bonus ROLLed that pool sig away; deeper sigs moved up by one
        pool_bonus = choice.get("bonus_pool_s") if rd == 0 else None
        deleted = sub[:-1] if pool_bonus else sub
        sc = script
        for a in deleted:
            sc = find_and_delete(sc, built["dummies"][rd][a])
        sc = find_and_delete(sc, built["pool"][s - 1])            # a no-op: PUSHDATA1 is never matched
        z = tamper.get(f"z{rd}", sighash_all(ins, outs, idx, sc, locktime=lt))
        zs.append(z)
        if built["chains"][rd] > 1:
            wit[f"l{rd}"] = tamper.get(f"l{rd}", built["chains"][rd] - lvls[rd + 1])
            if built["cfg"].get("sign_lvl"):
                wit[f"prel{rd}"] = tamper.get(f"prel{rd}", built["pre_l"][rd][built["chains"][rd] - lvls[rd + 1]])
        if built["cfg"].get("sign_j"):
            wit[f"prej{rd}"] = tamper.get(f"prej{rd}", built["pre_j"][rd][min(max(s, 1), kb) - 1])
        wit[f"j{rd}"] = tamper.get(f"j{rd}_abs", built["plan"]["rounds"][rd]["P1"] + (j - 1))   # j: 1-based s
        wit[f"key{rd}"] = tamper.get(f"key{rd}_raw", None) or enc(recover(POOL_R, s, z, choice["odd"][rd + 1]), choice["enc"][rd + 1])
        removed = []
        for i, a in enumerate(sub):
            rel = a - sum(1 for q in removed if q < a)
            wit[f"x{rd}_{i}"] = tamper.get(f"x{rd}_{i}", built["plan"]["rounds"][rd]["A"][i] + rel)
            if i < built["ts"][rd]:
                wit[f"pre{rd}_{i}"] = tamper.get(f"pre{rd}_{i}", built["pre"][rd][a])
            d = built["dummies"][rd][a]
            wit[f"KD{rd}_{i}"] = enc(recover(d[4], d[7], Z_SINGLE_BUG, 0))
            if pool_bonus and i == len(sub) - 1:
                t_signed = built["ts"][rd]
                wit[f"x{rd}_{i}"] = t_signed + 1 + pool_bonus        # above region: dsels, nsig, NULL, P1..
                wit[f"KD{rd}_{i}"] = enc(recover(POOL_R, pool_bonus, z, 0))
            removed.append(a)
    ss = b"".join(push_min(wit[l]) if isinstance(wit[l], bytes) else push_num(wit[l]) for l in built["witness"])
    ins2 = [(t_, v, (ss if i == idx else b""), q) for i, (t_, v, _, q) in enumerate(ins)]
    built["last_script_sig"] = ss
    return ser_tx(ins2, outs, lt), idx, zs


# ---------------------------------------------------------------- analysis
def p_der(L):
    """Exact probability that a uniform L-byte string passes IsValidSignatureEncoding."""
    f = lambda l: 0.5 if l == 1 else 0.5 - 1 / 512
    return sum(2.0 ** -48 * f(lr) * f(L - 7 - lr) for lr in range(1, L - 6))


def analyse(cfg, P_bits, built, enc_count=3):
    """Security in shots (one hash of one recovered-key encoding) and honest expected shots.

    S_i  = attacker's free choices per pinned tx in round i: 2 recids x enc_count encodings x pool
           bound x every bonus option (exact, from the script plan, including off-region picks).
    E_i  = honest expected solutions per pinned tx (legit bonus dummies only, conservative).
    """
    R = len(built["ts"])
    S, E = [], []
    for i in range(1, R + 1):
        rp = built["plan"]["rounds"][i - 1]
        kk, mm = cfg.get(f"k{i}", cfg["k"]), cfg.get(f"chain{i}", cfg.get("chain_r", 1))
        base = 2 * kk * (1 if cfg.get("force_comp") else enc_count) * mm       # honest freedom per subset
        # Unsigned pool index: the nonce PICK also reaches every item above the pool. The pinning
        # chain's levels stay on the stack (no cleanup), and the pinning hit among them is a valid DER
        # signature, so it is one more nonce option (found by the challenge judge's freedom audit).
        # Count all chain_pin levels (conservative; only DER-valid ones can work).
        extra = cfg.get("chain_pin", 1) if cfg.get("chain_pin", 1) > 1 else 0
        att = (2 * (1 if cfg.get("force_comp") else enc_count) * (1 if cfg.get("sign_j") else kk + extra)
               * (1 if cfg.get("sign_lvl") else mm))
        S.append(att * math.prod(rp["bonus_options"]))
        t, bn = cfg[f"t{i}"], cfg.get(f"b{i}", 0)
        E.append(math.comb(cfg["n"], t) * math.comb(cfg["n"] - t, bn) * base * 2.0 ** -P_bits)
    p = [1 - math.exp(-e) for e in E]
    # per pinned attempt: pinning 2^P, then round i (expected 2^P p_i shots) reached with prob prod p_<i
    attempt = 1 + sum(math.prod(p[:i + 1]) for i in range(R))
    honest = 2.0 ** P_bits * attempt / math.prod(p)
    pre = P_bits + sum(P_bits - math.log2(Si) for Si in S)
    # Collision (malicious spender): enumerate every round fully per pinned tx and collect every
    # passing signed digest. Cost per pinned tx ~ 2^P (1 + E1 + E1 E2 + ...); digests per pinned tx
    # ~ prod E_i * relabelings (which of the t+b passing selections are called "signed").
    relabel = math.prod(math.comb(cfg[f"t{i}"] + cfg.get(f"b{i}", 0), cfg[f"t{i}"]) for i in range(1, R + 1))
    signed_bits = sum(math.log2(math.comb(cfg["n"], cfg[f"t{i}"])) for i in range(1, R + 1))
    per_digest = 2.0 ** P_bits * (1 + sum(math.prod(E[:i + 1]) for i in range(R))) / (math.prod(E) * relabel)
    coll_birthday = math.log2(per_digest) + signed_bits / 2
    # Fixed-digest strategy (SECURITY_PROOF.md, Theorem 3): pin N = q p txs, test every one against the
    # same digest's full round blocks. E[collisions] ~ q^2 p prod(S_i p)^2 / (2 sum S_i), so
    # log2 q* = (P + 2 sum(P - log S_i) + log sum S_i + 1) / 2.
    coll_fixed = (P_bits + 2 * sum(P_bits - math.log2(Si) for Si in S) + math.log2(sum(S)) + 1) / 2
    coll = min(coll_birthday, coll_fixed)
    S_pin = 2 * cfg.get("k_pin", cfg["k"]) * enc_count * cfg.get("chain_pin", 1)
    quantum = (P_bits + sum(P_bits - math.log2(Si) for Si in S) - math.log2(S_pin)) / 2 - 1.5   # Theorem 2
    return dict(S=S, E=E, p=p, honest_shots_log2=math.log2(honest), preimage_bits=pre, collision_bits=coll,
                collision_birthday=coll_birthday, collision_fixed=coll_fixed, quantum_query_bits=quantum)


def config_a_reference(P_bits):
    """Paper Config A (n=150, 8+1b / 7+2b), recounted with the same model: 2 recids x 3 encodings per
    sighash, and the deployed CHECKSIGVERIFY puzzle, which also needs r to be an x-coordinate (+1 bit)."""
    P_eff = P_bits + 1
    S1, S2 = 6 * 142, 6 * math.comb(143, 2)
    pre = P_eff + (P_eff - math.log2(S1)) + (P_eff - math.log2(S2))
    return pre, math.log2(3) + P_eff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors", action="store_true", help="emit end-to-end consensus vectors")
    ap.add_argument("--report", action="store_true", help="print config/security table")
    a = ap.parse_args()

    if a.report:
        print(f"P(strict DER) 20B = 2^{math.log2(p_der(20)):.3f}   32B = 2^{math.log2(p_der(32)):.3f}")
        print("with an on-curve requirement on r (CHECKSIGVERIFY puzzle) each is ~1 bit harder\n")
        for hname, P_bits in (("RIPEMD", math.log2(1 / p_der(20))), ("SHA256", math.log2(1 / p_der(32)))):
            pre, hon = config_a_reference(P_bits)
            print(f"reference: paper Config A, {hname}, recounted: honest 2^{hon:.2f} shots, pre-image {pre:.1f} bits")
        print()
        print(f"{'config':34} {'ops':>4} {'bytes':>6} {'stack':>5} {'E1':>6} {'E2':>6} {'p1p2':>5} "
              f"{'honest':>7} {'pre-img':>7} {'collis':>6} {'Q-qry':>6}")
        for name, cfg in CONFIGS.items():
            bt = build(cfg)
            for hname, P_bits in (("RIPEMD", math.log2(1 / p_der(20))), ("SHA256", math.log2(1 / p_der(32)))):
                r = analyse(cfg, P_bits, bt)
                flag = " (OVER 10,000 B: invalid)" if len(bt["script"]) > 10000 or bt["ops"] > 201 else ""
                print(f"{name + ' ' + hname + flag:34} {bt['ops']:4d} {len(bt['script']):6d} {bt['max_stack']:5d} "
                      f"{r['E'][0]:6.1f} {(r['E'][1] if len(r['E']) > 1 else float('nan')):6.2f} {math.prod(r['p']):5.2f} "
                      f"2^{r['honest_shots_log2']:5.2f} {r['preimage_bits']:7.1f} {r['collision_bits']:6.1f} {r['quantum_query_bits']:6.1f}")
    if a.vectors:
        emit_vectors()


CONFIGS = {
    "2-STAGE TS2 n150 t16 kpin300 k1=64 comp deep": dict(n=150, t1=16, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256"),
    "2-STAGE TS2 n150 t16 kpin300 k1=32 comp deep": dict(n=150, t1=16, k=300, k1=32, force_comp=True, pool_deep=True, hash="sha256"),
    "2-STAGE n250 t16 k127 (k1=8)":  dict(n=250, t1=16, k=127, k1=8),
    "2-STAGE n250 t16 k127 (k1=24)": dict(n=250, t1=16, k=127, k1=24),
    "n140 t7+1b/8 k24":        dict(n=140, t1=7, b1=1, t2=8, k=24),
    "n145 t7+1b/8 k16":        dict(n=145, t1=7, b1=1, t2=8, k=16),
    "n148 t7+1b/8 k12":        dict(n=148, t1=7, b1=1, t2=8, k=12),
    "n140 t8/7 k64":           dict(n=140, t1=8, t2=7, k=64),
    "n145 t8/7 k40":           dict(n=145, t1=8, t2=7, k=40),
    "n150 t8/7 k24":           dict(n=150, t1=8, t2=7, k=24),
    "n136 t8/7 k96 (k1=16)":   dict(n=136, t1=8, t2=7, k=96, k1=16),
    "n130 t8/7 k127 (k1=8)":   dict(n=130, t1=8, t2=7, k=127, k1=8),
}


def emit_vectors():
    out = []
    rng = random.Random(3)
    for tag, cfg in (("NB", dict(n=140, t1=8, t2=7, k=64, seed=5)),
                     ("BK", dict(n=148, t1=7, b1=1, t2=8, k=12, seed=6)),
                     ("TS", dict(n=250, t1=16, k=127, k1=8, seed=7)),
                     ("TS2", dict(n=150, t1=16, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256", seed=8)),
                     ("TS3", dict(n=150, t1=12, k=300, k1=16, force_comp=True, pool_deep=True, hash="sha256",
                                  chain_pin=8, chain_r=8, seed=9)),
                     ("TS4", dict(n=120, t1=8, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256",
                                  chain_pin=16, chain_r=16, sign_j=True, sign_lvl=True, seed=10))):
        out += vectors_for(tag, cfg, rng)
    print("\n".join(out))


def vectors_for(tag, cfg, rng):
    out = []
    R = 2 if "t2" in cfg else 1
    T = [cfg[f"t{i}"] + cfg.get(f"b{i}", 0) for i in range(1, R + 1)]
    last = R - 1

    def e(name, built, choice, ok, **kw):
        tx, idx, _ = spend(built, choice, **kw)
        out.append(f"{tag}_{name} {built['script'].hex()} {tx.hex()} {idx} {1 if ok else 0}")

    def rand_choice():
        return dict(jp=rng.randrange(cfg["k"]), j=[rng.randrange(1, cfg.get(f"k{i + 1}", cfg["k"]) + 1) for i in range(R)],
                    subsets=[rng.sample(range(cfg["n"]), T[i]) for i in range(R)],
                    odd=[rng.randrange(2) for _ in range(R + 1)],
                    lvl=[rng.randrange(1, cfg.get("chain_pin", 1) + 1)] +
                        [rng.randrange(1, cfg.get(f"chain{i + 1}", cfg.get("chain_r", 1)) + 1) for i in range(R)],
                    enc=[rng.choice(["comp", "uncomp", "hybrid"])] +
                        [("comp" if cfg.get("force_comp") else rng.choice(["comp", "uncomp", "hybrid"])) for _ in range(R)])

    tb = build(cfg, test_mode=True)
    prod = build(cfg, test_mode=False)
    sys.stderr.write(f"[{tag}] {cfg}: ops={tb['ops']} production bytes={len(prod['script'])} "
                     f"test-mode bytes={len(tb['script'])} max stack={tb['max_stack']}\n")
    for i in range(6):
        e(f"honest_spend_{i}", tb, rand_choice(), True)
    edge = rand_choice()
    edge["subsets"] = [list(range(cfg["n"]))[-T[0]:]] + ([list(range(T[1]))] if R > 1 else [])
    e("edge_subsets_last_and_first_ids", tb, edge, True)
    c = rand_choice()
    _, _, z_a = spend(tb, c)
    c2 = dict(c, subsets=[c["subsets"][i][:cfg[f"t{i + 1}"]][::-1] + c["subsets"][i][cfg[f"t{i + 1}"]:]
                          for i in range(R)])
    _, _, z_b = spend(tb, c2)
    assert z_a == z_b, "selection order must not change the round sighash"
    e("signed_selection_order_reversed", tb, c2, True)
    c = rand_choice()
    c["j"], c["jp"] = [10 ** 6] * R, 10 ** 6
    e("j_huge_is_clamped_to_pool_bound", tb, c, True)
    c = rand_choice()
    c["j"] = [0] + c["j"][1:]
    e("neg_j0_picks_NULL_sig", tb, c, False)
    e("neg_wrong_hors_preimage", tb, rand_choice(), False, tamper={"pre0_3": bytes(20)})
    A1, m1 = tb["plan"]["rounds"][last]["A"], tb["plan"]["rounds"][last]["m"]
    e("neg_x_below_region", tb, rand_choice(), False, tamper={f"x{last}_0": A1[0] - 1})
    e("neg_x_below_region_deep", tb, rand_choice(), False, tamper={f"x{last}_2": A1[2] - m1[2] - 3})
    e("neg_nonce_key_for_z_without_deletion", tb, rand_choice(), False,
      tamper={"z0": sighash_all(*make_tx()[:2], 1, tb["script"])})
    c = rand_choice()
    c["subsets"] = [c["subsets"][0][:cfg["t1"] - 1] + [c["subsets"][0][0]] + c["subsets"][0][cfg["t1"]:]] + c["subsets"][1:]
    e("neg_repeated_dummy_in_round", tb, c, False)
    e("neg_production_script_nonhit_aborts", prod, rand_choice(), False)
    if cfg.get("sign_j"):
        c = rand_choice(); s_ = min(c["j"][0], cfg["k1"]); other = s_ % cfg["k1"] + 1
        e("neg_signed_j_preimage_for_other_index", tb, c, False, tamper={"prej0": tb["pre_j"][0][other - 1]})
    m1 = cfg.get("chain1", cfg.get("chain_r", 1))
    if cfg.get("sign_lvl") and m1 > 1:
        c = rand_choice(); v = m1 - c["lvl"][1]
        e("neg_signed_level_preimage_for_other_level", tb, c, False,
          tamper={"prel0": tb["pre_l"][0][(v + 1) % m1]})
    if m1 > 1 and not cfg.get("sign_lvl"):
        e("chain_level_huge_is_clamped", tb, rand_choice(), True, tamper={"l0": 10 ** 6})
        e("neg_chain_level_negative", tb, rand_choice(), False, tamper={"l0": -1})
    if cfg.get("force_comp"):
        c = rand_choice(); c["enc"] = [c["enc"][0]] + ["uncomp"] * R
        e("neg_round_key_uncompressed_rejected_by_OP_SIZE", tb, c, False)
        c = rand_choice(); c["enc"] = [c["enc"][0]] + ["comp"] * R
        e("round_key_compressed_ok", tb, c, True)
    if cfg.get("pool_deep"):
        bad = design_check(tb)
        sys.stderr.write(f"[{tag}] designer check: {len(bad)} unsafe region items\n")
        assert not bad
        # j one above the pool reaches a region item (commitment): as a signature it is not DER -> abort
        c = rand_choice(); c["j"] = [0] + c["j"][1:]
        e("neg_deep_j_reaches_commitment", tb, c, False)
        # j reaching a SINGLE-bug dummy: its key is fixed and (designer check) its hash is not DER.
        # Tested with the real round puzzle (pinning keeps the stand-in so the round is reached).
        rr = build(cfg, test_mode=True, real_round_puzzle=True)
        c = rand_choice()
        rp0 = rr["plan"]["rounds"][0]
        n_ = cfg["n"]
        # region order above the pool (bottom->top): C_{R-1}.., D_{R-1}.., ..., C_0, D_0; for R=1: C_0 (n), D_0 (n)
        d_dummy = rp0["P1"] - n_ - 1                    # depth of the deepest dummy D0_{n-1}
        dsig = rr["dummies"][0][n_ - 1]
        kd = enc(recover(dsig[4], dsig[7], Z_SINGLE_BUG, 0))
        c2 = dict(c)
        tx2, idx2, _ = spend(rr, c2, tamper={"j0_abs": d_dummy, "key0_raw": kd})
        out.append(f"{tag}_neg_deep_j_reaches_dummy_fixed_key_not_DER {rr['script'].hex()} {tx2.hex()} {idx2} 0")
    if cfg.get("b1") and not cfg.get("pool_deep"):
        # Attacker view: a bonus index below the region reaches a pool sig. It is never deleted
        # (PUSHDATA1) and verifies under a key anyone can recover, so the spend is VALID. This is
        # why analyse() counts A+m-1 bonus options instead of n-t.
        for s_ in (1, cfg["k"]):
            c = rand_choice()
            if R > 1: c["j"][1] = rng.randrange(1, cfg["k"])
            c["bonus_pool_s"] = s_
            e(f"attacker_bonus_points_at_pool_sig_s{s_}", tb, c, True)
    if tb["ops"] < 201:
        e("ops_padded_to_201", build(cfg, test_mode=True, pad_ops=201 - tb["ops"]), rand_choice(), True)
    e("ops_padded_to_202", build(cfg, test_mode=True, pad_ops=202 - tb["ops"]), rand_choice(), False)
    if tb["ops"] < 201 and len(tb["script"]) > 10000 - 500:     # single <=520-byte pad element reaches the limit
        def padded_to(target):   # the pad's push header grows at 76/256 bytes, so search for the exact size
            for pb in range(1, 521):
                bt = build(cfg, test_mode=True, pad_bytes=pb)
                if len(bt["script"]) == target:
                    return bt
            return None          # a single pad push jumps over this exact size (push-header growth)
        p0, p1 = padded_to(10000), padded_to(10001)
        if p0 and p1:
            e("size_padded_to_10000", p0, rand_choice(), True)
            e("size_padded_to_10001", p1, rand_choice(), False)
    return out


if __name__ == "__main__":
    main()
