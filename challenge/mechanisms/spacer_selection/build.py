#!/usr/bin/env python3
"""Standalone spacer-selector prototype, adapted from frozen qsb_pool.build.

No trusted source is modified. Each region is independent. Zero sentinels bound
all index picks, and zero spacers make the two ROLL indices identical.
"""
from contextlib import contextmanager
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'challenge')]
import qsb_pool as q
import importlib.util
_spec = importlib.util.spec_from_file_location("spacer_destructive", HERE.parent/'destructive_chain/build.py')
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
DestructiveBuilder = _module.DestructiveBuilder
from qsbcore import (OP, der9, der_sig, hash160, lift_x, push_num)
POOL_R = q.POOL_R
REFERENCE_SPEND = q.spend

def build(cfg, hash_op=None, test_mode=False, pad_ops=0, pad_bytes=0, real_round_puzzle=False):
    hash_op = hash_op or {"sha256": "OP_SHA256", "rmd": "OP_RIPEMD160", "sha1": "OP_SHA1"}[cfg.get("hash", "rmd")]
    assert cfg.get("pool_deep"), "prototype requires pool-first layout"
    assert not cfg.get("b1", 0) and not cfg.get("b2", 0), "bonus selections unsupported"
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

    builder = DestructiveBuilder if cfg.get("destructive_chain", False) else q.Builder
    b = builder(wit, hash_op, test_mode)
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
        # Permanent boundary: all selected pairs lie above this marker.
        b.push_n(f"Z{rd}", 0)
        for i in reversed(range(n)):
            b.push(f"D{rd}_{i}", dummies[rd][i])
            b.push_n(f"F{rd}_{i}", 0)
            b.push(f"C{rd}_{i}", comm[rd][i])
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
        rp["index_base"], rp["max_depth"] = [], []
        for i in range(t):
            b.roll(f"x{rd}_{i}")
            top_region = remaining[0]
            A = b.depth(top_region) - 1                           # items above region, excluding x'
            m = len(remaining)
            # The symbolic reference removes positions 0,1,...; real choices
            # use base + 3*a - 2*(previously removed positions below a).
            rp["index_base"].append(b.depth(f"C{rd}_{i}") - i)
            rp["max_depth"].append(b.depth(f"Z{rd}") - 1)
            b.min_(rp["max_depth"][-1])
            b._op("OP_DUP")
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


def spend(built, choice, tx=None, tamper=None):
    adjusted = {}
    for rd, subset in enumerate(choice['subsets']):
        removed = []
        for i, a in enumerate(subset):
            base = built['plan']['rounds'][rd]['index_base'][i]
            adjusted[f'x{rd}_{i}'] = base + 3*a - 2*sum(x < a for x in removed)
            removed.append(a)
    adjusted.update(tamper or {})
    return REFERENCE_SPEND(built, choice, tx=tx, tamper=adjusted)


@contextmanager
def prototype_spender():
    original = q.spend
    q.spend = spend
    try:
        yield
    finally:
        q.spend = original
