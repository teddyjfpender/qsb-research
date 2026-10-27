#!/usr/bin/env python3
"""Mechanism prototype: consume the selected hash with ROLL instead of PICK.

Runs outside the frozen judge. No trusted source file is modified. Only round
chains (which discard all remaining levels) change; pinning stays unchanged.
"""
import argparse
from contextlib import contextmanager
import json
import math
from pathlib import Path
import random
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'challenge')]
import qsb_pool as q
from qsbcore import OP
from judge import checks, cost

REFERENCE_BUILDER = q.Builder


class DestructiveBuilder(REFERENCE_BUILDER):
    def puzzle(self, key_label, m=1, lvl_label=None, cleanup=False, sign_lvl=None):
        if not cleanup or m == 1:
            return super().puzzle(key_label, m, lvl_label, cleanup, sign_lvl)
        # Emit the original chain, bounds check, optional level authentication,
        # and DER check. Replace only its final level selector.
        super().puzzle(key_label, m, lvl_label, False, sign_lvl)
        expected = bytes([OP['OP_PICK'], 0x51, OP['OP_CHECKSIG'], OP['OP_DROP']])
        assert bytes(self.script[-4:]) == expected
        self.script[-4] = OP['OP_ROLL']
        # The symbolic builder uses level-index zero as its reference. Every
        # runtime level leaves m-1 items, all of which are discarded below.
        self.stack.pop()
        left = m - 1
        while left >= 2:
            self._op('OP_2DROP')
            del self.stack[-2:]
            left -= 2
        if left:
            self._op('OP_DROP')
            self.stack.pop()


@contextmanager
def prototype_builder():
    original = q.Builder
    q.Builder = DestructiveBuilder
    try:
        yield
    finally:
        q.Builder = original


def build(cfg, **kwargs):
    with prototype_builder():
        return q.build(cfg, **kwargs)


def evaluate(cfg):
    prod = build(cfg)
    test = build(cfg, test_mode=True)
    ops, errors = checks.limits(prod['script'])
    _, test_errors = checks.limits(test['script'])
    count, twin_error = checks.twin(prod['script'], test['script'])
    P = math.log2(1/q.p_der(32 if cfg['hash'] == 'sha256' else 20))
    a = q.analyse(cfg, P, prod)
    assert not cfg.get('b1', 0) and not cfg.get('b2', 0), 'bonus E overcount excluded'
    hours, rates = cost.gpu_hours(cfg, prod, a, P, cost.load_table())
    return dict(cfg=cfg, ops=ops, bytes=len(prod['script']), test_bytes=len(test['script']),
                static_errors=errors+test_errors, twin_error=twin_error,
                substitutions=count, security=a, estimated_gpu_hours=hours, rates=rates,
                confidence='proposal; not ranked; no new GPU measurement')


def test_all():
    lines = []
    # Exercise every level, all chain lengths, signed and unsigned levels,
    # plus existing honest/tamper vector families. Small n permits long chains
    # in these gadget tests; no security level is claimed for the small tests.
    for signed in (False, True):
        for m in range(2, 17):
            cfg = dict(hash='sha256', n=32, k=8, t1=4, k1=8, chain_pin=1,
                       chain1=m, pool_deep=True, force_comp=True,
                       sign_j=signed, sign_lvl=signed)
            old = q.build(cfg)
            new = build(cfg)
            assert old['ops'] - new['ops'] == m % 2
            assert len(old['script']) - len(new['script']) == m % 2
            assert old['plan'] == new['plan']
            tb = build(cfg, test_mode=True)
            for level in range(1, m+1):
                ch = dict(jp=0, j=[1], subsets=[[0, 5, 16, 31]], odd=[0, 1],
                          enc=['uncomp', 'comp'], lvl=[1, level])
                tx, idx, _ = q.spend(tb, ch)
                lines.append(f'roll_{signed}_{m}_{level} {tb["script"].hex()} {tx.hex()} {idx} 1')
            with prototype_builder():
                lines.extend(q.vectors_for(f'ROLL_{signed}_{m}', cfg, random.Random(1000+m)))
    results = []
    for name, k, n, k1, k2 in [('D', 96, 134, 96, 96), ('E', 64, 139, 48, 64)]:
        cfg = dict(hash='sha256', n=n, k=k, t1=7, t2=7, k1=k1, k2=k2,
                   chain_pin=1, chain1=3, chain2=3, pool_deep=True,
                   force_comp=False, sign_j=False, sign_lvl=False)
        result = evaluate(cfg)
        assert not result['static_errors'] and not result['twin_error'], result
        result['name'] = name
        result['design_check'] = q.design_check(build(cfg))
        results.append(result)
        with prototype_builder():
            lines.extend(q.vectors_for(f'ROLL_TIER_{name}', cfg, random.Random(2026)))
    payload = '\n'.join(lines)+'\n'
    c = subprocess.run([str(ROOT/'consensus_check/target/release/cchk')],
                       input=payload, capture_output=True, text=True, check=True)
    assert c.stdout.count('PASS') == len(lines), c.stdout
    assert c.stdout.splitlines()[-1] == 'unexpected results: 0', c.stdout
    path = HERE/'vectors.txt'
    path.write_text(payload)
    lean = subprocess.run([str(ROOT/'lean/.lake/build/bin/qsbcheck'), str(path)],
                          capture_output=True, text=True, check=True)
    assert not any(x.startswith(('FAIL', 'GAP')) for x in lean.stdout.splitlines()), lean.stdout
    expected = f'{len(lines)} vectors, 0 disagree with Core, 0 outside the model'
    assert expected in lean.stdout, lean.stdout
    report = dict(core_vectors=len(lines), core_summary=c.stdout.splitlines()[-1],
                  lean_summary=expected, tiers=results)
    (HERE/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--test', action='store_true')
    a = p.parse_args()
    if a.test:
        test_all()
