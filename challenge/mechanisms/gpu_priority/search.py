#!/usr/bin/env python3
"""Reproducible GPU-first proposal search; never changes trusted judge files.

The fast model ranks proposals only. Exact security and measured-table cost are
computed on rebuilt scripts for finalists, with every baseline security axis
preserved. Use --screen to run the frozen judge's actual screen gates.
"""
import argparse
import json
import math
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CH = HERE.parents[1]
sys.path[:0] = [str(CH.parent), str(CH)]
import qsb_pool as q
import security_menu as M
from judge import cost, design
from judge.__main__ import judge

M.P['sha1'] = math.log2(1 / q.p_der(20))
M.GPU['RTX 4090']['sha1'] = .0275
BASE = {
    'D': dict(hash='sha256', n=140, k=32, chain_pin=3, t1=6, b1=1,
              k1=16, chain1=2, t2=7, b2=0, k2=32, chain2=3),
    'E': dict(hash='sha256', n=130, k=96, chain_pin=1, t1=7, b1=0,
              k1=48, chain1=3, t2=7, b2=0, k2=96, chain2=2),
}
for c in BASE.values():
    c.update(R=2, pool_deep=True, force_comp=False, sign_j=False,
             sign_lvl=False, enc_honest=3)
VALUES = dict(hash=['sha256', 'sha1', 'rmd'], n=list(range(100, 157)),
              k=[8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 300],
              chain_pin=list(range(1, 17)), force_comp=[False, True],
              sign_j=[False, True], sign_lvl=[False, True])
for i in (1, 2):
    VALUES.update({f't{i}': list(range(4, 10)), f'b{i}': [0, 1, 2],
                   f'k{i}': [8, 12, 16, 24, 32, 48, 64, 96],
                   f'chain{i}': list(range(1, 17))})


def to_design(c):
    return dict(schema='qsb-design-v2', **{k: c[k] for k in
        ('hash', 'n', 'k', 'chain_pin', 'pool_deep', 'force_comp', 'sign_j', 'sign_lvl')},
        rounds=[dict(t=c[f't{i}'], b=c[f'b{i}'], k=c[f'k{i}'], chain=c[f'chain{i}'])
                for i in (1, 2)])


def proxy(c, target):
    if max(c['k1'], c['k2']) > c['k'] or M.ops_est(c) > 201:
        return None
    if c['sign_lvl'] and max(c['chain1'], c['chain2']) == 1:
        return None
    # Conservative byte proxy used by the repository's earlier searches.
    if M.bytes_est(c) > 10100:
        return None
    pre, E = M.quick(c)
    # A bonus selection's label does not change FindAndDelete. Count each
    # union once rather than each partition into signed/bonus slots.
    E = [e / math.comb(c[f't{i}'] + c[f'b{i}'], c[f't{i}'])
         for i, e in enumerate(E, 1)]
    quantum = (pre - math.log2(6*c['k']*c['chain_pin']))/2 - 1.5
    if pre < target[0] or quantum < target[1] or min(E) < 1:
        return None
    return M.hours(c, E, 'RTX 4090')


def exact(c, tbl):
    b = q.build(c)
    if b['ops'] > 201 or len(b['script']) > 10000 or b['max_stack'] > 1000:
        return None
    if len(q.build(c, test_mode=True)['script']) > 10000:
        return None
    P = M.P[c['hash']]
    a = q.analyse(c, P, b)
    if min(a['E']) < 1:
        return None
    try:
        h, rates = cost.gpu_hours(c, b, a, P, tbl)
    except cost.Unmeasured:
        return None
    return dict(cfg=c, design=to_design(c), hours=h, security=a,
                ops=b['ops'], script_bytes=len(b['script']), rates=rates)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--steps', type=int, default=150000)
    ap.add_argument('--seed', type=int, default=20261027)
    ap.add_argument('--finalists', type=int, default=40)
    ap.add_argument('--screen', action='store_true')
    args = ap.parse_args()
    rng = random.Random(args.seed)
    tbl = cost.load_table()
    axes = ['preimage_bits', 'quantum_query_bits', 'collision_bits']
    result = dict(seed=args.seed, steps=args.steps, tiers={})
    for name, base in BASE.items():
        br = exact(base, tbl)
        threshold = (br['security']['preimage_bits'], br['security']['quantum_query_bits'])
        seen = {}
        cur = dict(base)
        ch = proxy(cur, threshold)
        for it in range(args.steps):
            if it % 2000 == 0:
                cur = dict(base if (it//2000)%2 == 0 else BASE['E'])
                ch = proxy(cur, threshold)
            cand = dict(cur)
            for field in rng.sample(list(VALUES), rng.choice([1, 1, 2, 3])):
                cand[field] = rng.choice(VALUES[field])
            cand['enc_honest'] = 1 if cand['force_comp'] else 3
            h = proxy(cand, threshold)
            if h is None:
                continue
            key = json.dumps(cand, sort_keys=True)
            seen[key] = h
            temperature = .02 + .4 * (1 - (it % 2000) / 2000)
            if ch is None or h <= ch or rng.random() < math.exp(min(0, (ch-h)/temperature)):
                cur, ch = cand, h
        candidates = []
        rejected = dict(limits_or_unmeasured=0, security=0)
        for key, _ in sorted(seen.items(), key=lambda x: x[1])[:args.finalists]:
            ex = exact(json.loads(key), tbl)
            # The frozen judge has an identified bonus-space accounting error.
            # Keep the baseline for comparison, but never submit a candidate
            # whose GPU estimate would depend on that error.
            if ex and not any(ex['cfg'][f'b{i}'] for i in (1, 2)) and all(
                    ex['security'][a] >= br['security'][a] for a in axes):
                candidates.append(ex)
            else:
                rejected['limits_or_unmeasured' if ex is None else 'security'] += 1
        candidates.sort(key=lambda x: x['hours'])
        for i, ex in enumerate(candidates[:5]):
            dst = CH / 'submissions' / f'gpu_{name.lower()}_{i}'
            dst.mkdir(parents=True, exist_ok=True)
            (dst / 'design.json').write_text(json.dumps(ex['design'], indent=2)+'\n')
            if args.screen:
                ex['screen'] = judge(dst, args.seed, strict_manifest=True, mode='screen', log=lambda *a: None)
            print(name, i, ex['hours'], {a: ex['security'][a] for a in axes}, ex['design'], flush=True)
        result['tiers'][name] = dict(baseline=br, unique_feasible=len(seen), rejected=rejected,
                                     candidates=candidates[:5])
    (HERE/'results.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
