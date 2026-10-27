#!/usr/bin/env python3
"""GPU-first search of the standalone spacer proposal, never a ranked judge run."""
import argparse
from functools import lru_cache
import json
import math
import random
from pathlib import Path

import build as proto
import qsb_pool as q
import security_menu as menu
from judge import checks, cost
from challenge.mechanisms.der_budget.check import exact_probability

HERE = Path(__file__).resolve().parent
TABLE = cost.load_table()
P = {h: math.log2(1/float(exact_probability(32 if h == 'sha256' else 20)))
     for h in ('sha256', 'sha1', 'rmd')}
BASE = {
    'D': dict(hash='sha256', n=140, k=32, chain_pin=3, t1=6, b1=1,
              k1=16, chain1=2, t2=7, b2=0, k2=32, chain2=3),
    'E': dict(hash='sha256', n=130, k=96, chain_pin=1, t1=7, b1=0,
              k1=48, chain1=3, t2=7, b2=0, k2=96, chain2=2),
}
for c in BASE.values():
    c.update(R=2, pool_deep=True, force_comp=False, sign_j=False,
             sign_lvl=False, enc_honest=3)
AXES = ('preimage_bits', 'quantum_query_bits', 'collision_bits')
VALUES = dict(hash=['sha256', 'sha1', 'rmd'], n=list(range(90, 157)),
              k=[8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256],
              chain_pin=list(range(1, 17)), force_comp=[False, True],
              sign_j=[False, True], sign_lvl=[False, True])
for i in (1, 2):
    VALUES.update({f't{i}': list(range(5, 9)),
                   f'k{i}': [8, 12, 16, 24, 32, 48, 64, 96],
                   f'chain{i}': list(range(1, 17))})


@lru_cache(None)
def rate(stage, h, k, m, e):
    try:
        return cost.lookup(TABLE, stage, h, k, m, e)
    except cost.Unmeasured:
        return None


def metrics(c):
    pbits = P[c['hash']]
    S, E, signed = [], [], 0.0
    enc = 1 if c['force_comp'] else 3
    extra = c['chain_pin'] if c['chain_pin'] > 1 else 0
    for i in (1, 2):
        k, m, t = c[f'k{i}'], c[f'chain{i}'], c[f't{i}']
        S.append(2*enc*(1 if c['sign_j'] else k+extra)*(1 if c['sign_lvl'] else m))
        subsets = math.comb(c['n'], t)
        E.append(subsets * 2*enc*k*m * 2**-pbits)
        signed += math.log2(subsets)
    pre = 3*pbits - sum(math.log2(s) for s in S)
    quantum = (pre - math.log2(6*c['k']*c['chain_pin']))/2 - 1.5
    birthday = pbits + math.log2(1 + 1/E[1] + 1/(E[0]*E[1])) + signed/2
    fixed = (2*pre-pbits + math.log2(sum(S)) + 1)/2
    return dict(preimage_bits=pre, quantum_query_bits=quantum,
                collision_bits=min(birthday, fixed), S=S, E=E)


def ops(c):
    # Spacer selections save t1+t2; consuming selected chain levels saves one
    # further opcode for each odd m>1 (the previously validated proposal).
    return menu.ops_est(c) - c['t1'] - c['t2'] - sum(
        c[f'chain{i}'] % 2 for i in (1, 2) if c[f'chain{i}'] > 1)


def proxy(c, target):
    if max(c['k1'], c['k2']) > c['k'] or ops(c) > 201:
        return None
    if c['sign_lvl'] and max(c['chain1'], c['chain2']) == 1:
        return None
    # Conservative-but-loose prefilter; finalist scripts are rebuilt exactly.
    if menu.bytes_est(c) + 2*c['n'] - 3*(c['t1']+c['t2']) > 10300:
        return None
    wit = sum(3*c[f't{i}'] + 2 + int(c[f'chain{i}'] > 1) + int(c['sign_j']) +
              int(c['sign_lvl'] and c[f'chain{i}'] > 1) for i in (1, 2))
    stack = 6*c['n'] + 2 + c['k'] + wit + 2 + int(c['chain_pin'] > 1)
    stack += (c['k1']+c['k2']) if c['sign_j'] else 0
    stack += sum(c[f'chain{i}'] for i in (1, 2) if c['sign_lvl'] and c[f'chain{i}'] > 1)
    if stack > 1000:
        return None
    a = metrics(c)
    if min(a['E']) < 1 or any(a[x] < target[x] for x in AXES):
        return None
    pin = max(rate('pin', c['hash'], c['k'], c['chain_pin'], e) or 0 for e in (1, 3))
    if not pin:
        return None
    rates = [pin]
    for i in (1, 2):
        best = 0
        for e in ((1,) if c['force_comp'] else (1, 3)):
            r = rate('rnd', c['hash'], c[f'k{i}'], c[f'chain{i}'], e)
            if not r:
                continue
            # Interleaving also makes the remaining commitments part of the
            # rehashed suffix. Include that cost in proposal ranking.
            stream = 32*c['n']*i + 3*ops(c) - 10*c[f't{i}']
            extra = max(0, math.ceil((stream+TABLE['round_tx_tail']+9)/64)-TABLE['measured_round_blocks'])
            ns = 1e9/r + extra*TABLE['sha256_block_ns']/(2*c[f'k{i}']*c[f'chain{i}']*e)
            best = max(best, 1e9/ns)
        if not best:
            return None
        rates.append(best)
    p1, p2 = [-math.expm1(-e) for e in a['E']]
    return 2**P[c['hash']] * (1/(rates[0]*p1*p2) + 1/(rates[1]*p2) + 1/rates[2])/3600


def exact(c, target):
    b = proto.build(c)
    tb = proto.build(c, test_mode=True)
    opcount, errors = checks.limits(b['script'])
    _, terrors = checks.limits(tb['script'])
    subs, twin_error = checks.twin(b['script'], tb['script'])
    assert opcount == b['ops'] == ops(c)
    if errors or terrors or twin_error or max(b['max_stack'], tb['max_stack']) > 1000:
        return None
    a = q.analyse(c, P[c['hash']], b)
    quick = metrics(c)
    assert all(math.isclose(a[x], quick[x], abs_tol=1e-10) for x in AXES)
    if min(a['E']) < 1 or any(a[x] < target[x] for x in AXES):
        return None
    try:
        hours, rates = cost.gpu_hours(c, b, a, P[c['hash']], TABLE)
    except cost.Unmeasured:
        return None
    return dict(cfg=c, hours=hours, security=a, ops=opcount,
                script_bytes=len(b['script']), test_bytes=len(tb['script']),
                max_stack=b['max_stack'], substitutions=subs, stage_rates=rates,
                confidence='unranked mechanism estimate; full family soundness not proved')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--steps', type=int, default=100000)
    ap.add_argument('--finalists', type=int, default=500)
    args = ap.parse_args()
    rng = random.Random(20261028)
    report = dict(seed=20261028, steps=args.steps, probability='corrected exact DER', tiers={})
    for tier, base in BASE.items():
        target = q.analyse(base, P[base['hash']], q.build(base))
        seed = dict(base, b1=0, b2=0, t1=7, t2=7, n=130, k=64, k1=64, k2=64,
                    chain_pin=2, chain1=3, chain2=4, destructive_chain=True)
        cur, hcur = dict(seed), proxy(seed, target)
        seen = {}
        for j in range(args.steps):
            if j % 2000 == 0:
                cur = dict(seed)
                hcur = proxy(cur, target)
            cand = dict(cur)
            for key in rng.sample(list(VALUES), rng.choice([1, 1, 2, 3])):
                cand[key] = rng.choice(VALUES[key])
            h = proxy(cand, target)
            if h is None:
                continue
            seen[json.dumps(cand, sort_keys=True)] = h
            temp = .02 + .3*(1-(j%2000)/2000)
            if hcur is None or h <= hcur or rng.random() < math.exp(min(0, (hcur-h)/temp)):
                cur, hcur = cand, h
        winners = []
        for key, _ in sorted(seen.items(), key=lambda x: x[1])[:args.finalists]:
            val = exact(json.loads(key), target)
            if val:
                winners.append(val)
        winners.sort(key=lambda x: x['hours'])
        report['tiers'][tier] = dict(target={x:target[x] for x in AXES},
                                     unique_feasible=len(seen), rebuilt=min(args.finalists,len(seen)),
                                     candidates=winners[:5])
        print(tier, json.dumps(report['tiers'][tier]), flush=True)
    (HERE/'search_results.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
