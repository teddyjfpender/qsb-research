#!/usr/bin/env python3
"""Core-backed counterexample to counting signed/bonus partitions as fresh shots."""
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
import qsb_pool as q
from trace import parse_script_sig


def main():
    cfg = dict(hash='sha256', n=140, k=32, chain_pin=3, t1=6, b1=1,
               k1=16, chain1=2, t2=7, k2=32, chain2=3, pool_deep=True)
    rows, lines = [], []
    for test_mode in (False, True):
        built = q.build(cfg, test_mode=test_mode)
        views, witnesses = set(), set()
        for bonus in range(7):
            ch = dict(jp=0, j=[1, 1], subsets=[
                [i for i in range(7) if i != bonus] + [bonus], list(range(7))],
                odd=[0, 0, 0], enc=['comp']*3, lvl=[1]*3)
            tx, idx, z = q.spend(built, ch)
            items = dict(zip(built['witness'], parse_script_sig(built['last_script_sig'])))
            views.add((z[1], items['key0']))
            witnesses.add(built['last_script_sig'])
            if test_mode:
                lines.append(f'bonus_partition_{bonus} {built["script"].hex()} {tx.hex()} {idx} 1')
        assert len(views) == 1 and len(witnesses) == 7
        rows.append(dict(test_mode=test_mode, signed_bonus_partitions=7,
                         distinct_witnesses=len(witnesses), distinct_puzzle_inputs=len(views)))
    payload = '\n'.join(lines)+'\n'
    run = subprocess.run([str(ROOT/'consensus_check/target/release/cchk')],
                         input=payload, text=True, capture_output=True, check=True)
    assert run.stdout.count('PASS') == 7 and 'unexpected results: 0' in run.stdout
    b = q.build(cfg)
    a = q.analyse(cfg, math.log2(1/q.p_der(32)), b)
    report = dict(config=cfg, cases=rows, core=run.stdout,
                  reported_E1=a['E'][0], distinct_input_E1=a['E'][0]/7,
                  reported_success_probability1=1-math.exp(-a['E'][0]),
                  distinct_input_poisson_probability1=1-math.exp(-a['E'][0]/7),
                  vectors_sha256=hashlib.sha256(payload.encode()).hexdigest())
    (HERE/'bonus_space_result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
