#!/usr/bin/env python3
"""Organizer release tool: freeze checked, exact-layout real-DER GPU repeats."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT),str(ROOT/'challenge')]
import qsb_pool as q
from judge import design

source=ROOT/'challenge/mechanisms/spacer_selection/gpu_validation/report.json'
report=json.loads(source.read_text())
assert all(x['failed']==0 and x['verified']>=100 and x['control_false_pass']==0
           for x in report['correctness'])
profiles=[]
for tier in 'DE':
    _,cfg=design.load(ROOT/f'challenge/submissions/spacer_{tier.lower()}/design.json')
    built=q.build(cfg)
    shape={k:cfg[k] for k in ('hash','n','k','pool_deep','force_comp','chain_pin','sign_j','sign_lvl',
                             'destructive_chain','spacer_selection')}
    shape['rounds']=[dict(t=cfg[f't{i}'],b=cfg[f'b{i}'],k=cfg[f'k{i}'],chain=cfg[f'chain{i}']) for i in (1,2)]
    stages=[]
    for stage,k,m in [('pin',cfg['k'],cfg['chain_pin']),('round1',cfg['k1'],cfg['chain1']),
                      ('round2',cfg['k2'],cfg['chain2'])]:
        rates=[]
        for rep in range(3):
            raw=json.loads((source.parent/f'results/{tier}_{stage}_der_{rep}.json').read_text())
            assert raw['gpu']=='NVIDIA GeForce RTX 4090' and raw['gate']=='der'
            assert raw['hash']==('sha' if cfg['hash']=='sha256' else cfg['hash'])
            assert raw['K']==k and raw['chain']==m and raw['enc']==3 and raw['extra_blocks']==0
            assert raw['seconds']>=20 and raw['shots_per_s']>0
            rates.append(raw['shots_per_s'])
        stages.append(dict(stage=stage,der_rates=rates))
    profiles.append(dict(id=f'spacer_{tier.lower()}_rtx4090_20261027',shape=shape,
                         production_bytes=len(built['script']),ops=built['ops'],noise_margin=0.95,
                         source=str(source.relative_to(ROOT)),source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                         stages=stages))
target=ROOT/'challenge/judge/exact_rates.json'
target.write_text(json.dumps(dict(version=1,hardware='NVIDIA GeForce RTX 4090',profiles=profiles),indent=2)+'\n')
print(f'froze {len(profiles)} exact layouts from 18 real-DER measurements')
