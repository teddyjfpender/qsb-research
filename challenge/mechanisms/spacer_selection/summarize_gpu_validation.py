#!/usr/bin/env python3
"""Verify every benchmark job and compute measured-rate expected mean costs."""
import hashlib
import json
import math
import statistics
from pathlib import Path

from gpu_validation import HERE, ROOT, OUT, verify


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    results = OUT/'results'
    verification = []
    costs = {}
    for tier in ('D','E'):
        artifact = json.loads((HERE/f'{tier}_candidate.json').read_text())
        candidate = artifact['estimate']
        stage_results = []
        for stage in ('pin','round1','round2'):
            for rep in range(2):
                stem = f'{tier}_{stage}_zeros_{rep}'
                hits, rate = results/f'{stem}.hits', results/f'{stem}.json'
                record = dict(hits_sha256=digest(hits), rate_sha256=digest(rate),
                              verifier_sha256=digest(HERE/'gpu_validation.py'))
                cache = results/f'{stem}.verified.json'
                previous = json.loads(cache.read_text()) if cache.exists() else {}
                if all(previous.get(k) == v for k,v in record.items()):
                    record = previous
                else:
                    record.update(verify(tier,stage,hits,rate))
                    cache.write_text(json.dumps(record,indent=2)+'\n')
                verification.append(record)
            measured = []
            for rep in range(3):
                r = json.loads((results/f'{tier}_{stage}_der_{rep}.json').read_text())
                assert r['gpu'] == 'NVIDIA GeForce RTX 4090' and r['gate'] == 'der'
                assert r['enc'] == 3 and r['extra_blocks'] == 0 and r['seconds'] >= 20
                measured.append(r)
            rates = [r['shots_per_s'] for r in measured]
            stage_results.append(dict(stage=stage,rates=rates,median=statistics.median(rates),
                                      minimum=min(rates),maximum=max(rates),
                                      der_hits=sum(r['hits'] for r in measured),
                                      seconds=sum(r['seconds'] for r in measured)))
        p1,p2 = candidate['security']['p']
        # Corrected probability: 24 valid integer-length patterns for 32B,
        # 12 for 20B. Fractions were independently checked by der_budget.
        probability = (780555 if tier == 'D' else 390405)/36893488147419103232
        def hours(rates):
            return (1/rates[0]/p1/p2 + 1/rates[1]/p2 + 1/rates[2])/probability/3600
        measured_hours = hours([s['median'] for s in stage_results])
        conservative = hours([0.95*s['minimum'] for s in stage_results])
        costs[tier] = dict(original_estimate_hours=candidate['hours'],
                           measured_rate_expected_hours=measured_hours,
                           optimistic_repeat_envelope_hours=hours([s['maximum'] for s in stage_results]),
                           pessimistic_repeat_envelope_hours=hours([s['minimum'] for s in stage_results]),
                           conservative_with_5pct_rate_margin_hours=conservative,
                           original_estimate_ratio=measured_hours/candidate['hours'],
                           stages=stage_results, round_success_probabilities=[p1,p2],
                           der_probability=probability,
                           security=candidate['security'],
                           full_production_spend_solved=False,
                           interpretation='Measured stage throughput; projected mean with existing random-oracle/Poisson retry model. Not a full-solve observation or deadline guarantee.')
    paths = list(OUT.glob('*.bin')) + [OUT/'pool2_exact.cu', HERE/'round_renderer.cuh',
             HERE/'gpu_validation.py', HERE/'run_gpu_validation.py',
             ROOT/'gpu/pool2.cu', ROOT/'gpu/GPUMath.h',ROOT/'gpu/GPUHash.h',
             ROOT/'gpu/fasthash.cuh',ROOT/'gpu/field2.cuh']
    manifest = {str(path.relative_to(ROOT)):digest(path) for path in paths}
    report = dict(hardware='NVIDIA GeForce RTX 4090',date='2026-10-27',
                  original_estimates_are_not_measurements=True,tiers=costs,
                  correctness=verification,source_and_input_sha256=manifest,
                  measured_der_gpu_seconds=sum(s['seconds'] for c in costs.values() for s in c['stages']))
    (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({tier:{k:v for k,v in val.items() if k not in ('stages','security')}
                      for tier,val in costs.items()},indent=2))


if __name__ == '__main__':
    main()
