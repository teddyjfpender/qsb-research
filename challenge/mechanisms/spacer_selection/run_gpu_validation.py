#!/usr/bin/env python3
"""Run inside the isolated GPU directory after compiling both pool2 binaries."""
import json
import os
from pathlib import Path
import subprocess
import time

OUT = Path('results')
OUT.mkdir(exist_ok=True)


def hardware(label):
    fields = 'name,uuid,driver_version,power.limit,clocks.sm,clocks.mem,temperature.gpu,utilization.gpu'
    result = subprocess.run(['nvidia-smi',f'--query-gpu={fields}','--format=csv'],
                            text=True,capture_output=True,check=True)
    (OUT/f'hardware_{label}.txt').write_text(result.stdout)


hardware('before')
start = time.time()
for tier,k,hsh,high in [('D',96,'sha',21),('E',64,'sha1',30)]:
    for stage,chain in [('pin',2),('round1',4),('round2',5)]:
        binary = './pool2_pin' if stage == 'pin' else './pool2_round'
        jobs = [('zeros',0,5,0),('zeros',1,5,high)]
        jobs += [('der',rep,20,seq) for rep,seq in enumerate([0,high//2,high])]
        for gate,rep,seconds,seq in jobs:
            stem = f'{tier}_{stage}_{gate}_{rep}'
            env = dict(os.environ,POOL_CHAIN=str(chain),OMP_NUM_THREADS='12')
            args = [binary,f'{tier}_{stage}.bin',str(k),hsh,gate,'28',str(seconds),
                    '0',str(OUT/f'{stem}.hits'),'3',str(seq)]
            with (OUT/f'{stem}.json').open('w') as stdout, (OUT/f'{stem}.log').open('w') as stderr:
                subprocess.run(args,env=env,stdout=stdout,stderr=stderr,check=True,timeout=180)
            print(stem,(OUT/f'{stem}.json').read_text().strip(),flush=True)
    hardware(tier)
hardware('after')
(OUT/'duration.json').write_text(json.dumps(dict(wall_seconds=time.time()-start)))
