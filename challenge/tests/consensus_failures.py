#!/usr/bin/env python3
"""A crashed or truncated verifier must never turn into a passing judge gate."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'challenge')]
import qsb_pool as q
from judge import consensus,design
from judge.__main__ import lean_builder_check

_,cfg=design.load(ROOT/'challenge/submissions/spacer_d/design.json')
prod,tb=q.build(cfg),q.build(cfg,test_mode=True)
cases=[]
for code in (0,1):
    with patch('subprocess.run',return_value=SimpleNamespace(returncode=code,stdout='',stderr='')):
        bad,_=consensus.run_cchk(['one vector'])
        assert bad is None
        with tempfile.TemporaryDirectory() as td:
            bad,_=consensus.run_lean(['one vector'],td)
            assert bad
        ok,_=lean_builder_check(cfg,prod,tb)
        assert ok is False
    cases.append(dict(returncode=code,empty_output_rejected_by=['core','lean_replay','lean_builder']))
with patch('subprocess.run',return_value=SimpleNamespace(returncode=1,
           stdout='scripts x: 2 builds, 0 differ between Lean and Python',stderr='crash')):
    assert lean_builder_check(cfg,prod,tb)[0] is False
cases.append(dict(nonzero_exit_with_success_text_rejected=True))
(ROOT/'challenge/tests/consensus_failures_results.json').write_text(json.dumps(cases,indent=2)+'\n')
print('7 verifier-failure controls passed')
