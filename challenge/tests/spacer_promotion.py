#!/usr/bin/env python3
"""Promotion regressions: trusted bytes, independent Lean rebuild, and hostile witnesses."""
import copy
import json
import math
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'challenge')]
import qsb_pool as q
from judge import audit, consensus, cost, design, interp
from judge.__main__ import lean_builder_check, proof_family
from qsbcore import OP, der9, hash160, push_min, push_num, ser_tx
from redteam import patched


def reject_schema(d):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)/'design.json'; p.write_text(json.dumps(d))
        try: design.load(p)
        except design.Invalid: return
        raise AssertionError('bad extension accepted by schema')


def main():
    results, lines = [], []
    for tier in ('D','E'):
        d,cfg = design.load(ROOT/f'challenge/submissions/spacer_{tier.lower()}/design.json')
        old = json.loads((ROOT/f'challenge/mechanisms/spacer_selection/{tier}_candidate.json').read_text())
        for seed in (1,97):
            c = dict(cfg,seed=seed); prod=q.build(c); tb=q.build(c,test_mode=True)
            if seed == 1:
                assert prod['script'].hex()==old['production_script']
                assert tb['script'].hex()==old['test_script']
            ok,msg=lean_builder_check(c,prod,tb); assert ok,msg
            assert proof_family(c)['label']=='audited'
            lines += q.vectors_for(f'SPACER_{tier}_{seed}',c,random.Random(seed))
            an=q.analyse(c,math.log2(1/q.p_der(32 if tier=='D' else 20)),prod)
            h,_=cost.gpu_hours(c,prod,an,math.log2(1/q.p_der(32 if tier=='D' else 20)),cost.load_table())
            assert abs(h-old['timing_validation']['conservative_with_5pct_rate_margin_hours'])<1e-10
        for changes in [dict(pool_deep=False),dict(sign_j=True),dict(sign_lvl=True),
                        dict(destructive_chain='yes'),dict(selection_layout='unknown'),dict(gpu_hours=1),
                        dict(rounds=[dict(d['rounds'][0],b=1),d['rounds'][1]])]:
            reject_schema(dict(d,**changes))
        mutant=dict(cfg,hash='sha1' if tier=='D' else 'sha256')
        try: cost.measured_profile(mutant,q.build(mutant))
        except cost.Unmeasured: pass
        else: raise AssertionError('unmeasured hash/layout silently borrowed rates')
        results.append(dict(tier=tier,golden_bytes=True,lean_seeds=[1,97],schema_mutations=7,
                            unmeasured_rejected=True,conservative_hours=h))

    # Exercise cleanup parity and boundary levels independently of the large
    # candidates; every level has to leave exactly the same suffix.
    for m in (1,2,3,4,5,16):
        cfg=dict(hash='sha256',n=8,k=4,t1=2,k1=4,chain_pin=2,chain1=m,
                 pool_deep=True,force_comp=False,sign_j=False,sign_lvl=False,
                 spacer_selection=True,destructive_chain=True)
        prod=q.build(cfg); tb=q.build(cfg,test_mode=True)
        ok,msg=lean_builder_check(cfg,prod,tb); assert ok,msg
        for level in range(1,m+1):
            for sub in ([0,7],[7,0]):
                ch=dict(jp=1,j=[2],subsets=[sub],odd=[0,1],enc=['hybrid','uncomp'],lvl=[2,level])
                tx,idx,_=q.spend(tb,ch)
                lines.append(f'CHAIN_{m}_{level}_{sub[0]} {tb["script"].hex()} {tx.hex()} {idx} 1')

    # Independent malformed-bound control: fake C/D supplied below the region
    # must be unreachable. Replacing MIN with DROP must make this attack work.
    secret=b'a'*20; good=der9(1,1,3); evil=der9(1,2,3)
    b=q.Builder(['pre','evilD','evilF','evilC','x'],'OP_SHA256',False)
    b.push_n('Z',0); b.push('D',good); b.push_n('F',0); b.push('C',hash160(secret))
    b.roll('x'); evil_index=b.depth('evilC'); b.min_(b.depth('Z')-1); clamp=len(b.script)-1
    b._op('OP_DUP'); b._op('OP_ROLL'); b.stack.remove('C'); b.stack.append('csel')
    b.roll('pre'); b._op('OP_HASH160'); b._op('OP_EQUALVERIFY'); b.stack.pop(); b.stack.pop(); b._op('OP_ROLL')
    prefix=bytes(b.script); broken=bytearray(prefix); broken[clamp]=OP['OP_DROP']
    suffix=push_min(evil)+bytes([OP['OP_EQUALVERIFY']])+push_num(1)
    ss=b''.join(map(push_min,[secret,evil,b'',hash160(secret)]))+push_num(evil_index)
    tx=ser_tx([(bytes(32),0,ss,0xffffffff)],[(1,b'\x51')],0)
    lines += [f'BOUND_{name} {(script+suffix).hex()} {tx.hex()} 0 {expect}'
              for name,script,expect in [('intact',prefix,0),('removed',bytes(broken),1)]]

    # Real trusted-builder mutations must be caught by the freedom audit.
    _,cfg=design.load(ROOT/'challenge/submissions/spacer_d/design.json')
    for mutation in ('no_hors_check','no_clamp'):
        with patched(mutation):
            prod=q.build(cfg); tb=q.build(cfg,test_mode=True)
        an=q.analyse(cfg,math.log2(1/q.p_der(32)),prod)
        au=audit.run_audit(cfg,tb,prod,an,random.Random(33),budget_random=100)
        assert not au['ok'],f'undetected {mutation}'
        results.append(dict(mutation=mutation,detected=True,reason=au.get('error')))

    # Corrected DER pattern counts and bonus union counts are independent
    # regression anchors, not numbers copied from a submitted claim.
    assert q.p_der(20)==390405/2**65 and q.p_der(32)==780555/2**65
    assert q.p_der(8)==q.p_der(74)==0
    cfg=dict(n=20,k=8,t1=3,b1=1,k1=8,chain1=1,chain_pin=1,pool_deep=True,hash='sha256')
    an=q.analyse(cfg,45,q.build(cfg))
    assert an['E']==[math.comb(20,4)*48*2**-45]
    bad,tail=consensus.run_cchk(lines); assert bad==[],tail
    with tempfile.TemporaryDirectory() as td:
        bad,lean=consensus.run_lean(lines,td); assert bad==[],lean
    out=dict(cases=results,core_vectors=len(lines),core=tail,lean=lean,probability_and_union_counts=True)
    (ROOT/'challenge/tests/spacer_promotion_results.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out,indent=2))


if __name__=='__main__': main()
