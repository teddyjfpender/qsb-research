#!/usr/bin/env python3
"""Consensus and adversarial checks for the unranked spacer mechanism."""
import argparse
import json
import random
from pathlib import Path

import build as proto
import qsb_pool as q
from qsbcore import OP, der9, hash160, push_min, push_num, ser_tx
from judge import audit, checks, consensus
from search import P

HERE = Path(__file__).resolve().parent


def gadget_vectors():
    out = []
    n = 5
    secrets = [bytes([i+1])*20 for i in range(n)]
    ds = [der9(1, i+1, 3) for i in range(n)]
    cm = [hash160(s) for s in secrets]
    for removed in range(2**n-1):
        alive = [a for a in range(n) if not (removed >> a) & 1]
        b = q.Builder(['pre', 'evilD', 'evilF', 'evilC', 'x'], 'OP_SHA256', False)
        b.push_n('Z', 0)
        for a in reversed(range(n)):
            if a in alive:
                b.push(f'D{a}', ds[a])
                b.push_n(f'F{a}', 0)
                b.push(f'C{a}', cm[a])
            else:
                b.push_n(f'F{a}', 0)
        b.roll('x')
        positions = {a:b.depth(f'C{a}') for a in alive}
        evil_position = b.depth('evilC')
        bound = b.depth('Z')-1
        b.min_(bound)
        min_pos = len(b.script)-1
        b._op('OP_DUP')
        b._op('OP_ROLL')
        b.stack.remove(f'C{alive[0]}')
        b.stack.append('csel')
        b.roll('pre')
        b._op('OP_HASH160')
        b._op('OP_EQUALVERIFY')
        b.stack.pop()
        b.stack.pop()
        b._op('OP_ROLL')
        prefix = bytes(b.script)
        for a in range(n):
            # Check the postcondition: when C_a opens, the selected value must
            # be D_a. The production script consumes it later in CHECKMULTISIG.
            script = prefix + push_min(ds[a]) + bytes([OP['OP_EQUALVERIFY']]) + push_num(1)
            for x in [-2, -1] + list(range(evil_position+4)) + [2**31-1]:
                ss = b''.join(map(push_min, [secrets[a], ds[(a+1)%n], b'', cm[a]])) + push_num(x)
                tx = ser_tx([(bytes(32), 0, ss, 0xffffffff)], [(1,b'\x51')], 0)
                expected = a in alive and x == positions[a]
                out.append(f'gadget_m{removed}_a{a}_x{x} {script.hex()} {tx.hex()} 0 {int(expected)}')
        # Negative control: dropping the bound instead of MIN permits a witness
        # supplied commitment/dummy pair. The intact bound must reject it.
        broken = bytearray(prefix)
        assert broken[min_pos] == OP['OP_MIN']
        broken[min_pos] = OP['OP_DROP']
        a, other = alive[0], (alive[0]+1)%n
        tail = push_min(ds[other]) + bytes([OP['OP_EQUALVERIFY']]) + push_num(1)
        ss = b''.join(map(push_min, [secrets[a], ds[other], b'', cm[a]])) + push_num(evil_position)
        tx = ser_tx([(bytes(32), 0, ss, 0xffffffff)], [(1,b'\x51')], 0)
        out.append(f'bound_intact_m{removed} {(prefix+tail).hex()} {tx.hex()} 0 0')
        out.append(f'bound_removed_m{removed} {(bytes(broken)+tail).hex()} {tx.hex()} 0 1')
    return out


def choose(cfg, rng):
    return dict(jp=rng.randrange(cfg['k']),
                j=[rng.randrange(1,cfg[f'k{i}']+1) for i in (1,2)],
                subsets=[rng.sample(range(cfg['n']),cfg[f't{i}']) for i in (1,2)],
                odd=[rng.randrange(2) for _ in range(3)],
                enc=[rng.choice(['comp','uncomp','hybrid']) for _ in range(3)],
                lvl=[rng.randrange(1,cfg[key]+1) for key in ('chain_pin','chain1','chain2')])


def full_vectors(tag, cfg, rng):
    out = []
    tb, prod = proto.build(cfg, test_mode=True), proto.build(cfg)

    def emit(label, choice, expected, built=None, tamper=None):
        b = built or tb
        tx, idx, _ = proto.spend(b, choice, tamper=tamper)
        out.append(f'{tag}_{label} {b["script"].hex()} {tx.hex()} {idx} {int(expected)}')

    for i in range(30):
        emit(f'honest_{i}', choose(cfg,rng), True)
    c = choose(cfg,rng)
    for label, subsets in [('first', [list(range(cfg[f't{i}'])) for i in (1,2)]),
                            ('last', [list(range(cfg['n']-cfg[f't{i}'],cfg['n'])) for i in (1,2)])]:
        emit(label, dict(c, subsets=subsets), True)
        emit(label+'_reversed', dict(c, subsets=[s[::-1] for s in subsets]), True)
    for i in range(8):
        c = choose(cfg,rng)
        _,_,z = proto.spend(tb,c)
        reverse = dict(c, subsets=[s[::-1] for s in c['subsets']])
        _,_,zr = proto.spend(tb,reverse)
        assert z == zr
        emit(f'reversed_{i}', reverse, True)
    c = choose(cfg,rng)
    for rd in range(2):
        for i in range(cfg[f't{rd+1}']):
            emit(f'wrong_pre_{rd}_{i}', c, False, tamper={f'pre{rd}_{i}':bytes(20)})
        for val in (-1, 0, tb['plan']['rounds'][rd]['max_depth'][0], 2**31-1):
            emit(f'bad_index_{rd}_{val}', c, False, tamper={f'x{rd}_0':val})
        repeated = [list(s) for s in c['subsets']]
        repeated[rd][-1] = repeated[rd][0]
        emit(f'repeated_{rd}',dict(c,subsets=repeated),False)
        emit(f'negative_level_{rd}',c,False,tamper={f'l{rd}':-1})
        emit(f'clamped_level_{rd}',c,True,tamper={f'l{rd}':10**6})
    emit('production_nonhit',c,False,built=prod)
    emit('ops_202',c,False,built=proto.build(cfg,test_mode=True,pad_ops=202-tb['ops']))
    emit('ops_201',c,True,built=proto.build(cfg,test_mode=True,pad_ops=201-tb['ops']))
    return out


def replay(lines, name):
    bad, core = consensus.run_cchk(lines)
    assert bad == [] and core == 'unexpected results: 0', (bad,core)
    dst = HERE/name
    dst.mkdir(exist_ok=True)
    bad, lean = consensus.run_lean(lines, dst)
    assert bad == [], (bad,lean)
    assert f'{len(lines)} vectors, 0 disagree with Core, 0 outside the model' in lean, lean
    return dict(vectors=len(lines),core=core,lean=lean)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--seeds',type=int,default=3)
    ap.add_argument('--honest-samples',type=int,default=300)
    args=ap.parse_args()
    report={'gadget':replay(gadget_vectors(),'gadget_vectors'),'tiers':{}}
    print('gadget',report['gadget'],flush=True)
    search=json.loads((HERE/'search_results.json').read_text())
    for name,row in search['tiers'].items():
        winner=row['candidates'][0]
        cfg=winner['cfg']
        prod,tb=proto.build(cfg),proto.build(cfg,test_mode=True)
        assert not checks.limits(prod['script'])[1]
        assert not checks.limits(tb['script'])[1]
        assert not checks.twin(prod['script'],tb['script'])[1]
        safe=q.design_check(prod)
        assert safe == [], safe
        a=q.analyse(cfg,P[cfg['hash']],prod)
        audits=[]
        lines=full_vectors(name,cfg,random.Random(2026))
        with proto.prototype_spender():
            for seed in range(args.seeds):
                r=audit.run_audit(cfg,tb,prod,a,random.Random(2000+seed),budget_random=3000,log=lambda *a:None)
                assert r['ok'], {k:v for k,v in r.items() if k!='samples'}
                lines+=consensus.realised_audit_lines(f'{name}_seed{seed}',tb,r['samples'],random.Random(seed),n_acc=40,n_rej=40)
                audits.append({k:v for k,v in r.items() if k!='samples'})
                print(name,'audit',seed,'runs',r['runs'],'ok',r['ok'],flush=True)
            honest=audit.honest_space(cfg,tb,random.Random(404),samples=args.honest_samples)
            assert honest['ok'], honest
        evidence=replay(lines,f'{name}_vectors')
        report['tiers'][name]=dict(candidate=winner,designer_check=safe,audits=audits,
                                  honest_space=honest,replay=evidence)
        # Submit reviewable byte artifacts through the repository mechanism track.
        (HERE/f'{name}_candidate.json').write_text(json.dumps(dict(
            mechanism='spacer_selection',cfg=cfg,production_script=prod['script'].hex(),
            test_script=tb['script'].hex(),estimate=winner,
            status='proposal; not accepted by frozen ranked judge'),indent=2)+'\n')
        (HERE/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
        print(name,evidence,flush=True)


if __name__=='__main__':
    main()
