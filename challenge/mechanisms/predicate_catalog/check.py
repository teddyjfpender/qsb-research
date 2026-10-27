#!/usr/bin/env python3
"""Core probes for candidate legacy hash-output predicates and false shortcuts.

These are predicate tests, not production puzzle solutions. Synthetic DER,
all-zero and negative-zero values do not claim known hash preimages.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(ROOT/'challenge')]
from qsbcore import (G, der9, enc, hash160, is_valid_der, mul, push_min, push_nonmin,
                     push_num, recover, ser_tx, sighash_all)
from judge import checks, consensus
from challenge.mechanisms.der_budget.check import exact_probability

OP = {'IF':0x63,'NOTIF':0x64,'ELSE':0x67,'ENDIF':0x68,'DROP':0x75,
      'DUP':0x76,'DEPTH':0x74,'SWAP':0x7c,'SIZE':0x82,'EQUAL':0x87,
      'EQUALVERIFY':0x88,'CHECKSIG':0xac,'CHECKSIGVERIFY':0xad,
      'CHECKMULTISIG':0xae,'HASH160':0xa9,'SHA256':0xa8,'NOT':0x91}


def op(*names):
    return bytes(OP[n] for n in names)


def truthy(b):
    return any(b[:-1]) or bool(b and b[-1] not in (0,0x80))


def der_of_length(n):
    r,s=b'\x01',bytes([1])*(n-8)
    return bytes([0x30,n-3,2,len(r)])+r+bytes([2,len(s)])+s+b'\x01'


def main():
    lines, modeled, counts = [], [], Counter()
    tx=ser_tx([(bytes(32),0,b'',0)],[(1,b'\x51')],0,version=2)

    def emit(group,name,script,expected,transaction=None):
        line=f'{group}_{name} {script.hex()} {(transaction or tx).hex()} 0 {int(expected)}'
        lines.append(line)
        counts[group]+=1
        # Full Core is authoritative. Replay only the frozen Lean-supported
        # opcode subset, and explicitly report the remaining Core-only cases.
        if not checks.limits(script)[1]:
            modeled.append(line)

    unary={'1ADD':0x8b,'1SUB':0x8c,'NEGATE':0x8f,'ABS':0x90,'NOT':0x91,'0NOTEQUAL':0x92}
    binary={'ADD':0x93,'SUB':0x94,'BOOLAND':0x9a,'BOOLOR':0x9b,'NUMEQUAL':0x9c,
            'NUMNOTEQUAL':0x9e,'LESSTHAN':0x9f,'GREATERTHAN':0xa0,
            'LESSTHANOREQUAL':0xa1,'GREATERTHANOREQUAL':0xa2,'MIN':0xa3,'MAX':0xa4}
    rng=random.Random(20261029)
    sample_counts={}
    for length in (20,32):
        examples=[bytes(length),bytes(length-1)+b'\x80',b'\x01'+bytes(length-1),
                  bytes([255])*length,der_of_length(length)]
        examples += [rng.randbytes(length) for _ in range(16)]
        sample_counts[length]=len(examples)
        for j,x in enumerate(examples):
            tag=f'L{length}_{j}'
            for name,code in unary.items():
                emit('numeric_unary',tag+'_'+name,push_min(x)+bytes([code])+op('DROP')+push_num(1),False)
            for name,code in binary.items():
                for side in (0,1):
                    a,b=(x,b'\x01') if side==0 else (b'\x01',x)
                    emit('numeric_binary',tag+'_'+name+str(side),
                         push_min(a)+push_min(b)+bytes([code])+op('DROP')+push_num(1),False)
            emit('numeric_within',tag,push_min(x)+push_num(0)+push_num(1)+b'\xa5'+op('DROP')+push_num(1),False)
            for name,code in [('PICK',0x79),('ROLL',0x7a)]:
                emit('numeric_index',tag+'_'+name,push_num(1)+push_min(x)+bytes([code]),False)
            for name,code in [('CLTV',0xb1),('CSV',0xb2)]:
                emit('numeric_timelock',tag+'_'+name,push_min(x)+bytes([code])+op('DROP')+push_num(1),False)
            emit('size',tag,push_min(x)+op('SIZE')+push_num(length)+op('EQUALVERIFY','DROP')+push_num(1),True)
            emit('depth',tag,push_min(x)+op('DEPTH')+push_num(1)+op('EQUALVERIFY','DROP')+push_num(1),True)
            emit('boolean_false',tag,push_min(x)+op('IF')+push_num(0)+op('ELSE')+push_num(1)+op('ENDIF'),not truthy(x))
            emit('boolean_true',tag,push_min(x),bool(truthy(x)))
            emit('equal_fixed_zero',tag,push_min(x)+push_min(bytes(length))+op('EQUAL'),x==bytes(length))
            emit('equal_self',tag,push_min(x)+op('DUP','EQUAL'),True)
            # A 20/32-byte hash in the pubkey slot is not a usable ECDSA key.
            emit('hash_as_pubkey',tag,push_min(der9(1,1,1))+push_min(x)+op('CHECKSIG','NOT'),True)
            emit('der_gate',tag,push_min(x)+push_num(1)+op('CHECKSIG','DROP')+push_num(1),is_valid_der(x))
            # NOT does not catch a strict-DER script error.
            emit('der_not_catch',tag,push_min(x)+push_num(1)+op('CHECKSIG','NOT'),is_valid_der(x))
            # Both calls have m=n=2. The invalid first pubkey makes the first
            # valid signature fail, so the loop stops before inspecting x.
            keys=push_num(2)+push_min(enc(G))+push_num(1)+push_num(2)
            tail=op('CHECKMULTISIG','DROP')+push_num(1)
            emit('cms_skips_hash',tag,push_num(0)+push_min(x)+push_min(der9(1,1,1))+keys+tail,True)
            emit('cms_checks_hash',tag,push_num(0)+push_min(der9(1,1,1))+push_min(x)+keys+tail,is_valid_der(x))
            # A witness may always duplicate an unconstrained digest; equality
            # only becomes a hard predicate if its comparison target is bound.
            script=op('SHA256','EQUAL')
            msg=rng.randbytes(33)
            ss=push_min(hashlib.sha256(msg).digest())+push_min(msg)
            etx=ser_tx([(bytes(32),0,ss,0)],[(1,b'\x51')],0,version=2)
            emit('equal_witness',tag,script,True,etx)

    # Positive numeric controls distinguish a real length limit from a malformed
    # test template. Nonminimal zero encodings up to four bytes are consensus-valid.
    for length in range(7):
        x=bytes(length)
        for name,code in unary.items():
            emit('numeric_controls',f'{name}_{length}',push_min(x)+bytes([code])+op('DROP')+push_num(1),length<=4)
        for name,code in binary.items():
            emit('numeric_controls',f'{name}_{length}',push_min(x)+push_num(1)+bytes([code])+op('DROP')+push_num(1),length<=4)
        for name,code in [('CLTV',0xb1),('CSV',0xb2)]:
            emit('timelock_controls',f'{name}_{length}',push_min(x)+bytes([code])+op('DROP')+push_num(1),length<=5)

    disabled={'CAT':0x7e,'SUBSTR':0x7f,'LEFT':0x80,'RIGHT':0x81,'INVERT':0x83,
              'AND':0x84,'OR':0x85,'XOR':0x86,'2MUL':0x8d,'2DIV':0x8e,
              'MUL':0x95,'DIV':0x96,'MOD':0x97,'LSHIFT':0x98,'RSHIFT':0x99}
    for name,code in disabled.items():
        emit('disabled',name,push_min(b'a')+push_min(b'b')+bytes([code])+push_num(1),False)
        emit('disabled_skipped',name,push_num(0)+op('IF')+bytes([code])+op('ENDIF')+push_num(1),False)

    # Concrete two-transaction counterexample to replacing the puzzle by equality
    # against a witness-provided digest. Keep the hashlock preimage unchanged.
    secret=bytes.fromhex('3d'*20)
    sig=der9(1,1,1)
    script=(op('HASH160')+push_min(hash160(secret))+op('EQUALVERIFY')+
            op('DUP')+push_nonmin(sig)+op('SWAP','CHECKSIGVERIFY','SHA256','EQUAL'))
    spent=[]
    for who,point in [('owner',G),('different_recipient',mul(2,G))]:
        output=b'\x76\xa9\x14'+hash160(enc(point))+b'\x88\xac'
        ins=[(bytes.fromhex('7a'*32),0,b'',0xffffffff)]
        outs=[(1000,output)]
        z=sighash_all(ins,outs,0,script)
        key=enc(recover(1,1,z,0))
        digest=hashlib.sha256(key).digest()
        ss=b''.join(push_min(v) for v in (digest,key,secret))
        full=ser_tx([(ins[0][0],0,ss,0xffffffff)],outs)
        emit('free_target_forgery',who,script,True,full)
        spent.append(dict(recipient=who,transaction=full.hex(),output_script=output.hex(),
                          pubkey=key.hex(),digest=digest.hex(),sighash=str(z)))
    assert spent[0]['sighash']!=spent[1]['sighash']

    payload='\n'.join(lines)+'\n'
    (HERE/'core_vectors.txt').write_text(payload)
    r=subprocess.run([str(consensus.CCHK)],input=payload,capture_output=True,text=True,check=True)
    assert r.stdout.count('PASS')==len(lines) and r.stdout.splitlines()[-1]=='unexpected results: 0',[
        line for line in r.stdout.splitlines() if line.startswith('FAIL') or line.startswith('unexpected')]
    lean_dir=HERE/'lean_vectors'
    lean_dir.mkdir(exist_ok=True)
    bad,summary=consensus.run_lean(modeled,lean_dir)
    assert bad==[] and f'{len(modeled)} vectors, 0 disagree with Core, 0 outside the model' in summary,(bad,summary)
    report=dict(scope='Finite predicate probes and local lemmas, not exhaustive synthesis or an impossibility proof.',
                core_vectors=len(lines),core_summary=r.stdout.splitlines()[-1],
                lean_vectors=len(modeled),core_only_vectors=len(lines)-len(modeled),lean_summary=summary,
                by_group=dict(counts),samples_per_hash_length=sample_counts,
                probability_classes=[dict(length=n,numeric_acceptance=0,size_entropy_bits=0,
                    fixed_equality_probability=f'1/{256**n}',boolean_false_probability=f'2/{256**n}',
                    der_probability=str(exact_probability(n))) for n in (20,32)],
                concrete_free_target_counterexample=spent,
                sources=['https://raw.githubusercontent.com/bitcoin/bitcoin/v26.0/src/script/interpreter.cpp',
                         'https://raw.githubusercontent.com/bitcoin/bitcoin/v26.0/src/script/script.h',
                         'https://robinlinus.com/binohash.pdf',
                         'https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/main/paper/QSB.pdf',
                         'https://mirror.b10c.me/lists/bitcoindev/ZjzFtus_aBchwKz2@camus/t/'])
    (HERE/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='concrete_free_target_counterexample'},indent=2))


if __name__=='__main__':
    main()
