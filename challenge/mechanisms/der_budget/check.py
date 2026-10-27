#!/usr/bin/env python3
"""Exact DER-pattern count and a conditional frozen-kernel time certificate.

Read-only with respect to the trusted builder/analyser/judge. Output goes here.
This is not a new puzzle, a measured GPU run, or a general impossibility proof.
"""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'challenge')]
import qsb_pool as q
from qsbcore import OP, is_valid_der, push_min, push_num, ser_tx
from judge import cost, design


def integer_probability(length):
    if length < 1:
        return Fraction(0)
    return Fraction(1, 2) if length == 1 else Fraction(255, 512)


def exact_probability(length):
    if not 9 <= length <= 73:
        return Fraction(0)
    # Six fixed bytes: sequence tag/length and two integer tags/lengths.
    # The final sighash byte is unrestricted by the DER-only check.
    return sum((Fraction(1, 256**6) * integer_probability(r) *
                integer_probability(length - 7 - r)
                for r in range(1, length - 7)), Fraction(0))


def signature(r, s, flag=1):
    length = len(r) + len(s) + 7
    return bytes([0x30, length - 3, 2, len(r)]) + r + bytes([2, len(s)]) + s + bytes([flag])


def test_patterns():
    lines = []
    tx = ser_tx([(bytes(32), 0, b'', 0xffffffff)], [(1, b'\x51')], 0)

    def emit(label, sig, expected):
        assert is_valid_der(sig) == expected, (label, sig.hex())
        script = (push_min(sig) + push_num(1) + bytes([OP['OP_CHECKSIG'], OP['OP_DROP']])
                  + push_num(1))
        lines.append(f'{label} {script.hex()} {tx.hex()} 0 {int(expected)}')

    for length in (20, 32):
        for r in range(length - 6):
            s = length - 7 - r
            for flag in (0, 1, 3, 0x80, 0xff):
                sig = signature(bytes([1])*r, bytes([1])*s, flag)
                assert len(sig) == length
                emit(f'L{length}_r{r}_s{s}_flag{flag}', sig, r > 0 and s > 0)
        # Exercise the integer-prefix cases underlying the probability count.
        for r in range(1, length - 7):
            s = length - 7 - r
            for which in ('r', 's'):
                n = r if which == 'r' else s
                cases = [('zero', bytes(n), n == 1),
                         ('positive', b'\x7f' + bytes(n-1), True),
                         ('negative', b'\x80' + bytes(n-1), False)]
                if n >= 2:
                    cases += [('needed_padding', b'\x00\x80' + bytes(n-2), True),
                              ('redundant_padding', b'\x00\x7f' + bytes(n-2), False)]
                for label, val, expected in cases:
                    rb, sb = bytes([1])*r, bytes([1])*s
                    if which == 'r':
                        rb = val
                    else:
                        sb = val
                    emit(f'L{length}_r{r}_{which}_{label}', signature(rb, sb), expected)

    # Exhaust all 256 one-byte and 65,536 two-byte prefixes, using the actual
    # independent Python DER predicate. Longer integers have unrestricted tails.
    counts = []
    for n in (1, 2):
        accepted = sum(is_valid_der(signature(x.to_bytes(n, 'big'), b'\x01'))
                       for x in range(256**n))
        assert Fraction(accepted, 256**n) == integer_probability(n)
        counts.append(dict(length=n, accepted=accepted, total=256**n))

    payload = '\n'.join(lines)+'\n'
    path = HERE / 'vectors.txt'
    path.write_text(payload)
    core = subprocess.run([str(ROOT/'consensus_check/target/release/cchk')],
                          input=payload, capture_output=True, text=True, check=True)
    assert core.stdout.count('PASS') == len(lines), core.stdout
    assert core.stdout.splitlines()[-1] == 'unexpected results: 0', core.stdout
    lean = subprocess.run([str(ROOT/'lean/.lake/build/bin/qsbcheck'), str(path)],
                          capture_output=True, text=True, check=True)
    summary = f'{len(lines)} vectors, 0 disagree with Core, 0 outside the model'
    assert summary in lean.stdout, lean.stdout
    return dict(core_vectors=len(lines), core_summary=core.stdout.splitlines()[-1],
                lean_summary=summary, exhaustive_integer_prefixes=counts)


def budget(table, probability):
    rows = []
    for stage in ('pin', 'rnd'):
        for hsh in ('sha256', 'sha1', 'rmd'):
            pts = [r for r in table['rates'] if r['stage'] == stage and r['hash'] == hsh]
            best = max(pts, key=lambda r: r['rate'])
            p = probability(32 if hsh == 'sha256' else 20)
            rate = Fraction(str(best['rate'])) * Fraction(str(table['noise_margin']))
            hours = 1 / p / rate / 3600
            rows.append(dict(stage=stage, hash=hsh, best_measured_shape=best,
                             hours=float(hours), exact_hours=str(hours)))
    pin = min((r for r in rows if r['stage'] == 'pin'), key=lambda r: Fraction(r['exact_hours']))
    rnd = min((r for r in rows if r['stage'] == 'rnd'), key=lambda r: Fraction(r['exact_hours']))
    bound = Fraction(pin['exact_hours']) + 2 * Fraction(rnd['exact_hours'])
    assert bound > 2
    return dict(stage_bounds=rows, three_stage_lower_bound_hours=float(bound),
                exact_three_stage_lower_bound=str(bound),
                maximum_two_stage_classical_bits=2*max(
                    math.log2(1/float(probability(n))) for n in (20, 32)),
                speedup_needed_even_in_relaxation={
                    'two_hours': float(bound / 2), 'half_hour': float(bound * 2)})


def accepted_candidates(table):
    rows = []
    for name in ('gpu_d_0', 'gpu_e_0'):
        _, cfg = design.load(ROOT/'challenge/submissions'/name/'design.json')
        built = q.build(cfg)
        assert not any(built['bs']), 'bonus accounting is a separate finding'
        vals = {}
        for label, p in [('frozen', q.p_der(32)), ('corrected', float(exact_probability(32)))]:
            P = math.log2(1 / p)
            a = q.analyse(cfg, P, built)
            h, rates = cost.gpu_hours(cfg, built, a, P, table)
            vals[label] = dict(hours=h, security=a, stage_rates=rates)
        rows.append(dict(name=name, estimates=vals))
    return rows


def main():
    table = cost.load_table()
    patterns = []
    for n in (20, 32):
        p = exact_probability(n)
        old = Fraction(q.p_der(n))
        erroneous = Fraction(1, 256**6) * Fraction(255, 512)**2
        assert old - p == erroneous
        # Check all supported lengths, not just the two hash-output lengths.
        assert len(list(range(1, n-7))) == n-8
        patterns.append(dict(length=n, valid_patterns=n-8,
                             formula_patterns=n-7, exact_probability=str(p),
                             frozen_probability=str(old), exact_bits=math.log2(1/float(p)),
                             frozen_bits=math.log2(1/float(old)),
                             attempt_inflation=float(old/p),
                             valid_integer_lengths=[[r, n-7-r] for r in range(1, n-7)],
                             three_hit_rate_needed_billion_per_second={
                                 'two_hours': float(3/p/7200/10**9),
                                 'half_hour': float(3/p/1800/10**9)},
                             rejected_extra_pattern=dict(len_r=n-7, len_s=0),
                             rejected_example=signature(bytes([1])*(n-7), b'').hex()))
    for n in range(9, 74):
        assert exact_probability(n) > 0
        assert math.isclose(q.p_der(n) - float(exact_probability(n)),
                            float(Fraction(1, 256**6) * integer_probability(n-7) * Fraction(255, 512)),
                            rel_tol=1e-12)
    report = dict(
        scope='Conditional cost-model certificate, not a universal puzzle lower bound.',
        patterns=patterns,
        validation=test_patterns(),
        frozen_model=budget(table, lambda n: Fraction(q.p_der(n))),
        corrected_probability=budget(table, exact_probability),
        accepted_candidates=accepted_candidates(table),
        reference_sha256=hashlib.sha256((ROOT/'challenge/judge/rates.json').read_bytes()).hexdigest())
    (HERE/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
