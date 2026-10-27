# Exact DER patterns and the two-hour budget

This is a reproducible accounting finding and a conditional cost-model
certificate. It is **not a new puzzle or an under-two-hour solution**. It rules
out reaching that target by changing parameters or mixing the existing hashes
while retaining the frozen RTX 4090 rate table and sequential DER-stage model.
It does not rule out a new predicate, a different security reduction, a faster
kernel, or other hardware.

## The pattern-count error

A length-L Bitcoin DER signature, including its final sighash byte, has shape

```
30 (L-3) 02 r [R: r bytes] 02 s [S: s bytes] [sighash byte]
r + s = L - 7; r >= 1; s >= 1
```

The DER-only puzzle leaves the final sighash byte unrestricted. The six
tag/length bytes are fixed for each pair `(r,s)`. An integer of length one has
128 acceptable byte values. For length at least two, there are 32,640 acceptable
first-two-byte prefixes out of 65,536; later bytes are unrestricted. Consequently,

```
f(1) = 1/2
f(l) = 255/512 for l >= 2
p(L) = 256^-6 * sum(f(r) * f(L-7-r), r=1,...,L-8)
```

`qsb_pool.p_der` uses `range(1, L-6)`, including the invalid endpoint
`r=L-7, s=0`. Its helper also assigns a nonzero probability to a zero-length
integer. The valid range is `range(1, L-7)`. The proposal's `exact_probability`
additionally makes the integer probability zero for nonpositive lengths and
enforces the DER signature-length limits. No trusted source is changed.

| Hash output | Valid length patterns | Frozen formula counts | Correct P = log2(1/p) | Extra expected attempts |
|---|---:|---:|---:|---:|
| 20 bytes: SHA-1 / RIPEMD-160 | 12 | 13 | 46.425388 | 8.3279% |
| 32 bytes: SHA-256 | 24 | 25 | 45.425859 | 4.1653% |

`results.json` enumerates every valid `(r,s)` pair and supplies an explicit
rejected example of each erroneous endpoint. Core, the Python predicate, the
Lean interpreter, and inspection of `gpu/pool2.cu:der_ok` all reject empty S.
The CUDA predicate was inspected; no CUDA execution is claimed here.

This is a probability-model error, not evidence of a consensus bypass. Rarer
valid outputs increase the modeled attack work as well as honest work. The
two existing upper-tier submissions still exceed their security thresholds
when evaluated with the corrected probability. Their previous deep reports
remain historical frozen-judge results, not corrected cost estimates.

## The time certificate

For each stage/hash combination, take the fastest measured table entry,
including the judge's 0.95 margin. Ignore the opcode, script-byte and stack
limits, extra sighash blocks, and finite-search failures. Allow each stage to
use its independently best shape and hash, even when those choices cannot fit
together in one script. This is an optimistic relaxation of the frozen model.

Two stages supply at most 92.850776 classical bits even before subtracting
attacker freedoms. Both upper-tier thresholds exceed 111 bits, so this family
needs at least three stages.

If `c0,c1,c2` are the single-hit costs and `p1,p2` the round-success
probabilities, the judge's retry formula simplifies to

```
T = c0/(p1*p2) + c1/p2 + c2 >= c0 + c1 + c2, for 0 < p1,p2 <= 1.
```

The best entries under the corrected probability are both SHA-1:

| Stage | Best table shape | Raw rate | Optimistic single-hit GPU-hours |
|---|---|---:|---:|
| Pin | k64, chain16, 3 encodings | 31.225 G/s | 0.884924 |
| Round | k96, chain16, 3 encodings | 30.977 G/s | 0.892008 |

Their expected-time sum is **2.668940 RTX 4090 GPU-hours**. Even the erroneous frozen
probability gives **2.463761 hours**. `check.py` computes these bounds as exact
rational numbers, scans every table entry, and checks both exceed two hours.
The corner-minimum interpolation cannot exceed the largest measured entry;
extra sighash work and retries cannot improve the bound. No design achieving
either relaxed bound is claimed.

Thus mixed SHA-1/SHA-256 stages cannot meet the target using this table. Further
parameter search is not a route to a sub-two-hour result under this model.

For scale, three 20-byte DER hits need **39.375 G attempts/s** for a two-hour
expected search, or **157.501 G/s** for thirty minutes, with no retry or setup overhead.
For SHA-256 the corresponding rates are **19.694 G/s** and **78.776 G/s**.
These are requirements for the existing three-hit predicate, not performance
predictions or general lower bounds on other puzzles.
Individual lucky searches can finish sooner; these are expected-cost bounds,
not minimum runtimes for every random instance or deadline guarantees.

## Corrected estimates for the audited candidates

Same designs and stage rates; only the DER probability and consequent retry
probabilities change. These are estimates, not newly measured GPU runs.

| Submission | Historical frozen GPU-hours | Corrected GPU-hours | Corrected classical / quantum / collision bits |
|---|---:|---:|---|
| gpu_d_0 | 5.329748 | **5.566873** | 115.352765 / 51.591420 / 82.765262 |
| gpu_e_0 | 5.573731 | **5.845655** | 117.018864 / 52.216951 / 83.177801 |

These candidates have no bonus selections, so the separate signed/bonus union
overcount found under `../gpu_priority/` does not affect this recalculation.

## Validation and reproduction

From the repository root:

```
python3 challenge/mechanisms/der_budget/check.py
cd lean
lake env lean ../challenge/mechanisms/der_budget/Proof.lean
```

- 552 concrete DER-pattern vectors: all expected results in Core; Lean agrees
  on all 552, with none outside its interpreter model.
- All 256 one-byte and 65,536 two-byte integer prefixes checked against the
  independent Python DER predicate.
- Positive/negative integers, required/redundant zero padding, both empty
  integer endpoints, every valid R/S length pair, and five sighash bytes tested.
- The pattern-count discrepancy checked for every permitted length 9 through 73.
- Lean proves that an accepted signature has nonempty S, the valid layout
  endpoint, and a denominator-cleared retry-cost inequality. Two closed integer
  inequalities verify the reported rational bounds exceed two hours.
- No `sorry` or `native_decide`; only Lean's standard logical axioms appear.
  The local lemmas do not constitute a formal derivation of the empirical rate
  table, a full probability proof, or a full D/E security proof.

No new ranked submission is warranted by this finding. The next successful
candidate must change a constraint outside this certificate's scope and then
pass the existing security and consensus checks. The user's two-hour and
thirty-minute targets remain unmet.
