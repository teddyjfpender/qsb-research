# Spacer selectors: a new independent-round script layout

The prototype removes one opcode from every HORS selection without sharing
secrets or dummy regions between rounds. The released byte artifacts are a
**mechanism-track proposal**, not a ranked submission or a fully proved D/E
family. They still use the existing DER predicate. Exact-layout RTX 4090
measurements now project **4.412697 GPU-hours at tier D and 4.498099 at tier E**.
The original 4.253431/4.759079 estimates were broadly supported but are
superseded by these measured-rate projections. Neither is a completed
production solve. The user's two-hour and thirty-minute targets remain unmet.
See [CLOSEOUT.md](CLOSEOUT.md) for the measured submission and research closure.

## The trick and stack effect

For each round, replace separate commitment/dummy arrays with the following
region, shown bottom to top:

```
Z=0  D[n-1] 0 C[n-1]  ...  D[1] 0 C[1]  D[0] 0 C[0]
```

`C[a]=HASH160(pre[a])` is 20 bytes; `D[a]` is the original 9-byte dummy
signature. The zeros cost one byte and no counted opcode. `Z` is a permanent
boundary marker and is never removed. The witness carries the same preimages,
indices, nonce keys and dummy keys as before, with differently encoded indices.

At each selection, let `x` be the depth of C[a] while the original x is on the
stack. The gadget is:

```
<depth of x> ROLL
<depth of Z minus 1> MIN
DUP ROLL
<depth of preimage> ROLL HASH160 EQUALVERIFY
ROLL
```

The first ROLL consumes the duplicate of x and moves C[a] to the top. After
authentication consumes C[a] and the preimage, the last ROLL consumes the
original x and selects D[a]. The spacer makes those two numeric indices equal.
Both C[a] and D[a] disappear; the zero between them remains. Other triplets
remain intact, so this works in any selection order, including after earlier
removals. No ordering check or parity check is needed.

More precisely, with lists written top first, the region has shape
`front ++ [C, spacer, D] ++ suffix`. Its commitment is at index `len(front)`.
The witness index is `len(front)+1` because one copy of it remains above the
region during the first ROLL. Erasing C leaves D at that same witness index.
The resulting region is `front ++ [spacer] ++ suffix`. `Proof.lean` proves this
generic list identity for arbitrary front/suffix lists and values.

The absolute witness index for original position a at selection i is

```
index_base[i] + 3*a - 2*count(previously selected positions smaller than a).
```

`build.py` derives each base and bound from its symbolic stack. Its spender
implements that formula. The bound uses Z rather than the deepest remaining
commitment: selecting the last position must not make a future bound reach
into another round or into attacker-controlled witness data.

## Why the attacker choices should remain the same

This is a local gadget argument plus adversarial evidence, not a claim that
the full frozen `SelectionSound` statement has been proved for this family.

For an in-region selection, the HASH160 check must match an unconsumed
commitment. Dummies and zeros have the wrong length. Opening an unexposed
commitment is the existing BadHashEvent. Once a known commitment matches, the
stack identity forces selection of its paired dummy; no dummy substitution is
available through a different ordering. A repeated selection fails because its
commitment was removed. The two rounds have independent regions and secrets.

MIN bounds the first selector above the permanent sentinel. Thus it cannot
reach the next round below the region, signed-index commitments below the
regions, or witness-supplied fake commitment/dummy pairs. Above the region,
previously revealed HORS commitments have already been removed. Selecting an
unrevealed commitment or matching some other 20-byte value remains an existing
BadHashEvent. Witness preimages lie below the region, so rolling a preimage
does not change the spacing inside a selected triplet.

An explicit negative control replaces MIN with DROP. Then a witness-supplied
commitment can authorize an unrelated witness-supplied dummy. Core and Lean
accept that attack on the deliberately broken gadget and reject it when the
bound is intact. Removing the bound is not a proposed optimization.

FindAndDelete still removes exactly the selected minimal dummy pushes. The
interleaved zeros and 20-byte commitment pushes do not add matching signature
pushes. Nonce pools, key encodings, signed indices and hash-chain selectors keep
their previous semantics. The candidate estimates therefore use the existing
`S_i` counts, including the leftover pin-chain nonce choices. All probabilities
use the corrected DER pattern count from `../der_budget/`.

The candidates also use the previously tested destructive chain selector from
`../destructive_chain/`, which consumes the selected hash and saves one cleanup
opcode on odd round-chain lengths.

## Cost and candidates

Selection changes from nine to eight gadget opcodes, or from eleven to ten
including the later dummy-key ROLL and CHECKMULTISIG key charge. The layout adds
one zero per position and one sentinel per round, while removing the old ADD
and its constant push for each selection. It increases the initial stack by
`R*n + R` items. Actual scripts must still fit the 1,000-item and 10,000-byte
limits; bytes are not treated as unbounded.

Interleaving also increases the suffix rehashed for each round. The estimates
charge those additional SHA-256 blocks using the frozen cost model. The new
proposal-local GPU renderer has since measured all four exact round layouts,
including their interleaved commitments. It is a benchmark/search kernel for
these layouts, not a complete production spending pipeline. The old fixed
round-problem renderer remains unchanged.

Deterministic search: seed 20261028, 100,000 mutation steps per tier, 500
finalists rebuilt per tier. This is a search for good candidates, not a global
optimality proof. Constraints preserve all three baseline-tier security axes
recomputed with the corrected DER probability. No bonus selections are used.

| Tier | Hash | n / pool / round bounds | Chains: pin / r1 / r2 | Original model GPU-h | Classical / quantum / collision bits |
|---|---|---|---|---:|---|
| D | SHA-256 | 129 / 96 / 96,96 | 2 / 4 / 5 | **4.253431** | 113.556305 / 50.193190 / 82.226848 |
| E | SHA-1 | 135 / 64 / 64,64 | 2 / 4 / 5 | **4.759079** | 117.695523 / 52.555280 / 84.033726 |

Both use seven authorized selections per round, all three key encodings,
pool-first layout, and unsigned nonce indices and levels.

| Tier | Counted ops | Production bytes | Stand-in bytes | Maximum symbolic stack |
|---|---:|---:|---:|---:|
| D | 200 | 9,717 | 9,948 | 924 |
| E | 200 | 9,749 | 9,980 | 928 |

In the original model comparison, relative to the corrected estimates for the current audited candidates
`gpu_d_0` (5.566873 h) and `gpu_e_0` (5.845655 h), these are **23.59%** and
**18.59%** less expected GPU work. D preserves its tier thresholds, not every
higher security number of `gpu_d_0`. E improves all three modeled security axes
over `gpu_e_0`. Those percentages compare historical model estimates, not fresh
measurements of both designs. The new measurement and its limitations follow.

## Exact-layout GPU validation and closeout

One RTX 4090, CUDA 12.8, driver 595.91.07, 450 W cap; three 20-second real-DER
measurements per stage, with subset ranges spread across each round's space.
Median rates (billions of attempts/second) are D: 8.3138 / 9.2656 / 9.3952;
E: 16.281 / 20.763 / 21.244. The corrected DER probability and existing retry
model give 4.412697 / 4.498099 expected GPU-hours. Applying a 5% rate allowance
to each stage's slowest repeat gives 4.656597 / 4.739034 hours; this allowance is
not a statistical confidence interval or guaranteed completion time.

Across 12 reduced-difficulty runs, 3,464 hits were recorded without duplicates
within each run. Independently sampled CPU checks verified 2,954 hits and
rejected all 2,954 altered-sign controls. All encodings and chain levels were
represented. The CPU stream model also passed 412 exact FindAndDelete cases.
No full production DER solve was performed. The scripts and their existing
security audit status are unchanged. Raw runs, inputs, source digests and the
reproducible report are in `gpu_validation/`.

The measured mechanism proposal is retained for review, and this research pass
is closed at the user's request. It is not ranked or promoted. No under-two-hour
construction or proof of global optimality is claimed. The rented pod was
terminated after the artifacts were retrieved.

## Validation and submission artifacts

- **3,032 gadget vectors** cover every nonempty active-set state of five
  triplets, all five possible known preimages, indices across and beyond the
  region, integer edges, and the broken-bound control.
- **313 whole-script vectors per tier** include random honest spends, endpoint
  subsets, reversed orders, wrong preimages, repeated selections, bad indices,
  level bounds, production non-hits, 201/202-op boundaries, and realized
  accepted/rejected adversarial witnesses.
- **All 3,658 vectors pass Core and agree with Lean**, with none outside the
  interpreter model. Stand-in puzzle hashes are used for positive whole-spend
  vectors; no production DER puzzle solve is claimed.
- Freedom audit: three seeds per tier, **65,352 D runs and 65,592 E runs**.
  Neither exceeds its claimed choices. These audits are evidence, not exhaustive
  proofs over arbitrary witnesses.
- Honest-space audit: **300 samples per tier**, all accepted and distinct.
- Production `design_check` reports no unsafe dummy/commitment items for either
  candidate. Static checks and production/stand-in twin checks pass.
- The local Lean pairing theorem uses only `propext` and `Quot.sound`, without
  `sorry` or `native_decide`. Full-family soundness and a trusted Lean builder
  have not been added.

Reproduce from the repository root:

```
python3 challenge/mechanisms/spacer_selection/search.py --steps 100000 --finalists 500
python3 challenge/mechanisms/spacer_selection/check.py --seeds 3 --honest-samples 300
cd lean
lake env lean ../challenge/mechanisms/spacer_selection/Proof.lean
```

`D_candidate.json` and `E_candidate.json` contain exact production and stand-in
script bytes, configurations and clearly labeled estimates for mechanism-track
review. `validation.json` records the audits and replay results. The frozen
builder, judge, analyser, Lean model and Core harness are unchanged. The
proposal has not been promoted into the design language or ranked leaderboard.

This establishes a useful new selection construction. It does not establish
the fundamentally cheaper puzzle needed to meet the requested time budget:
the three-DER-hit bound from `../der_budget/` still applies under the frozen
rate model.
