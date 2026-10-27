# GPU-priority research

## 2026-10-27 — scope and baseline

User objective: reduce GPU-hours at the two highest security-menu tiers, allowing
larger transactions. Targets are D and E, preserving their classical, quantum,
and collision security, not merely the challenge's 80-bit admissibility floor.

Base: `2263cd305ab31c9e8e538ab3d1ec617d232f42e3`.
The public qsb.fast CUDA competition is closed as of this inspection. This
checkout instead provides local data-only ranked submissions and a mechanism
proposal route. No benchmark.json or Yukon-linked QSB benchmark is present.

Recomputed with the untouched builder, analyser, and frozen GPU cost table:

| Tier | Classical | Quantum | Collision | GPU-hours | Ops | Script bytes |
|---|---:|---:|---:|---:|---:|---:|
| D | 111.798930 | 49.814503 | 78.421321 | 5.845836 | 201 | 9472 |
| E | 116.176141 | 52.003108 | 82.627231 | 6.040779 | 200 | 9551 |

These conservative judge times are distinct from the older 4.81/5.22-hour
stage-measurement estimates in SECURITY_MENU.md. Comparisons must use the same
cost basis.

Hypothesis: the fee-oriented challenge search misses GPU-efficient combinations
of bonus selections, larger pools, and longer chains. First search this space
explicitly with GPU-hours as the objective; then evaluate the best candidates
with the unmodified judge. This is a bounded baseline experiment, not a claim
that parameter changes can exceed the DER hash-work floor.

Core's libbitcoinconsensus and the existing Lean library both built successfully.
The cryptographic soundness theorem in Lean currently covers TS2 only; D/E
remain audited families. Do not label them fully formally proved.

## User clarification and explicit time target

The user clarified that all work and submissions belong in this repository.
The external competition's status is irrelevant to this task. They then asked
for **under two GPU-hours**, preferably **under thirty minutes**, at both upper
tiers. This is the outstanding objective. The current results below are
intermediate progress, not completion. Account for total work, not elapsed
wall-clock time divided across GPUs, and distinguish GPU models and estimates.

## Completed experiments and local submissions

- Deterministic GPU-first search: seed 20261027, 500,000 mutation steps per tier,
  1,200 finalists rebuilt. All three security axes constrained to the corresponding
  original tier. Final candidates contain no bonus selections.
- `gpu_d_0`: deep accepted; 5.329748 model GPU-h, 115.176 / 51.503 / 82.692 bits,
  10,934 total vB. Audit: 85,038 runs / 3 seeds, 1,000 honest samples, 264 Core/Lean
  vectors and byte-identical Lean rebuild.
- `gpu_e_0`: deep accepted; 5.573731 model GPU-h, 116.842 / 52.129 / 83.101 bits,
  10,893 total vB. Audit: 84,354 runs / 3 seeds, 1,000 honest samples, 259 Core/Lean
  vectors and byte-identical Lean rebuild.
- Both join the split (vB, GPU-h, bits) frontier. Neither joins the default
  fee-weighted frontier. Nominal reductions against frozen-model D/E: 8.83%/7.73%.
- Early n141 E candidate rejected by the test-script 10,000-byte limit; replaced
  with n140. Preserve the rejected report as experiment history.
- Verified a bonus-space overcount: seven signed/bonus partitions produce one
  identical puzzle input. All seven stand-in spends pass Core. D's E1 drops from
  5.319436 to 0.759919 for the legitimate distinct-dummy search. Corresponding
  retry-model time is 7.429422 h. The frozen judge remains unchanged; proposals
  and a reproducible counterexample are under `mechanisms/gpu_priority/`.
- Implemented destructive chain selection (ROLL instead of PICK) in an isolated
  prototype. Saves one cleanup opcode per odd round-chain length. 1,032 vectors
  pass Core and agree with Lean. A generic local stack-equivalence lemma checks
  with only propext/Quot.sound, without sorry or compiled evaluation. Its best
  examples are still above five hours. The E example is slower than the ranked
  E submission. This mechanism is a proposal, not a promoted or fully proved family.

## Remaining research requirement

No under-two-hour or under-thirty-minute upper-tier construction has been
demonstrated. No new GPU measurements or full production-puzzle solves were run
in this session. The frozen rates provide the current numerical estimates.
At existing measured compression rates, three independent DER hits already cost
about two hours before EC and retries; this does not prove an impossibility for
new predicates, faster kernels, or other constructions. Future work must test
such changes rather than present more small parameter gains as meeting the goal.

## DER pattern count and GPU-budget certificate

Hypothesis: an exact enumeration of the DER length patterns and an optimistic
relaxation of the frozen GPU table can determine whether any parameter choice,
including mixed puzzle hashes, could meet the requested two-hour budget.
Inspection found that `qsb_pool.p_der(L)` includes `len_R = L - 7`, which makes
`len_S = 0`. Core, the local Python predicate, the Lean interpreter, and the CUDA
predicate reject that pattern. Reproduce the discrepancy outside trusted files,
then report both the frozen-model bound and the corrected-probability bound.

Result: the discrepancy is confirmed. The 20-byte predicate has 12 valid
integer-length patterns, not 13; the 32-byte predicate has 24, not 25. Expected
attempts increase by 8.3279% and 4.1653%, respectively. The independent Python
predicate checks all 65,792 one-/two-byte integer prefixes; 552 concrete
positive/negative pattern vectors pass Core and agree with Lean. Local Lean
lemmas prove nonempty S, the length endpoint, and a cleared-denominator retry
inequality without sorry or native_decide. Trusted files remain untouched.

Recomputing the two accepted, bonus-free designs with exact DER probability
gives **5.566873 GPU-h for gpu_d_0** and **5.845655 GPU-h for gpu_e_0**. Both still
meet all three respective security thresholds. Previous 5.329748/5.573731 values
are historical frozen-model estimates; they are not the corrected estimates.

An exact-rational optimistic relaxation of the entire frozen RTX 4090 rate
table gives **2.668940 GPU-h** for three stages after correcting probability
(2.463761 with the frozen probability). It independently chooses each stage's
best shape/hash, ignores size/op limits and extra sighash work, and assumes no
retries. Therefore parameter tuning or mixed hashes within that cost model
cannot meet two hours. This is not a universal bound on new predicates,
constructions, kernels, or hardware. The earlier compression-only illustrations
also used the erroneous probability and must not be treated as exact bounds.

Artifacts: `mechanisms/der_budget/{check.py,results.json,vectors.txt,Proof.lean,PROPOSAL.md}`.
No new GPU measurement or ranked submission was made for this accounting
finding. The requested under-two-hour and under-thirty-minute upper-tier
solutions have not yet been demonstrated.

## Spacer selection hypothesis

A new independent-round layout replaces separate C/D arrays with triplets
`D_i, 0, C_i` (bottom to top). After rolling C_i and verifying its preimage,
the same numeric index should roll D_i: the consumed index copy accounts for
the one-item spacer. This removes the ADD opcode per HORS selection. A permanent
zero sentinel below each region anchors the MIN bound despite arbitrary removal
orders. Regions and secrets remain separate between rounds. Test the stack
identity, arbitrary orders and adversarial indices before claiming unchanged
freedom counts or evaluating longer chains. This is not the previously rejected
shared-dummy construction, and it does not by itself evade the DER time bound.

Result: implemented under `mechanisms/spacer_selection/`. Core and Lean agree
on 3,032 focused selector vectors and 313 whole-script vectors per upper-tier
candidate (3,658 total). A local Lean theorem proves the pairing/removal identity
for arbitrary surrounding lists with only propext/Quot.sound. The intentionally
broken no-bound variant accepts witness-supplied fake pairs; the intact MIN
rejects them. This validates that the safety bound cannot simply be dropped.

Three-seed freedom audits pass: 65,352 D runs and 65,592 E runs. Honest-space
audits pass 300 samples per tier; production designer checks and static/twin
checks pass. No full-family soundness proof or trusted Lean builder is claimed.

The layout saves 14 selection opcodes in the two seven-selection rounds.
Combined with the earlier destructive chain selector, it fits chain lengths
2/4/5 in 200 opcodes. Exact rebuilt candidates (corrected DER probabilities):

| Tier | Hash | n / k | GPU-h estimate | Classical / quantum / collision | Bytes / test bytes / stack |
|---|---|---|---:|---|---|
| D | SHA-256 | 129 / 96 | 4.253431 | 113.556305 / 50.193190 / 82.226848 | 9717 / 9948 / 924 |
| E | SHA-1 | 135 / 64 | 4.759079 | 117.695523 / 52.555280 / 84.033726 | 9749 / 9980 / 928 |

Estimated reductions against the previous corrected best audited candidates:
23.59% D, 18.59% E. D preserves the D thresholds rather than every excess bit of
gpu_d_0; E improves all three modeled axes over gpu_e_0. The longer interleaved
sighash suffixes are charged in these estimates. Exact-layout GPU measurements
and a production search renderer remain outstanding. No production puzzle hit
or under-two-hour solution is claimed.

The proposal, exact script-byte candidates, vectors, local proof, search and
audit reports are submitted through the repository's mechanism track. This is
a new selection construction, still within the three-DER-hit family and its
conditional time bound. The user's request for a fundamentally faster puzzle
remains the active objective; do not redefine it as these smaller gains.
