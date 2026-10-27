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
