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

## Alternative-predicate investigation

Previous turn classified as progress: the spacer-selector implementation,
proof, byte artifacts and audits are committed at e5477f3. The active work now
targets a fundamentally cheaper transaction-binding predicate. Rechecked the
original QSB/Binohash papers, Heilman's original Lamport/size discussion and
Core 26's interpreter: no new qualifying construction was found in those
sources. Hypothesis to test: another enabled legacy byte-inspection operation
may provide a tunable, cheaper predicate on transaction-bound hash outputs.
Build consensus probes and local lemmas for the numeric, boolean, equality,
size and signature paths, including lazy CHECKMULTISIG. Scope is deliberately
limited to those paths; do not turn failure to find a predicate into a universal
impossibility claim.

Outcome: 2,146 Core probes pass, including arithmetic/size/boolean/equality,
pubkey parsing, strict-DER errors, lazy multisig and disabled-opcode controls.
The 695 cases supported by the frozen Lean opcode subset all agree with Core;
1,451 cases are explicitly Core-only. Seven local Lean lemmas check with only
propext/Quot.sound. A concrete weak alternative (comparing the recovered key's
hash against an unconstrained witness digest) permits two script-valid spends
paying different recipients with the same revealed hashlock secret. No cheaper
secure predicate was found in these tested families. Artifacts are under
`mechanisms/predicate_catalog/`.

## Research closeout at the user's request

The user asked to close the work if no further useful construction could be
found. We are stopping this research pass because there is no credible
identified route to the requested time target under the current constraints.
This is a judgment about the available research paths, **not** a proof that the
global frontier has been reached. Do not mark the original objective achieved.

Best new mechanism estimates remain 4.253431 GPU-h (D) and 4.759079 GPU-h (E),
with the stated local proofs and audits under `mechanisms/spacer_selection/`.
They are unranked proposals without new exact-layout GPU measurements. The
existing deep-accepted candidates estimate at 5.566873/5.845655 GPU-h after the
DER probability correction. No verified sub-two-hour or sub-thirty-minute
upper-tier construction was produced. All generated work is local; no new GPU
resources were rented, and no transactions or external submissions were sent.

## Bounded spacer timing validation (user-requested closeout, 2026-10-27)

Hypothesis: the 4.253431 h D and 4.759079 h E spacer estimates survive a
fresh RTX 4090 measurement of the actual production script layouts. Build a
proposal-local renderer, compare its sighashes and reduced-difficulty GPU hits
with the independent CPU implementation, measure the real DER gate, and either
retain supported estimates or replace/reject them. Finish with a mechanism
submission and explicit closure; do not reopen the construction search.

Outcome: completed exact-layout measurements on one RTX 4090 (CUDA 12.8,
driver 595.91.07, 450 W). Three real-DER runs per stage measured median rates
D 8.3138/9.2656/9.3952 G attempts/s and E 16.281/20.763/21.244 G attempts/s.
With corrected DER probabilities and the unchanged retry model, projected
means are **4.412697 h D / 4.498099 h E**, versus the old 4.253431/4.759079.
The old estimates were broadly supported: D optimistic by 3.74%, E conservative
by 5.48%. Slowest repeats with a 5% rate allowance yield 4.656597/4.739034 h;
this is a planning allowance, not a confidence interval or deadline guarantee.

Validation: 412 exact CPU stream cases; 3,464 reduced-difficulty GPU hits,
2,954 independently re-derived samples passing, zero altered-sign control
passes, all encodings/levels represented, no within-run duplicates. Source and
input hashes match the GPU host. The existing Core/Lean and security-audit
artifacts still apply to byte-identical scripts. No full production DER solve
was attempted or claimed. Timed GPU work was 425.75 seconds, with 445.89 seconds
for the benchmark driver including setup. The one newly rented pod was deleted;
the subsequent pod list was empty. Authentication stayed in the local Runpod
configuration outside this repository.

At the user's request, also reviewed Zagitta/gpu-unlock and
JustAResearcher/gpu-unlock-ada. Their tensor speedups do not map to the existing
integer QSB kernels: the compiled round kernel contains no tensor instructions.
No unlock was installed or benchmarked; this is an instruction-path assessment,
not an unlocked A/B result. Sources and inspected revisions are in
`mechanisms/spacer_selection/CLOSEOUT.md`.

Final disposition: retain the measured **local mechanism-track submission**,
unranked and with full-family soundness still unproved. Close this research
pass. Neither the two-hour nor thirty-minute objective was achieved; no global
optimality claim is made. `CLOSEOUT.md`, updated candidates and proposal, CUDA
renderer, raw measurements and `gpu_validation/report.json` complete the work.

## Owner-requested ranked promotion (judge 3)

The owner explicitly requested the remaining trusted builder, Lean, analyser,
rate-table and ranked-leaderboard integration. This authorizes an organizer
release beyond the ordinary solver sandbox; no existing historical acceptance
is relabeled and no frozen security theorem is weakened.

Implemented `qsb-design-v3` while retaining v2 input support. Spacer selection
and destructive round-chain cleanup now live in the trusted Python and Lean
builders. The published seed-1 bytes match exactly; two independent build seeds
per candidate pass the Lean byte checker. The new full-family proof target
explicitly includes residual pin-chain nonce signatures, and remains unproved:
ranked labels stay `audited`. Original TS2 family proofs still compile.

The judge now imports no proposal code. Exact rates are frozen from the 18
real-DER GPU repeats, keyed by all semantic layout parameters; other new
shapes are unmeasured and rejected. Scores use the existing conservative policy:
D 4.657 h and E 4.739 h. Both the JSON and leaderboard also show the 4.413/4.498 h
median-rate projections. The DER empty-integer probability bug and the bonus
union overcount are corrected globally for this new release.

Promotion regressions passed 160 Core/Lean vectors, schema and measurement
rejection controls, and whole-builder mutations removing MIN or HORS checks.
Seven crashed/truncated-verifier controls also pass. The full Lean regression
passes 75 byte-identical builds and 658 consensus replays, including the prior
real production spend; no new axioms or sorry proofs were added. Deep-ranked
results and the final manifest are recorded in `judge/releases/qsb-judge-3.json`.

Final deep runs under manifest `ffb31e8bd64490dd` accepted both spacers and
revalidated `gpu_d_0` / `gpu_e_0` for comparison. D/E freedom audits cover
101,352 / 101,592 runs, with 1,000 honest samples and 264 Core/Lean vectors each.
All gates passed. The two spacers are the current revalidated frontier;
historical runs retain their original manifest. The 36 existing red-team cases
also passed. All three original D/E tier thresholds remain met after both
counting corrections. This completes the requested ranked integration; the
under-two-hour construction goal remains unmet, without an optimality claim.
