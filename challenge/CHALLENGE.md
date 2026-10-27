# QSB design challenge (autoresearch)

**Goal.** Map, and keep pushing, the trade-off between the **cost** of a quantum-safe Bitcoin spend
(QSB) and its **security**.

**What gets scored.** A fixed judge turns each design into a **result vector**:

| component | meaning | direction |
|---|---|---|
| `sats` | total cost of an honest spend: on-chain fees for the locking script and the spend, plus GPU time for the puzzle search, at frozen prices | lower is better |
| `preimage_bits` | 2nd-preimage security, the primary security axis | higher is better |
| `quantum_bits`, `collision_bits` | quantum-query and collision security | reported; `--dims all` uses them |
| `bits_confidence` | `proven` when a frozen Lean soundness theorem covers the design's family, otherwise `audited` | shown on the board |

**No scalar mixes cost and security.** Designs are compared by **Pareto dominance**: A beats B only
if it costs no more *and* gives no fewer bits.

**Why it's hard to cheat.**
- A submission is data only: one small JSON file in a fixed design language. It runs no code and
  carries no claims.
- The judge builds the script itself and computes security itself. It audits that security number
  against an adaptive attacker and checks every verdict against Bitcoin Core.
- Cost comes from frozen measurements, not models the submission controls.

## Result vector and admissibility

**Admissibility floors** only exclude toys. Above them, security is scored, not banded:
- 2nd-preimage ≥ 80 bits;
- quantum ≥ 32;
- collision ≥ 60;
- in every round, the honest spender must expect at least 1 solution per pinned transaction.

**Cost:**

  sats = total vB × 5 sat/vB + RTX 4090 GPU-hours × 690 sats/h

- **Total vB** = production script + honest scriptSig + 60 vB of transaction overhead.
- **The GPU price** assumes $0.69 per 4090-hour at $100k/BTC.
- **Constants** are frozen in `judge/constants.json`. Every report also gives the cost at 1, 5, 20
  and 50 sat/vB.
- `leaderboard.py --dims split` gives the frontier over (vB, GPU-hours, bits), which doesn't depend
  on the fee rate at all.

**Why bits aren't a band any more.**
- With bands, a design with more security at the same cost earned nothing, and every design crowded
  just above a threshold.
- As a vector:
  - a design at 100 bits for 30k sats is a real result;
  - "the cheapest design with ≥ b bits" can be read off the board for any b;
  - a loop can't trade hidden security for a better score.
- **The flip side:** now that bits are rewarded directly, any overstatement pays. So the security
  count is audited on every run, and the board shows whether each point's bits are `proven` or only
  `audited`.

## The board: a Pareto frontier

- **The board** is the set of deep-verified designs nothing dominates, over (sats, preimage bits).
  An exact tie goes to the earlier run.
- **A submission improves the board** iff no deep-verified design dominates it. `run_ranked.sh`
  prints this for every accepted run.
- **Pending entries** are standard runs that would join the frontier. `run_batch.sh deep-pending`
  deep-verifies all of them in parallel.
- **Why deep verification replaces an improvement margin.** Results are deterministic (same design,
  same vector under every seed; tested), so there's no noise for a margin to absorb. What can be
  wrong about a frontier point is:
  - an audit that was lucky with its sampling, which deep mode addresses with 3 audit seeds, 10x
    perturbations, 1,000 honest samples and 3x realised Core vectors;
  - a rate-table entry a few percent optimistic for that exact shape. The organizer re-measures
    frontier designs on a GPU (`tools/measure_design.py`).
- **Progress summaries,** for tracking only and never for comparing two designs:
  - the cheapest deep-verified design at ≥ 85, 90, 100, 110, 116, 120 and 128 bits;
  - the hypervolume the frontier dominates.

**Current release: `qsb-judge-3`.** Spacer D/E are integrated into the trusted
builder, Lean port and ranked judge. Their measured-rate projections are
4.413/4.498 hours; conservative scored costs are 4.657/4.739 hours. See the
[release notes](judge/releases/qsb-judge-3.md) for schema fields, proof limits,
measurement provenance and versioned leaderboard behavior. Current rows come
only from runs revalidated under the new manifest.

**Historical board** (judge `qsb-judge-2`). There were 38 deep-verified frontier designs, all found by
`tools/optimize.py` (569 screens, 35 min). Excerpt:

| sats | 2nd-pre bits | confidence | GPU-h | vB | design |
|---|---|---|---|---|---|
| **16,327** | 82.45 | audited | 2.29 | 2,949 | SHA-1, n=48, pool 16, pinning chain 8, unsigned, all encodings, t=13, m=8 |
| 17,524 | 85.15 | audited | 3.34 | 3,044 | SHA-256, n=48, pool 8, signed j, t=13, m=8 |
| 19,198 | 90.04 | audited | 3.39 | 3,372 | SHA-1, n=56, pool 8, signed j+level, all encodings, t=12, m=4 |
| 20,520 | 91.62 | audited | 3.05 | 3,683 | SHA-1, n=56, pool 16, signed j+level, compressed, t=12, m=8 |
| **53,563** | 115.18 | audited | 7.08 | 9,735 | SHA-256, n=116, pool 96, 2 rounds t=7/7, chains 2/3 |
| 55,264 | 116.18 | audited | 7.75 | 9,983 | SHA-256, n=120, pool 96, 2 rounds, k=48/96 |
| 58,819 | 120.15 | audited | 7.82 | 10,685 | SHA-256, n=130, pool 96, 2 rounds, second round t=8, k=16 |

**What the vector view shows that a banded scalar hid:**
- **Security comes in stage-sized steps.** Two stages top out at about 92 bits. A third stage adds
  about 25–35 bits at once, so the frontier jumps from 91.6 bits at 20.5k sats to 115.2 bits at
  53.6k. Nothing in between is on the frontier.
  - The cheapest design with at least 100 bits costs 2.8x the cheapest with at least 90.
  - **A mechanism that gives a cheap "partial" third stage would fill that gap.** That is an open
    target for the mechanism loop.
- **Bits below 90 are cheap.** At 82–88 bits the frontier is SHA-1 unsigned designs at 16–18k sats.
- **Every frontier point is `audited`.** The only `proven` family (TS2) is dominated: 51k sats for
  83.7 bits (`leaderboard.py --proven`). The proof loop's most valuable targets are therefore the
  frontier's families:
  - unsigned and signed rounds with chains and all encodings (M4);
  - 2-round designs (M5).
- **GPU promotion check:** re-measured on an RTX 4090 for two frontier designs. Every stage ran
  4.7–6.3% faster than the table priced it (`gpu/results7/rtx4090/promo_measured.jsonl`), so the
  cost side is conservative.

The judge's GPU-hours are deliberately conservative. They use the grid-cell minimum and a 0.95
margin, charge for extra sighash rehashing, and include retries. So they sit a little above the
optimistic figures in SECURITY_MENU.md (E: 6.04 h here vs 5.22 h there).

## What you submit

A directory containing exactly one file, `design.json`, of at most 4 KiB:

```json
{"schema": "qsb-design-v2", "hash": "sha256",
 "n": 64, "k": 16, "pool_deep": true, "force_comp": true, "chain_pin": 8,
 "sign_j": true, "sign_lvl": true,
 "rounds": [{"t": 11, "b": 0, "k": 16, "chain": 8}]}
```

| field | meaning | range |
|---|---|---|
| `hash` | puzzle hash opcode | `sha256` / `rmd` (RIPEMD-160) / `sha1` |
| `n` | dummies and HORS commitments per round | 4–300 |
| `k` | nonce-signature pool size | 1–300 |
| `pool_deep` | pool-first layout | bool |
| `force_comp` | rounds accept compressed keys only | bool |
| `chain_pin` | hash-chain length in pinning | 1–16 |
| `sign_j`, `sign_lvl` | HORS-sign the round's pool index / chain level (needs `pool_deep`) | bool |
| `rounds[i].t` | signed dummy selections | 1–40 |
| `rounds[i].b` | unsigned bonus selections | 0–2 |
| `rounds[i].k` | pool bound for the round | 1–min(`k`, 96) |
| `rounds[i].chain` | hash-chain length in the round | 1–16 |

Other rules:
- Schema `qsb-design-v3` additionally requires `selection_layout` (`split` or
  `spacer`) and Boolean `destructive_chain`. Spacer layouts require `pool_deep`,
  unsigned indices/levels and no bonus selections. New layouts need exact GPU
  measurements; the original grid is not silently reused for them.
- There are 1 or 2 rounds.
- `t + b ≤ n/2` in every round. This is the layout condition the Lean soundness proof needs.
- **Rejected on sight:** unknown keys, missing keys, wrong types, booleans used as numbers, floats,
  and any claimed metric.

The judge picks every random value itself (dummy signatures, HORS preimages, test transactions,
audit sampling) from a seed drawn after the submission is fixed.

## The judge: eight gates

A design is scored only if every gate passes. `python3 -m judge <dir> --seed N` runs them in order
and writes a JSON report with each gate's evidence.

The judge was exercised by a 33-case red-team suite (`tests/redteam.py`, results in
`tests/redteam_results.json`). It covers every format cheat, every gate violation, and deliberately
broken analysers, builders and interpreters, which must all be caught. All 33 behave as required.

| # | gate | what it establishes |
|---|---|---|
| 0 | **integrity** | every trusted file matches `judge/MANIFEST.sha256`. A modified judge refuses to score in ranked mode. |
| 1 | **schema** | the submission is well-formed data in the design language. Claims are never read. |
| 2 | **build** | the judge builds the production and test-mode scripts itself (`qsb_pool.build`). |
| 3 | **static** | Core's limits, recomputed from the bytes by the judge's own parser. **Twin check:** the test-mode script equals the production script except that each puzzle hash is replaced by `OP_DROP <fixed DER>`, so every run on the test-mode script says something about the deployed bytes. `design_check()` passes. |
| 4 | **security** | the frozen analyser (`qsb_pool.analyse`) computes 2nd-preimage, quantum and collision bits and E_i. They must clear the admissibility floors; above them they are the scored security part of the result vector. |
| 5 | **audit** | **freedom audit:** an adaptive attacker with exactly the attacker's real knowledge must not have more choices than the analyser's S_i in any stage. **Honest-space audit:** the choices behind E_i must really be accepted and distinct. |
| 6 | **consensus** | three checks: (a) honest spends, negative vectors, and *realised audit runs* (attacker runs made concrete with real recovered keys) are replayed in Bitcoin Core (libbitcoinconsensus) and the Lean model, and every verdict must agree; (b) the Lean builder must rebuild the same bytes; (c) Lean is mandatory in ranked mode. |
| 7 | **cost** | GPU-hours come from the frozen table of measured 4090 rates, looked up conservatively. Bytes come from the production script and the judge-built honest scriptSig. |

### Why each gate exists (threat model)

| way to cheat or fail | what stops it |
|---|---|
| claiming a security or cost number | the design language has no field for one; the judge computes everything |
| running code, reading or writing files, touching the judge | submissions are one data file copied into a fresh read-only directory; ranked runs check the manifest and record its digest |
| a design whose attacker has more choices than the security count assumes | **freedom audit** (gate 5); Lean soundness theorem for the families it covers |
| a design the analyser mishandles (feature interactions) | the freedom audit measures real choices on the judge-built script. Its first run found a real analyser gap (below). |
| overstating the honest spender's search space to lower the cost | **honest-space audit** (gate 5) |
| a gap between the judge's interpreter and Core | every audit verdict class is replayed in Core with real keys. A disagreement is reported as a judge fault, never scored. An honest spend the judge rejects but Core accepts is reported as `judge-error`, not blamed on the submission. |
| a gap between the Python builder and the verified model | the Lean builder must produce identical bytes; Lean replays every vector against Core |
| the test-mode script differing from what's deployed | twin check (gate 3) |
| gaming the GPU cost model | rates are measured, not modelled (360 shapes on an RTX 4090). A grid shape takes its measured rate; an off-grid shape takes the minimum over the corners of its grid cell. Both get a 0.95 margin; measured non-monotone dips are at most 6%. Extra sighash rehashing is charged per block. Shapes outside the grid are rejected. |
| precomputation or seed games | the seed is drawn after submission; the score doesn't depend on the seed (tested) |
| exploiting measurement noise | none in-loop: scores are deterministic functions of the design |
| changing the judge in the agent's workspace | the agent's sandbox must not have write access to `challenge/judge`, `qsb_pool.py`, `qsbcore.py`, `trace.py`, `lean/` or `consensus_check/`. `run_ranked.sh` records the manifest digest. The leaderboard ranks only runs under the published digest; set `QSB_JUDGE_DIGEST` in the runner to pin it. |

### What's proven, what's tested, and the remaining risk

- **Proven (Lean):**
  - the script semantics model and the builder's bytes;
  - the HORS gadget;
  - FindAndDelete facts;
  - the static op bound;
  - full selection soundness (`ts2_family_sound`) for the TS2 family.

  The judge's report says whether a design is in a proven family.
- **Tested on every submission:**
  - the freedom and honest-space audits;
  - Core and Lean replay of about 100 vectors, including realised attacker runs;
  - a byte-identical Lean rebuild.
- **Remaining risk.** For designs outside a proven family, the freedom audit is strong evidence,
  not proof. It sweeps every witness slot over its full range, tries every key encoding, opens every
  revealed commitment adaptively, and samples multi-slot perturbations. A freedom that only appears
  in a rare multi-slot combination could still be missed. Two things bound this risk:
  - the design language only combines organizer-built features, each exercised by the red-team suite;
  - the Lean proof is being extended to chains, signed indices and 2 rounds (FORMAL_VERIFICATION.md,
    M4/M5). Each extension moves families from "audited" to "proven".

### The audit already paid for itself

On its first run, the freedom audit found a case the analyser undercounted. In designs with an
unsigned round pool index and a pinning hash chain, the pinning chain's leftover levels stay on the
stack. The pinning hit among them is a valid DER signature, and the round's nonce pick can reach
it: one extra attacker option per level. `analyse()` now counts it. This lowered menu tiers C and D
by 0.1–0.4 bits; signed-index designs are unaffected. This is exactly the class of mistake
(a feature interaction in the security count) that an autoresearch loop would otherwise find and
exploit.

## The research process: two loops

1. **Inner loop, automatic, no LLM** (`tools/optimize.py`). It maps the design language's whole
   cost/security frontier:
   - enumerates 1- and 2-round designs;
   - buckets them by estimated bits;
   - screens the proxy-cheapest few per bucket with the judge's own `--mode screen` (same result
     vector as a ranked run, tested);
   - then local-searches every one-step neighbour of every frontier point until the frontier stops
     moving, which gets it off the grid.

   Each frontier design is written as a submission. `run_batch.sh` ranks them in parallel, and
   `run_batch.sh deep-pending` promotes them. No LLM time goes on parameter tweaks.
2. **Outer loop, LLM research agent** (`AGENT.md`). Its job is new *mechanisms*, since the design
   language is searched out. It works through the mechanism track (`MECHANISMS.md`):
   - proposal and human review of the security reduction;
   - provisional evaluation from bytes only: the judge never runs proposal code in-process, and
     derives stages, P, attacker knowledge and slot types from the bytes;
   - promotion into the design language with a builder, a Lean port and proof, analyser support,
     and red-team cases. After that, the inner loop explores the mechanism automatically.

3. **Proof loop** (LLM agent + Lean). It turns `audited` bits into `proven` ones. The objective
   verifier is the Lean kernel checking a **frozen statement**, which is the least gameable verifier
   in the project:
   - **Targets.** The organizer freezes one target per design family:
     `∀ p rnd, Side_F p rnd = true → SelectionSound p rnd`.
     - `SelectionSound` is the frozen statement in `lean/QSB/Soundness.lean`.
     - `Side_F` is an organizer-written side condition.
     - `lean/check.sh` pins both by hash.
   - **No vacuous side conditions.** A side condition can't be made trivially false: the organizer's
     check also evaluates `Side_F` to `true` on every board design of the family (`native_decide`),
     as `ts2_family_sound` is instantiated for the real TS2 spend today.
   - **What a submission is:** Lean files under `lean/QSB/` that prove the target.
   - **Acceptance:** `lean/check.sh` passes, meaning:
     - the frozen statements are unchanged;
     - no `sorry` and no new axioms;
     - `native_decide` appears only in per-instance side checks, never in family theorems.
   - **Effect:** every board design in the family gets `bits_confidence: proven`.
   - **Next targets:** M4, the TS4/A1/L family and the current 2-round t90 frontier designs (chains,
     signed indices, all encodings); then M5, 2 rounds (FORMAL_VERIFICATION.md).

**Every run's report gives the loop somewhere to go next:**
- the gate and reason for any rejection, with evidence (for example the counterexample witness);
- `diagnostics.headroom`: slack in ops, bytes, bits and E, which shows the binding constraint;
- `cost_split`: fees vs GPU;
- `sats_at_other_fee_rates`.

**Modes:**
- `screen`: about 1 s, unranked.
- `standard`: ranked, about 40 s.
- `deep`: promotion, a few minutes.

## What the loop can change, and what it can't

**The loop can change:** any combination of the design language's fields, meaning the space of
QSB designs the verified builder can produce. This covers:
- pool sizes, bounds and layouts;
- hash choice;
- chain lengths;
- signing;
- the number of rounds, selections and bonus selections.

**New mechanisms go through the mechanism track, not the loop.** Examples: a new gadget, a new
predicate, a different sighash trick. A mechanism enters the design language only when it has all
of these:
1. a builder extension in `qsb_pool.py` and a byte-identical Lean port (`lean/QSB/Build.lean`);
2. an analyser extension, with its freedom counts argued in SECURITY_PROOF.md;
3. a Lean proof, or a documented extension of the frozen soundness statement, for the new family;
4. red-team cases that break the new mechanism on purpose and show the judge notices;
5. new rate measurements if it introduces a new stage shape;
6. a new judge release with a regenerated manifest, which resets the leaderboard version.

## Running it

```bash
# once: build the ground truths
(cd research/consensus_check && cargo build --release)     # Bitcoin Core consensus library
research/lean/check.sh                                       # Lean model, proofs, qsbcheck binary

# develop (does not refuse on manifest changes)
cd research/challenge
python3 -m judge baselines/L_lean --seed 1 --dev

# screen a design in ~1 s (unranked), or search the whole design language
python3 -m judge submissions/example --mode screen --dev
python3 tools/optimize.py --out submissions/front       # maps the whole frontier
./run_batch.sh standard submissions/front_*               # rank them in parallel

# ranked (fresh dir, seed drawn after submission, manifest enforced, result recorded); --deep to promote
./run_ranked.sh submissions/example
./run_ranked.sh submissions/example --deep
./run_batch.sh deep-pending          # promote everything that would join the frontier
python3 leaderboard.py               # the frontier, cheapest-at-b-bits, hypervolume
python3 leaderboard.py --dims split  # fee-rate-independent frontier over (vB, GPU-h, bits)
python3 leaderboard.py --history     # every design ever run, any verdict

# promotion GPU check: re-measure the leader's exact stage shapes on an RTX 4090
python3 tools/measure_design.py plan submissions/<name>/design.json > ../gpu/measure.sh
python3 tools/measure_design.py compare submissions/<name>/design.json ../gpu/measured.jsonl

# the judge's own test: every cheat attempt and every deliberately broken model must be caught
python3 tests/redteam.py
```

**An autoresearch agent** follows `AGENT.md`: screen, then rank, then promote, and log every
experiment. New ideas go through `MECHANISMS.md`.

## Organizer operations

- **Re-measuring rates:**
  1. `gpu/sweep7.sh` on an RTX 4090, output to `gpu/results7/rtx4090/`;
  2. `tools/build_rates.py`;
  3. `tools/make_manifest.py`;
  4. publish the new digest.
- **Any change to a trusted file:** the red-team suite and `lean/check.sh` must pass before
  `tools/make_manifest.py` is run.
- **Pinned files:** `tools/make_manifest.py` lists them: the judge, rates, constants, builder,
  analyser, interpreter helpers, Lean frozen statements, and the Core harness sources.
