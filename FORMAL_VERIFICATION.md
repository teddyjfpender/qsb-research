# Formal verification of QSB in Lean 4

`research/lean/` is a Lean 4 project (core Lean, no Mathlib) that works as a regression gate for the
QSB design. It has three parts:

1. **A model of Bitcoin legacy script.** It covers the opcode subset QSB emits and follows Core's
   rules under libbitcoinconsensus flags. The model comes with machine-checked proofs about the
   QSB gadgets and the tier scripts.
2. **A Lean port of `qsb_pool.build`.** The checker proves that the port produces the same bytes
   as Python for 65 builds.
3. **An executable interpreter with its own SHA-256, SHA-1, RIPEMD-160 and secp256k1.** It
   replays every consensus vector and must agree with Bitcoin Core on all 658 of them.

Run it:

```bash
research/lean/check.sh        # ~2 min; exits non-zero on any failure
```

Toolchain: `leanprover/lean4:v4.28.0` (pinned in `lean-toolchain`, fetched by elan).

## What is verified now

### Proved in Lean (no `sorry`; `check.sh` prints the axioms)

| theorem | statement |
|---|---|
| `numDec_numEnc` | CScriptNum decoding inverts encoding, for every integer. |
| `hors_gadget` | Exact effect of the HORS selection gadget on **any** stack and **any** witness `x`. The gadget is `<dx> ROLL <B> MIN DUP <c1> ADD ROLL <dpre> ROLL HASH160 EQUALVERIFY ROLL`. If it succeeds: `v = min(x, B) >= 0`; the item at `v + c1 - 1` (the commitment) equals `HASH160` of the item at `dpre - 2` (the preimage); both are removed; the item at `v` (the dummy) ends on top; 9 ops are counted. |
| `hors_select` | Applies on the builder's region layout: `A` items above the region, then the `m` remaining dummies, then their `m` commitments. A successful selection either (a) opens position `j`'s commitment and moves position `j`'s dummy to the top, for some `j < m`; or (b) opens a HASH160 preimage of an item *above* the region at index `m ≤ i < A`, which is only possible when `A > m`. Nothing is assumed about the items above the region. It also covers the degenerate "index 0 re-rolls the number" case: `EQUALVERIFY` then compares a 20-byte hash with a script number of at most 5 bytes. |
| `plan_in_region` | For the 2-stage tiers (A, B, A-SHA1, TS4, and the real TS2 script), `A ≤ m` at every selection, so only case (a) exists. The (A, m) plan is also checked against Python's. |
| `three_stage_round2_reaches_above` | For tiers C, D and E, round 2 has `A > m`, so case (b) is reachable in principle (see Findings). |
| `pushMin_not_prefix_pushdata1` | A minimal-push FindAndDelete pattern never matches at a `PUSHDATA1` opcode. This is why pool signatures survive. |
| `findAndDelete_id'` | FindAndDelete is the identity when the pattern occurs at no GetOp boundary. The model follows Core's algorithm exactly, including matches that span opcodes. |
| `run_opcount`, `no_opcount_failure` | The 201-op limit is static. Suppose every `CHECKMULTISIG` is preceded by its key-count push (`cmsPreceded`) and `staticOps ≤ 201`. Then no execution can fail on the op count, for any witness and any crypto. |
| `limits_sound`, `poolSafe_sound` | Generic bridges from the executable checks to the statements above. |
| `all_tiers_ok`, `tier{A..E}_limits`, `tierASha1_limits`, `ts4_limits`, `realTs2_limits` | Checked for each production script (tiers A–E, the SHA-1 variant of A, TS4, and the script of the real TS2 spend): size ≤ 10,000 bytes; it parses; it uses only modelled opcodes; `staticOps ≤ 201` and equals Python's op counter. |
| `tierA/E_within_limits` | The readable form for tiers A and E: at most 10,000 bytes, and no execution can hit the op limit. |
| `tierA/E_pool_never_deleted`, `all_tiers_ok` | For every pool index `i < k`, FindAndDelete of `P_i` leaves the script unchanged. So the round sighash is the same whichever pool signature is used. |
| `tiers_dummies_exact` | For every dummy of tiers A–E and A-SHA1, FindAndDelete removes exactly one push. |

### Checked by execution on every run of `check.sh`

- **Builder equality** (`qsbcheck --scripts`). The Lean `Build.build` is a line-by-line port of
  `qsb_pool.build`, and receives Python's randomness as input.
  - It must reproduce Python's script bytes, op count and max symbolic stack for 65 builds: 13
    designs × 5 variants (production, test mode, real-round puzzle, `pad_ops`, `pad_bytes`).
  - The Core op-count rule, applied to the parsed bytes, must equal Python's counter.
  - Result today: **65/65 identical**. The `REAL_TS2` export is byte-identical to `real/script.hex`,
    the script of the real spend.
- **Consensus replay** (`qsbcheck <vectors>`). The Lean interpreter runs with Lean
  implementations of SHA-256, SHA-1, RIPEMD-160, legacy `SignatureHash` and secp256k1 ECDSA
  (libsecp256k1 parsing rules). It must agree with Core's recorded verdict on every vector.

  | vector set | count | agree with Core |
  |---|---|---|
  | edge cases (`lean/edge_vectors.py`, labelled by Core at generation time) | 62 | 62 |
  | mechanism vectors (`gen_vectors.py`) | 114 | 114 |
  | end-to-end (`qsb_pool.py --vectors`) | 131 | 131 |
  | final menu (`final_menu_vectors.txt`) | 118 | 118 |
  | security menu (`security_menu_vectors.txt`) | 232 | 232 |
  | real TS2 spend (GPU-found SHA-256 hits, `real/production_vector.txt`) | 1 | 1 |

  The edge set covers:
  - sighash types, including the SIGHASH_SINGLE bug and ANYONECANPAY;
  - high-S signatures;
  - all pubkey encodings, bad hybrid parity and points off the curve;
  - non-DER signatures aborting even when the result is dropped;
  - FindAndDelete of an embedded signature;
  - the CHECKMULTISIG key order, NULLDUMMY, the 20-key limit and nKeys op counting;
  - an unreached non-DER signature being ignored;
  - the 201-op, 520-byte, 1000-item and 10,000-byte limits, each at and one past the limit;
  - CScriptNum: non-minimal, negative zero, 5-byte operands, overflowing results;
  - ROLL/PICK bounds, CastToBool, DER edge cases and P2SH.

**Mutation checks** (run once by hand to confirm the gate catches real bugs):

| change | caught? |
|---|---|
| Disabling FindAndDelete in the model | yes: 58 vector failures, and the proofs stop compiling |
| MAX_OPS 201 → 202 | yes: 5 failures |
| Ignoring NULLDUMMY | yes: 2 failures |
| Allowing 21 multisig keys | yes |
| Push limit 520 → 521 | yes |
| Stack limit 1000 → 1001 | yes |
| One changed byte, or a changed op count, in a Python build | yes: `--scripts` fails |
| Dropping the low-S normalization | no: this is an *equivalent* mutant, since ECDSA accepts both `s` and `n - s` |

## What is trusted

- **The model's fidelity to Core.** Nothing *proves* the Lean interpreter equals Bitcoin Core's C++.
  The evidence is agreement on 658 Core-labelled vectors, 62 of them written against Core's
  specific edge cases. OP_CODESEPARATOR, witness programs, OP_IF and every opcode outside the
  subset are modelled as `unsupported`. The replay reports those as "outside the model", never as
  a verdict.
- **Crypto.** The proofs treat hashes and ECDSA as abstract parameters, except that `hors_select`
  and `hors_gadget` assume `HASH160` outputs are 20 bytes. The executable SHA-256, SHA-1,
  RIPEMD-160 and secp256k1 code is trusted, tested against hashlib and Core. Cryptographic
  hardness (preimage resistance, the random-oracle model) is not formalised here.
- **`native_decide`.** The per-tier facts are evaluated by compiled code, so they trust the Lean
  compiler (`Lean.ofReduceBool`). The general theorems do not.
- **The security reduction.** The ROM/QROM arguments and the counts `S_i` are in
  `SECURITY_PROOF.md`, on paper. The Lean work establishes the script-level facts those arguments
  rely on, not the probability bounds.
- **Python-only code.** `analyse()`, the cost model and `design_check()` (probabilistic, run by
  the script creator) are not ported. `spend()` is exercised only indirectly, through the vectors.

## Findings while building this

1. **Model gap: P2SH, found and fixed.** A bare `OP_HASH160 <20> OP_EQUAL` scriptPubKey is P2SH
   under Core's flags. The first model disagreed with Core on the edge vector `hash160_value`.
   P2SH is now modelled. QSB scripts are never P2SH-shaped (they are ~9–10 kB), so no QSB result
   changes.
2. **An argument `SECURITY_PROOF.md` should spell out: out-of-region selections in 3-stage tiers.**
   - The selection index is clamped only from above (`MIN`), so an index `x < A` reaches the
     items *above* the region. `hors_select` proves what that allows: the "commitment" opened is
     then one of those items.
   - **2-stage tiers:** at every selection the region is at least as large as what is above it
     (`plan_in_region`: e.g. tier A has A ≤ 25, m ≥ 113). The "commitment" then always lands on a
     9-byte dummy, which a 20-byte hash never equals, so this case is impossible outright.
     - This holds even though tier B and the SHA-1 variant leave 16 twenty-byte pinning-chain
       values above round 1's region (`puzzle(..., cleanup=False)`); they are simply out of reach.
   - **3-stage tiers C, D and E:** round 2's region sits below round 1's *unused* region, so
     A ≈ 250 > m ≈ 130 (`three_stage_round2_reaches_above`). An attacker's round-2 index can then
     target an unused round-1 **commitment**. The attacker would need its HORS preimage, which the
     signer never reveals: the preimages revealed in round 1 belong to commitments already consumed
     in round 1. So the attack needs a HASH160 preimage (2^160) and it is not a weakness.
   - The paper proof and `analyse()` should still state this case explicitly. It relies on the
     secrecy of *all* unrevealed preimages, not only those of the round being attacked.
3. **No divergence between the Python builder and the Lean port.** Bytes, op counts and max
   stack depth all match.

## The soundness theorem (M1–M3 proven)

### The statement (`QSB/Soundness.lean`, frozen)

For every accepting execution of the production script, with **any initial stack** (the attacker's
scriptSig) and **any crypto oracle** (hash functions are parameters; the only assumption is that
`HASH160` outputs are 20 bytes):

```
SelectionSound p rnd :=
  ∀ cr rev W is s', (∀ b, (cr.hash160 b).length = 20) →
    parse (build p rnd).script = some is → run ⟨cr, script⟩ is ⟨W, 0⟩ = .ok s' → accepting s' →
    let evs := trace ⟨cr, script⟩ is ⟨W, 0⟩
    ((evs.filterMap Ev.sigs?).length = p.ts.length ∧
       ∀ r < …, Authorised p rnd rev r (evs.filterMap Ev.sigs?)[r])
    ∨ BadHashEvent cr.hash160 p rnd rev evs
```

- **`trace`** records every CHECKMULTISIG, with its signature list, and every `HASH160` step as
  `heq pre target`. Here `pre` is the hashed item and `target` is the stack item below it, i.e. the
  value the following `EQUALVERIFY` compares against. In QSB scripts every `HASH160` is
  immediately followed by `EQUALVERIFY`, so these are exactly the commitment openings.
- **The round of an event** is the number of multisigs executed before it.
- **`BadHashEvent`:** some recorded `HASH160` output equals its target, but the target is not one
  of the *current round's revealed* commitments. Revealed commitments are HORS positions in
  `rev.hors r`; with signing, also signed-j `CJ` and signed-level `CL` openings. This covers:
  - an unrevealed commitment of any round;
  - a revealed commitment of another round;
  - any non-commitment value, such as a 20-byte hash-chain level.
- **`Authorised r sigs`:** `sigs` is the round's `t_r + b_r` selected dummies (last selected
  first) followed by a nonce. The selected positions are distinct and inside the region; the first
  `t_r` are revealed. The nonce is a pool signature `P_s` with `s ≤ k_r` (and `s` revealed when
  `sign_j`). In the pool-first layout it may also be a region dummy or commitment, the disjunct
  that `design_check()` rules out under real ECDSA.
- **The multisig scriptCode** is not part of the statement: Core computes it from the signature
  list.

**Why the statement changed (step 0).** The earlier form assumed that the witness opens only
revealed HORS commitments, and concluded `Authorised` outright. That form is false or
unprovable in general for two reasons:
- In three-stage designs, round 2's selection index can reach 20-byte items *above* its region,
  including round 1's leftover commitments. If `revealed 0` is larger than `t_0`, a revealed
  round-1 commitment can be opened in round 2.
- The pinning chain's 20-byte levels (RIPEMD-160 or SHA-1 designs) stay on the stack.

The game-hopping form moves every such case into `BadHashEvent`. Bounding its probability is the
paper's job: each event needs a HASH160 preimage or second-preimage of a value the attacker was
not given.

### Milestones

| milestone | status | theorem |
|---|---|---|
| M1: emitted code has the expected shape | **proven** for the TS2 family | `Blocks.parse_encode`: well-formed code items parse back exactly. `Blocks.parse_build_TS2`: `SideTS2 p rnd → parse (build p rnd).script = some ((blocksTS2 p rnd).map CI.instr)` |
| M2: block lemmas with stack-shape invariants | **proven** | `Exec.*`: run/trace composition and a peel lemma per opcode. `Gadget.gadget_spec`: one HORS selection on a *region with holes* (P above, m remaining aligned dummies and commitments, pool, unknown witness suffix), with exact new stack and exact trace. `TS2.loop`: t selections give distinct positions, and each is opened by a recorded HASH160 event. Also `pin_spec`, `pro_spec`, `nonce_cases`, `epi_spec`, `cms_accept`, `cmsLoop_true_ne` |
| M3: full theorem, TS2 family | **proven** | `TS2.ts2_family_sound : SideTS2 p rnd = true → SelectionSound p rnd`. Instances: `TS2Instances.realTs2_sound` (the script of the real spend Core accepted; `check.sh` checks it equals `real/script.hex`) and `ts2_sound` (the vector design) |
| M4: chains, sign_j, sign_lvl (TS4, A, L) | not started | |
| M5: R = 2 (tiers C/D/E) | not started | |

**The TS2 family and `SideTS2`.** The family is: one round, no bonus keys, no chains, no signing,
a forced-compressed round key and the pool-first layout. `SideTS2 p rnd` is a decidable side
condition, checked per instance by `native_decide`. It requires:
- the family shape;
- `(build p rnd).script = encode (blocksTS2 p rnd)`: the symbolic-stack builder emits the closed
  form. This is checked per instance, not proved for all parameters;
- every push well formed;
- `1 ≤ t`, `2t ≤ n`, `k_1 ≤ k`, and all constants < 2^31;
- dummies neither empty nor 20 bytes, and commitments pairwise distinct.

`blocksTS2` gives every depth constant in closed form, e.g. selection `i` rolls its index from
depth `2n + k + t + 1 − 2i`. The proof reasons about the closed form.

**Axioms** (`#print axioms`):

| theorems | axioms |
|---|---|
| `ts2_family_sound`, `gadget_spec`, `loop`, `parse_build_TS2` | `propext`, `Classical.choice`, `Quot.sound` only. No `native_decide` (the two UInt8 facts use kernel `decide`) |
| `realTs2_sound`, `ts2_sound` | the above, plus `Lean.ofReduceBool` and `Lean.trustCompiler`, from the per-instance `native_decide` of `SideTS2` |

`check.sh` enforces this policy.

**Frozen statements.** `QSB/Frozen.lean` restates the exact types of the proven theorems as
`example`s. `FROZEN.sha256` pins that file and every file the statements depend on: `Bytes`,
`Hash`, `Script`, `Build`, `Soundness` and `Blocks`. `check.sh` fails if any pinned file changes
or any statement stops typechecking. So a change to a proof cannot silently weaken what is proven,
and a deliberate change to a statement shows up as a hash update.

### What the proof showed

- **Every selection lands in its region only because `2t ≤ n` in the TS2 family.** At selection
  `i` the items above the region are the `i` earlier dummies, the nonce and NULL (A = i + 2); the
  region holds n − i dummies. With A ≤ m, an index that misses the region makes the "commitment"
  a dummy, which a 20-byte hash never equals. For tiers where A > m can happen, the out-of-region
  opening must be a `BadHashEvent`. That holds for round 2 of C/D/E, where the target is a
  round-1 commitment.
  - **Watch for this in M5:** the nonce slot, which sits above the region, can hold a *commitment*
    (a PICK index into the commitment area). If A > m, an attacker could open a revealed
    commitment of the *current* round that sits above the region. That would be a "good" event
    whose selection is not in the region. M5 has to show this can't happen (by the layout), or
    the round check in `Good` must be tied to the region.
- **An empty nonce (the NULL item) is harmless without any assumption.** CHECKMULTISIG can then
  only return false (`cmsLoop_true_ne`), so the script does not accept.
- **Short or garbage witnesses need no special case.** Every lemma goes from success to shape,
  and a missing witness item makes a ROLL or PICK fail.

### Remaining roadmap

- **M4** (chains, `sign_j`, `sign_lvl`): the chain level is picked with MIN/PICK over m hash
  levels, and signed-j and signed-level add CJ/CL opening gadgets. These are the same kind of
  proof as the selection gadget, with events that are good when opened at a revealed index.
  Needed: closed-form `blocks` for these features, and a `Side` check.
- **M5** (R = 2): compose two rounds. Round 1 ends with CHECKMULTISIGVERIFY, and round 2's region
  sits under round 1's leftovers (A > m). Generalise `gadget_spec` to the above-region case, which
  yields a `heq` whose target is an above-region item; then classify those items.
- **Optional:** prove `build = encode blocks` for all parameters (a refinement proof of the
  symbolic-stack builder) instead of checking it per instance.

## How to use it when changing the design

- **Changing `qsb_pool.build`** (layout, gadgets, new options):
  1. `check.sh` fails at step 4 until `QSB/Build.lean` is updated to match.
  2. Port the change. The failing entry shows the first differing byte.
  3. If the change adds a new gadget, add its semantic lemma next to `hors_gadget`.
- **Adding a tier or changing tier parameters:**
  1. Add it to `DESIGNS` in `lean/export_scripts.py` and to `WANT` in `lean/gen_tiers.py`.
  2. Add a `*_limits` theorem in `QSB/TierProofs.lean`.
  3. The build then *proves* the 10,000-byte and 201-op limits and the pool-signature
     FindAndDelete fact for it, or fails.
- **New vectors.** Any file of `name spk_hex tx_hex idx expect` lines can be replayed with
  `lake exe qsbcheck file.txt`. Add new Core-rule edge cases to `lean/edge_vectors.py`; their
  expected verdicts come from Core.
- **A new opcode.** Extend `Op`/`stepOp` in `QSB/Script.lean`. Until then the replay reports it as
  "outside the model" and `check.sh` fails.

## Layout

| path | what |
|---|---|
| `QSB/Script.lean` | script model: CScriptNum, GetOp, FindAndDelete, BIP66, interpreter, P2SH, static op count |
| `QSB/Hash.lean`, `QSB/Secp.lean`, `QSB/Tx.lean` | executable crypto, tx parsing, legacy sighash, `verifyInput` |
| `QSB/Build.lean` | port of `qsb_pool.build` |
| `QSB/Proofs.lean` | general theorems (gadgets, FindAndDelete, op count) |
| `QSB/Tiers.lean` (generated), `QSB/TierProofs.lean` | the tier scripts' exact inputs and per-tier theorems |
| `QSB/Soundness.lean` | the soundness statement: trace, `Good`/`BadHashEvent`, `Authorised`, `SelectionSound` (frozen) |
| `QSB/Blocks.lean` | M1: code items, parse-of-encoding, closed-form TS2 blocks, `SideTS2` |
| `QSB/Exec.lean`, `QSB/Gadget.lean` | M2: run/trace composition, per-opcode peel lemmas, the selection gadget on a region with holes |
| `QSB/TS2.lean`, `QSB/TS2Instances.lean` | M3: the TS2 family theorem and its instances |
| `QSB/Frozen.lean`, `FROZEN.sha256` | pinned theorem statements |
| `Main.lean` | `qsbcheck`: builder equality (`--scripts`) and consensus replay |
| `export_scripts.py`, `gen_tiers.py`, `edge_vectors.py`, `check.sh`, `vectors/` | glue, generated inputs, gate |
