# Order-of-magnitude cheaper QSB spends: nonce-signature pools and a DER-only puzzle check

Status: research note, 2026-09-24. Scope: Avihu Levy's *Quantum-Safe Bitcoin Transactions Without
Softforks* (QSB, [`../avihu-repo`](../avihu-repo)) and the Layr-Labs grinding benchmark ([`../layr`](../layr)).

## TL;DR

Two changes to the QSB locking script make an honest spend cheaper at the same or higher
second-preimage security. Neither needs a soft fork, and both were checked against Bitcoin Core's
own script interpreter (libbitcoinconsensus).

- **Measured** with the tuned `gpu/pool2.cu` kernel, every hit re-derived on the CPU, against
  Layr's tuned kernels running today's scheme (101 h on an RTX 4090):

  | design | 2nd-preimage bits | RTX 4090 | RTX 5090 |
  |---|---|---|---|
  | 3-stage, paper's RIPEMD-160 | 117 | 9.2 h (11x) | 6.2 h (16x) |
  | 3-stage, OP_SHA256 puzzle | 114 | 6.6 h (15x) | 4.3 h (23x) |
  | 2-stage **TS2** (pinning pool 300, compressed-only round) | 84 | 4.1 h (25x) | 2.9 h (34x) |
  | 2-stage **TS4** (TS2 + hash chains + signed pool index/level, §12) | **90** | **1.76 h (58x)** | **1.21 h (84x)** |
  | 3-stage **tier E** (short chains + all encodings, §13) | **116** | **5.22 h (19x)** | ≈3.6 h |

- **Round 7 (§15):** once GPU time is about 1 h, **on-chain bytes dominate the real cost**. Tier L
  shrinks the script from 9.2 kB to 3.0 kB (3.8 kvB for the whole spend vs 9.9) at 89.7 bits for
  2.3 GPU-hours, which makes the spend **2.0–2.5x cheaper in total** at 1–20 sat/vB.
- **Round 6 (§14):**
  - An `OP_SHA1` puzzle (tier A1) gives **91.6 bits at 1.62 h on an RTX 4090 and 1.14 h on an RTX 5090**,
    both measured. That is about 63x/89x below Config A.
  - It's also a floor argument: any DER-based stage costs at least 2^P hash compressions. So ≤92-bit
    designs are now within about 25% of the best possible, and the 3-stage tiers are limited by the
    201-op budget.
- **Security menu.** Five exact, consensus-tested designs cover every target up to 116 bits:
  89.7 / 91.6 / 108 / 111.8 / 116 bits at 1.76 / 1.91 / 3.94 / 4.81 / 5.22 RTX 4090-hours. See
  [`SECURITY_MENU.md`](SECURITY_MENU.md).

- **A real spend is verified.** A GPU-found spend of the production TS2 script (strict-DER
  `OP_SHA256` puzzles; pinning in 4 h 11 min and the round in 19 min on one RTX 4090) is **VALID** in
  Bitcoin Core's interpreter. Changing the output by 1 sat or flipping one nonce bit makes it
  INVALID. See `gpu/README.md`, "Real spend", and `real/`.
- **The floor.** Every attempt still needs one SHA-256 block, and each stage ~2^45.4 attempts.
  TS4 is within ~13% of that floor on both cards (1.56 h / 1.03 h for two stages). Three-stage
  designs are opcode-bound at ≈6.6 h / 4.5 h for 114 bits. See §10–§12 and
  [`gpu/README.md`](gpu/README.md).

1. **Nonce-signature pool (shots ~5–10x cheaper).** Replace the single hardcoded `sig_nonce` with k
   hardcoded signatures that share r=1 and use s = 1..k. Push each one with `OP_PUSHDATA1`, which
   FindAndDelete never matches, so every pool signature is checked against the *same* sighash z.
   The k·2 recoverable keys are then `±j·A − B` (A fixed, B = r⁻¹·z·G). One sighash and one
   fixed-base scalar multiplication yield 2k puzzle attempts ("shots"), each costing about half a
   point addition plus one hash, instead of the ~16 additions plus sighash share today.
   - **RTX 4090, same code as a k=1 control:** 5.6x per shot at k=12 and 7.1x at k=24 for
     pinning-shaped work; 6.8x / 9.6x for round-shaped work.
   - **Against Layr's tuned kernels:** 2.0x / 2.6x (pinning) and 1.9x / 2.8x (round).
   - **CPU with libsecp256k1:** 5.1x / 6.8x, for comparison.
2. **DER-only puzzle check (half as many shots).** Replace `<key_puzzle> OP_CHECKSIGVERIFY` with
   `OP_1 OP_CHECKSIG OP_DROP`. It costs the same number of opcodes. BIP66 strict-DER is consensus,
   so a non-DER hash still aborts. A 1-byte "pubkey" makes CHECKSIG return false without failing,
   because STRICTENC and NULLFAIL are policy only. The deployed pipeline needs the hash's r to be a
   curve x-coordinate, a condition absent from the paper's analysis and applied only in the v16 hit
   filter (`qsb_real_search.cu:326`). This change drops it, so each stage needs **2x fewer shots**.

The pool also replaces most bonus keys. The best configuration found that fits in 201 opcodes and
10,000 bytes (n=148, round 1 = 7 signed + 1 bonus, round 2 = 8 signed, k=12) reaches **119.3 bits**
of second-preimage resistance in shot units. Paper Config A, recounted the same way, reaches
116.3 bits and needs 2x the shots, each several times more expensive.

This note also corrects the paper's security accounting (§5). Two items from my own first pass are
retracted (§8).

---

## 1. Cost model: shots

A **shot** is one test of whether `H(encoding(recovered key))` is strict DER. An honest spend runs
three stages (pinning, round 1, round 2), and each needs about 1/p shots, where p is the DER
probability:

| hash output | P(strict DER), exact | with on-curve r (deployed check) |
|---|---|---|
| 20 B (RIPEMD-160, SHA-1) | 2^-46.31 | ≈ 2^-47.31 |
| 32 B (SHA-256) | 2^-45.37 | ≈ 2^-46.37 |

(`p_der()` in `qsb_pool.py` gives the exact sum over r/s lengths, including BIP66 minimal-encoding
rules.)

### Why the puzzle can't be made easier

- **DER is the only usable test.** Script can inspect a 20/32-byte hash output only through DER
  validity in CHECKSIG, or through OP_EQUAL / OP_SIZE / CastToBool (probability ~0, 0 and ~1).
  Numeric opcodes fail on inputs over 4 bytes, and CAT/SUBSTR/AND/XOR are disabled.
- **The fixed bytes set a floor.** Five fixed header bytes put ≈2^-40 on any hash-only DER test,
  and the actual floor is 2^-45.4. OR-ing several tests needs OP_IF and extra hashes, so it doesn't
  reduce the cost per shot.
- **Three stages are needed.** More than ~92 bits of second-preimage resistance requires two
  rounds plus pinning.

So the number of shots is essentially fixed, at ~3 × 2^45.4 (SHA-256) or ~3 × 2^46.3 (RIPEMD).
**The only big lever is the cost of a shot.** That is exactly what the pool changes.

For reference, the Layr benchmark's best RTX 4090 kernels reach ≈786M candidates/s (pinning) and
≈600M/s (subset). One candidate is 2 shots, so that is ≈1.57G and ≈1.2G shots/s. Paper Config A
recounted (2^48.9 shots) comes to roughly **100+ RTX 4090-hours**.

## 2. Trick 1: the nonce-signature pool

### Mechanism

- **FindAndDelete.** Legacy `CHECKSIG`/`CHECKMULTISIG` remove every occurrence of the signature
  from the scriptCode before hashing. Core searches only for the *minimal* push (`0x09 || sig`),
  and only at opcode boundaries. A signature pushed as `OP_PUSHDATA1 0x09 || sig` is never matched,
  and MINIMALDATA is policy only, so its presence never changes z. This is claims C1/C4: a
  minimally pushed pool signature *is* deleted and gives a different z.
- **Pool layout.** Put k signatures in the script, all `SIGHASH_ALL`, all with r=1 (x=1 is on
  secp256k1), s_j = j. Each is 9 bytes, 11 with the PUSHDATA1 header.
- **Selecting from the pool.** The witness gives j; the script runs `roll j, <k> OP_MIN, OP_PICK`
  (3 opcodes).
- **Recovered keys.** For the one sighash z of a stage:

      Q_j^± = r⁻¹(±s_j·R − z·G) = ±j·A − B,   A = r⁻¹·R (constant),   B = r⁻¹·z·G

  Compute B once with the usual fixed-base table. Then all 2k keys come from additions of the
  precomputed affine points j·A. The +j and −j points share the inverse of x_{jA} − x_B, and a
  Montgomery batch amortizes the inversion. This is the same loop as VanitySearch's grouped key
  search: `GRP_SIZE`/`HSIZE` in the Layr repo's `GPUMath.h`. The sighash, which is ~27 SHA blocks in
  the rounds, is also amortized over 2k shots.
- **Encodings.** Compressed, uncompressed (04) and hybrid (06/07) encodings of each key are all
  consensus-valid (C3), so each key is up to 3 shots. Uncompressed and hybrid cost two hash blocks,
  so an honest spender mostly uses compressed. The attacker model counts all three.

### Script cost

| stage | paper | with pool | Δ |
|---|---|---|---|
| pinning | 5 ops | 9 ops (roll j, MIN, PICK, PICK key, CHECKSIGVERIFY, ROLL key, H, CHECKSIG, DROP) | +4 |
| round | 11t + 8 | 11t + 11 (+ push OP_0; roll j, MIN, PICK) | +3 |
| bonus key | 5 ops (3 + key roll + CMS key count) | same | 0 |

Bytes: 11 per pool signature. `CHECKMULTISIG` also adds nKeys to the op count; the generator counts
it, and the padding tests show Core counts the same way.

### Required safety rules (each backed by a consensus test)

- **Cap j with `OP_MIN`.** Without it, `OP_PICK` reaches items in the witness, and an attacker
  could supply their own "nonce" signature with any sighash flag. A huge j is clamped to the pool
  bound: test `j_huge_is_clamped_to_pool_bound`.
- **Push OP_0 before the round's pick, then use j ∈ [1,k].** j=0 then copies the empty NULLDUMMY
  element, which can't verify, so the spend fails (`neg_j0_picks_NULL_sig`). A negative j aborts
  `OP_PICK`.
- **Keep signed selections in lockstep.** Commitments and dummies are both `OP_ROLL`ed at the same
  relative index. Selection order then doesn't change z (asserted in the generator), and a repeated
  index fails (`neg_repeated_dummy_in_round`).
- **The signed-selection lower bound needs no opcode.** An index below the dummy region makes the
  commitment `OP_ROLL` land on a 9-byte dummy or pool signature, which can never equal a 20-byte
  HASH160 (`neg_x_below_region`, `_deep`).
- **Put round 1's regions above round 2's.** When round 2 runs, the only 20-byte items above its
  region are round 1's *unrevealed* commitments. The reverse order would expose round 2's revealed
  commitments during round 1 and give an attacker a real bypass.
- **Count bonus keys by their exact options.** An index below the region is **not** harmless for a
  bonus key. It can pick a pool signature, which is never deleted and verifies under a key anyone
  can recover. 36 of 36 such attacker spends were consensus-valid in an ad-hoc sweep over all pool
  positions; two are kept in the suite (`attacker_bonus_points_at_pool_sig_*`).
  The security model therefore counts A+m−1 options per bonus key (everything reachable), not n−t.
- **Keep other minimal 9-byte pushes distinct.** No minimally pushed 9-byte item may equal a pool
  signature; dummies use hashtype 0x03, so none does. Rounds must also differ in size or subsets;
  `t1 ≠ t2`, or a bonus in only one round, rules out identical scriptCodes.

### Measured speedup per shot (CPU, libsecp256k1 field/group code)

`bench/pool_bench.c` compares two versions of the per-candidate work:
- **Current:** fixed-base u1·G with the 16-bit-window table the Layr kernels use, two recovery-ID
  points, batched affine conversion, and 2 × SHA-256(33 B).
- **Pool:** B = (z/r)·G with the same table, then 2k batched ± additions and 1 × SHA-256 per key.

Both include the same sighash work. The pool points are cross-checked against libsecp256k1's own
group addition (574 of 574 match). Apple M4 Max, 3 runs each (`bench/results_m_series.txt`):

| sighash shape | k=8 | k=12 | k=16 | k=24 | k=32 | k=64 | k=127 |
|---|---|---|---|---|---|---|---|
| pinning (3 compressions per z) | ~4.3x | **5.1x** | ~6.0x | **6.8x** | ~7.6x | ~9x | ~10x |
| round (27 compressions per z) | | **6.9x** | | **10.1x** | | | |

The current loop's hash share (~16%) is close to what the Layr GPU numbers imply. The CPU makes SHA
relatively more expensive than a GPU does, though, so the round-shaped gains are an upper bound for
GPUs. The pinning-shaped figures are the conservative planning numbers. Beyond k≈24 the hash
dominates, and the remaining gains come from the hash choice (§4).

## 3. Trick 2: the DER-only puzzle check

- **The change.** Paper: `… H <roll key_puzzle> OP_CHECKSIGVERIFY`. Proposed: `… H OP_1 OP_CHECKSIG
  OP_DROP`. Both use the same op count, since `OP_1` is a push.
- **Tested (T5).** 20-byte strict-DER strings with hashtype bytes 00/01/03/80/ff, r lengths 1/5/12,
  and r values that are *not* x-coordinates are all accepted. A wrong first byte, a wrong length
  byte or a negative s aborts the script.
- **Why it matters.** With `CHECKSIGVERIFY`, a DER-valid hash whose r isn't an x-coordinate can
  never be satisfied, because no key verifies. The deployed kernels do filter for it
  (`gpu_der_r_on_curve`), so today's real stage probability is ≈2^-47.3 (RIPEMD), not the paper's
  2^-46.4. The DER-only check restores 2^-46.3 for everyone.
- **Side benefits.** It also drops `key_puzzle` from the witness (33 B per stage) and removes the
  key-recovery step after a hit.
- **Security trade.** Security falls by the same 1 bit per stage as honest cost; see the tables.

## 4. Hash choice (smaller lever, now worth it)

Once shots are hash-bound (§2), the puzzle's hash opcode matters:
- **OP_SHA256.** 32-byte output, p = 2^-45.37: about 1.9x fewer shots than RIPEMD for about 3 bits
  less security. SHA-256 and RIPEMD-160 cost roughly the same per block on GPUs (not measured here).
- **OP_SHA1.** Enabled in legacy script (T6), with the same p as RIPEMD. It's typically about 2x
  faster than SHA-256 on GPUs (my assumption; not measured here). Its collision weakness shouldn't
  matter: the inputs are recovered EC keys, which neither party can choose. Still, it's the more
  controversial option.

## 5. Corrections to the paper's accounting

Formal bounds (ROM/QROM, with the attack that lowers TS2 collision resistance) are in
[`SECURITY_PROOF.md`](SECURITY_PROOF.md).

| issue | effect |
|---|---|
| Both recovery IDs and 3 key encodings pass consensus, so an attacker gets 6 shots per sighash, not 1 | about −2.6 bits per round of second-preimage resistance |
| The deployed `CHECKSIGVERIFY` puzzle also needs r on the curve | about +1 bit per stage of security, and **2x honest cost** vs the paper's estimate |
| SIGHASH_SINGLE-bug message value is **2^248** (`uint256::ONE`'s bytes read big-endian), not 1 | needed to recompute dummy keys; checked in T3 (z=1 fails, z=2^248 passes) |
| Bonus-key indices below the region reach `sig_nonce` / earlier dummies | a few extra options (+t+1); negligible for Config A, **large** once a pool exists |

Net: Config A recounted is **116.3 bits** second-preimage (RIPEMD), not 118. Honest work is ≈2^48.9
shots, not 2^47.7.

## 6. Configurations

These rows are exact script builds (`python3 qsb_pool.py --report`, saved in `report.txt`). The
columns are:
- **pre-img / collis:** log2 of attacker work in shots.
- **E1/E2:** honest expected solutions per pinned transaction.
- **honest:** expected shots, including re-pinning when a round has no solution.

Attacker freedom per round = 2 recovery IDs × 3 encodings × pool bound × exact bonus options.

| config | hash | ops | bytes | E1 | E2 | honest | pre-img | collision |
|---|---|---|---|---|---|---|---|---|
| paper Config A, recounted | RIPEMD | 201 | ~9.5k | | | 2^48.89 | 116.3 | |
| **n148, 7+1b / 8, k=12** | RIPEMD | 201 | 9,758 | 31.1 | 3.89 | **2^47.91** | **119.3** | 83.7 |
| n145, 7+1b / 8, k=16 | RIPEMD | 201 | 9,616 | 35.1 | 4.38 | 2^47.91 | 118.4 | 83.4 |
| n140, 7+1b / 8, k=24 | RIPEMD | 201 | 9,397 | 39.4 | 4.93 | 2^47.90 | 117.2 | 83.0 |
| n148, 7+1b / 8, k=12 | SHA256 | 201 | 9,758 | 59.8 | 7.47 | 2^46.95 | 116.4 | 82.6 |
| n140, 8 / 7, k=64 (no bonus) | RIPEMD | 196 | 9,824 | 13.1 | 0.79 | 2^48.53 | 121.8 | 87.0 |

What the table shows:
- **Bonus configs match the ideal honest cost.** They reach 3 × 2^46.3 shots with p₁p₂ ≈ 0.99.
- **Without a bonus key, round 2 (t=7) falls short.** With the budget k, E2 < 1, which forces
  re-pinning. They buy more security for ~1.5–2x more honest work.
- **k trades bytes (n) and security for cheaper shots.**

### Overall estimate vs Config A (same hash)

| config | fewer shots | cheaper shots | total | security |
|---|---|---|---|---|
| k=12 | 1.97x | 5.1–6.4x | **≈10–13x** | 119.3 vs 116.3 bits |
| k=24 | 1.97x | 6.8–9.1x | **≈13–18x** | 117.2 bits |
| k=12, OP_SHA256 | | | another ≈1.9x | −3 bits |

The cheaper-shot range runs from pinning-shaped only to the per-stage CPU mix. These totals assume
**equal kernel quality**, and the GPU in-code ratios confirm them (5.6–9.6x × 1.97 ≈ 11–19x).

**Measured on an RTX 4090 (tuned kernel, `gpu/README.md`).** Layr's tuned kernels running paper
Config A take **≈101 GPU-hours**. The pool2 kernel takes:
- **12.6 h (8.1x)** for n148 k12 RIPEMD at 119 bits;
- **9.2 h (11x)** for n140 k24 RIPEMD at 117 bits;
- **8.0 h (12.7x)** for n148 k12 SHA-256 at 116 bits;
- **6.6 h (15.4x)** for n140 k24 SHA-256 at 114 bits;
- **≈4.2 h (≈24x)** for the 2-stage SHA-256 design at 84 bits.

The prototype `pool.cu` (4.2–5.9x) is superseded by these numbers.

## 7. Validation performed

Everything below runs through `consensus_check` (Bitcoin Core 26's libbitcoinconsensus via the
`bitcoinconsensus` crate, consensus flags `VERIFY_ALL_PRE_TAPROOT`). The results are **245 of 245
as expected, 0 unexpected**.

- **`gen_vectors.py`, 114 mechanism vectors (T1–T6):**
  - T1 (24): one z serves all 4 pool signatures × 2 recovery IDs × 3 encodings.
  - T2 (4): control, where minimal pushes are deleted.
  - T3/T4 (65): CHECKMULTISIG round shape (the subset changes z, j doesn't), including the 2^248
    SINGLE-bug value.
  - T5 (19): DER-only check, including off-curve r and non-DER aborts.
  - T6 (2): OP_SHA1.
  - Plus 8 algebra checks, Q = ±s·A − B.
- **`qsb_pool.py --vectors`, 131 end-to-end vectors on six complete scripts** (NB: n140 8/7 k64 at
  196 ops; BK: n148 7+1b/8 k12 at 201 ops; TS: 2-stage n250 t16 k127 at 196 ops; TS2: 2-stage
  pool-first, forced-compressed, pinning pool 300, at 198 ops; TS3: TS2 plus hash chains, 192 ops;
  TS4: TS3 plus signed pool index and level, 196 ops):
  - honest spends with random j, recovery ID, encoding and subsets, including edge subsets and a
    reversed selection order;
  - clamping, j=0, a wrong HORS preimage, indices below the region, a repeated dummy, and a nonce
    key computed for the wrong z;
  - the attacker bonus-at-pool-signature spend;
  - the production script with a non-hit key (aborts);
  - op limit 201 valid and 202 invalid;
  - size 10,000 valid and 10,001 invalid.

  **Test mode** replaces only the puzzle hash opcode with `OP_DROP <fixed DER-valid 20 B>`, at the
  same op count. The 2^46 search itself isn't run; everything around it is.
- **`bench/pool_bench.c`:** the CPU cost measurements in §2, with a point cross-check (574/574).
- **`gpu/` (RTX 4090):** the pool kernel on Layr's pinning problem, with Layr's kernels as the
  baseline through Layr's own harness.
  - 17 hit-verified runs: 0 failed hits, Poisson-consistent counts, negative controls clean.
  - Exact CPU comparison of 1,152 points across 17 builds.
  - One build (k=64 + RIPEMD) miscompiles, most likely from carry chains split across asm
    statements. It's detected, excluded and documented.
- **`trace.py`:** a tracing interpreter used to diagnose the bonus-at-pool finding. It's a
  debugging aid, not a consensus reference.

- **A real spend** (`gpu/README.md`, "Real spend"): the production TS2 script, with pinning and
  round strict-DER SHA-256 hits found on an RTX 4090 (4 h 11 min + 19 min). The full spend is
  **VALID** in libbitcoinconsensus, and a 1-sat output change or a 1-bit nonce change makes it
  INVALID.

### Not validated yet

- A *tuned* GPU pool kernel. The prototype is measured; the equal-quality 11–19x is inferred from
  in-code ratios.
- Relay and mining of the non-standard transaction (unchanged from QSB).
- Formal security proofs; the numbers here come from the attack-cost model above.

## 8. Retracted from the first pass

- **"Share one dummy-signature pool between rounds with OP_PICK."** This is broken. Commitments are
  `OP_ROLL`ed (relative indices) while dummies would be `OP_PICK`ed (absolute), so different
  orderings of the same revealed commitments select different dummy sets. An index can also repeat.
  That gives the attacker up to ~t! extra options per round, and fixing it costs opcodes. Keep
  separate pools.
- **"k=127 fits alongside n=150."** It only fit because of the retracted sharing idea. The real
  budget-feasible configs use k≈12–24 plus one bonus key.
- **"Config A is ~113.6 bits."** That ignored the on-curve requirement. With it, the figure is
  ≈116.3 bits (§5).

## 9. Next steps

1. **Kernel: done.** `gpu/pool2.cu` covers carry-safe arithmetic, three encodings, inlined hashes
   and Jacobian setup. What's left is incremental:
   - incremental round sighash, so enumeration order shares midstates;
   - larger fixed-base windows;
   - SHA-256 scheduling closer to the ~17G/s full-block ceiling.

   Expected: about 1.2–1.4x more, still bounded by the §10 floor.
2. **Real spend: done at the consensus level** (`real_spend.py`, `gpu/README.md`). Still open: a
   regtest/signet broadcast with real funding outputs, to exercise mempool, relay and mining for the
   non-standard transaction.
3. **Tune k per stage.** Pinning can use the full pool at no security cost, and round 1 can use a
   smaller bound (`k1`). Also try different j→s maps; any small s values work.
4. **Formal write-up** of the security model (§6) and the lower-bound and ordering rules (§2), for
   review by Avihu / Robin Linus.

## 10. The hash floor and the 1-hour target

Every stage needs about 1/p_DER ≈ 2^45.4 (SHA-256) or 2^46.3 (RIPEMD-160) hash evaluations of
recovered keys. No legacy-script predicate on a hash output is easier than strict DER:
- numeric opcodes and CLTV/CSV reject inputs over 4–5 bytes;
- OP_PICK/ROLL and CHECKMULTISIG counts need small numbers;
- pubkey parsing never aborts;
- OP_EQUAL is 2^-160.

Things that looked promising and don't help:
- **Endomorphism (λ·P).** It isn't a valid pool key without solving a DLP.
- **−P.** Never a pool key.
- **Sharing hash work across encodings.** The first bytes differ.
- **Bitcoin SHA-256 ASICs.** Header-only.

Measured on a 4090, one SHA-256 compression costs 0.060 ns (whole GPU) and a pool point about 0.05
ns of EC work. So the floor is about 2 h of hashing for three SHA-256 stages (1.34×10^14 shots) and
about 1.5 h for two. Under one RTX 4090-hour needs about 3–5x more hash throughput per GPU-hour. On
wall-clock time rather than GPU-hours, 8 rented GPUs finish the 6.6 GPU-hour design in about 50
minutes (≈$5).

## 11. Round 3: what else was tried, and what's left

**Built and measured:**
1. **Forced-compressed rounds** (`OP_SIZE 33 OP_EQUALVERIFY`, 2 ops). The attacker's 3-encoding
   freedom goes, giving +1.58 bits per round; that budget pays for a 3x larger round pool at equal
   security. Consensus-tested.
2. **Pool-first layout.** Round sighashes stop rehashing the pool (11–12 bytes per signature).
   Safety: a low j now reaches region items. A commitment fails DER; a SINGLE-bug dummy verifies
   under a fixed key whose hash `design_check()` proves is non-DER in all encodings. Both paths are
   consensus-tested; the dummy path is run with the real round puzzle.
3. **2-stage TS2.** Pinning uses a pool of 300 (setup is free, and pinning security doesn't depend on
   pool size). The round uses a compressed-only bound of 32–64. 198 ops, 8,574 bytes.
   84–85 bits second-preimage. Collision resistance is **≈65 bits**: a fixed-digest attack beats the
   birthday estimate I used earlier. See `SECURITY_PROOF.md`, Theorem 3.
4. **Pools up to 512 in the kernel.** Pinning gets 6.84G shots/s on a 4090 at k=300, and 9.61G on a
   5090.
5. **Blackwell.** The RTX 5090 is 1.40–1.53x a 4090 on this workload. Layr's pinning kernel doesn't
   run on it.

**Ruled out:**
- **SHA-1 puzzle.** Hashing is cheap, but the 20-byte DER probability is 1.9x worse and EC work
  dominates once hashing is cheap, so it's ~1.4x worse per hit.
- **RIPEMD with three encodings.** The fastest raw shots (12.5G/s on a 5090), but 1.9x less
  likely per shot, so ~1.3x worse than SHA-256 with one encoding per hit.
- **Chained hashes as an OR.** Same hash cost per shot.
- **One stage.** A pool with GPUs breaks ~45 bits within one block interval.

**What's left** (none of it an order of magnitude):
- Kernel overhead (~22%): 1.2–1.3x.
- Incremental round sighash through enumeration order: ≈5–7%.
- A larger Blackwell part (RTX PRO 6000, ~10% more SMs than a 5090): ~1.1x.
- Wall-clock: an 8-GPU box runs TS2 in ≈22 min.

On a 5090 that's roughly 2.2–2.5 h per spend for TS2 and ≈3.3 h at 114 bits, about 30–45x below
today's pipeline. A further 10x at the same security would need an easier consensus predicate than
strict DER on a ≥20-byte hash. Legacy script has none (§10), so it would take a soft fork.

## 12. Round 4: hash chains and signed indices (TS4)

**1. Hash-chain OR.** The script computes h₁ = H(key), h_{i+1} = H(h_i), and the witness
(`OP_MIN` + `OP_PICK`) selects one level to DER-check.
- **Speed:** each recovered key gives m attempts, so the per-key EC and overhead cost (≈0.08 ns on a
  4090) is divided by m. Measured at m=16, an attempt costs 0.070 ns against 0.062 ns for a bare
  SHA-256 block.
- **Security:** each level is a distinct random-oracle point. Pinning's security is unchanged; a
  round loses log₂ m bits unless the level is signed.
- **Designer check:** now covers every chain level of every fixed dummy key.

**2. Signing the pool index and chain level.** These are cheap honest freedom: they reuse one
sighash, where varying the subset needs a new sighash, a scalar multiplication and 14 SHA blocks.
Unsigned, they are also attacker freedom. Adding HORS commitments for every j and every level, opened
like dummy selections, costs 6 ops each and removes that freedom. A round then contributes P − 1 bits
(only the recovery-ID parity stays free), while the honest spender keeps the full k·m attempts per
key. At about 1 bit per op this is twice as op-efficient as dummy selections (~0.45 bits/op).

**TS4**: n120, t8, pinning pool 300 with chain 16, round bound 64 with chain 16, j and level signed,
forced-compressed round, pool-first, OP_SHA256.

| TS4 | value |
|---|---|
| size | 196 ops, 9,219 bytes |
| honest solutions per pinned tx | E = 38 |
| second preimage | **89.7 bits** |
| collision | 65.2 bits |
| quantum queries | 36.0 bits |
| consensus tests | 26 vectors, including the wrong-index and wrong-level openings |
| RTX 4090, measured stage rates | **1.76 h** |
| RTX 5090, measured stage rates | **1.21 h** |

**Design frontier** (`design_search.py`: measured cost model, exact rebuild of the winners;
`design_search.txt`):

| target | best found | RTX 4090 | RTX 5090 |
|---|---|---|---|
| 2-stage ≥ 88 bits | TS4 (89.7) | 1.74 h (model) / 1.76 h (measured) | 1.18 h / 1.21 h |
| 2-stage ≥ 84 bits | signed j only (85.7) | 1.74 h | 1.18 h |
| 3-stage ≥ 100 bits | 109 bits | 4.66 h | 3.17 h |
| 3-stage ≥ 114 bits | 114.2 bits | 6.64 h | 4.52 h |

Three-stage designs stay op-bound: the 201-op budget can't pay for the digest selections of two
rounds plus chains or signing.

**Tried and rejected:**
- **Rotations via IMAD:** 4% slower.
- **Interleaving two SHA-256 chains** in a thread: slower, so SHA-256 is throughput-bound, not
  latency-bound.
- **SHA-1 chain levels:** 2.2x cheaper per block, but a 20-byte output needs 1.9x more attempts, so
  only ~1.1x end to end, at a review cost.
- **Splitting stages across two inputs:** each input's script is independent in legacy script, so it
  adds no security to the other input's funds.

**Where this leaves the floor.**
- **TS4 is within about 13% of the two-stage hash floor** on each card: 2 × 2^45.4 SHA-256 blocks is
  1.56 h on a 4090 and 1.03 h on a 5090.
- **Three-stage designs are bounded by opcodes**, not compute.
- **What would move further:** an easier consensus predicate (none exists in legacy script), faster
  SHA-256 hardware, or accepting fewer security bits.
- **Wall-clock time** remains trivially parallel.

## 13. Round 5: a security menu up to 116 bits

**Why the tiers look the way they do.**
- Each stage adds at most P bits (45.4 for SHA-256, 46.3 for RIPEMD-160) and costs ~2^P attempts.
- **Two stages** therefore top out at 2P − 1: 89.7 bits with SHA-256, 91.6 with RIPEMD-160.
- **Beyond that, three stages**, which are bound by opcodes and bytes. Each round needs about 34 bits
  of *signed* sighash variation, and only dummy selections provide it (≈11 ops per ~5 bits).

**What made three-stage designs cheaper.**
- **Short chains (m = 2–3)** in both rounds. They cost only 6–9 ops.
- **The honest spender hashes all three key encodings** in rounds that accept them.
- A finer search (`menu_fine3.py`, 11,487 feasible designs).
- Result: 116 bits drops from 9.3 h (coarse search) and 6.6 h (earlier best) to **5.22 h** on a 4090,
  from measured stage rates. That's about 19x below Config A at equal security.

**Ideas that don't beat dummy selections under both limits:**
- sighash-type-byte pools (120 variants per signature, but byte-heavy);
- CODESEPARATOR position choices (about 3 ops per option);
- deletable pool signatures (same cost as dummies);
- two nonce signatures in one CMS (an AND of puzzles);
- sharing a dummy region with ordering checks (trades bytes for ops, and both bind).

**New kernel paths, all verified on the CPU:**
- RIPEMD-160 hash chains: 25.5G attempts/s pinning, 25.2G round on a 4090; 300/300 hits verified
  across 8 levels.
- Three encodings with chains: 300/300 hits verified across 3 encodings and 3 levels.

The model matches measurements within ~10% (slightly optimistic for three encodings), and the menu
uses the measured rates.

**Validation.** Every tier is rebuilt exactly, passes `design_check()` and gets consensus vectors:
118 for the final menu (`final_menu.py`) and 232 for the coarse menu (`security_menu.py`), 0
unexpected.

## 14. Round 6: how close we are to the floor, and OP_SHA1

**The floor.** Consider what legacy script can test on a value that depends on the transaction:

| candidate predicate | why it doesn't work |
|---|---|
| a numeric op on a hash output | fails on operands over 4 bytes |
| a slice of a hash output | the slicing opcodes are disabled |
| pubkey-encoding checks | policy only, not consensus |
| `OP_EQUAL` | succeeds only with probability 2^-160 |
| BIP66 strict DER on a hash output (the one that works) | fixed success probability 2^-P per hash |

- **Cost per stage.** P is 45.37 for 32-byte outputs and 46.31 for 20-byte outputs. Each hash
  compression yields at most one candidate, so every stage costs the honest spender at least 2^P
  compressions.
- **Security per stage.** Each stage adds at most P bits.
- **Consequence.** Pooling, chains, encodings and signed indices only amortize EC work and setup.
  They can't push a stage below one compression per 2^-P chance of success.
- **Floors on a 4090.** A stage costs at least 0.78 h with SHA-256 (0.0615 ns × 2^45.37) or 0.67 h
  with SHA-1 (0.0275 ns × 2^46.31). Two stages (≤ 92.6 bits) therefore cost at least 1.33 h on a 4090
  and 0.90 h on a 5090. Three stages (≤ ~135 bits) cost at least about 2.0 h and 1.4 h.

**OP_SHA1.** SHA-1 compresses 2.2x faster than SHA-256 on both cards. Its 20-byte output makes the
DER probability 1.9x worse. The net saving shows up only in hash-bound shapes, i.e. long chains:

| shape (same session) | RTX 4090 SHA-256 | RTX 4090 SHA-1 | RTX 5090 SHA-256 | RTX 5090 SHA-1 |
|---|---|---|---|---|
| TS4 pinning, k300 m16 | 14.98 G/s | **30.42 G/s** | 20.85 G/s | **44.03 G/s** |
| TS4 round, k64 m16 | 14.58 G/s | **29.37 G/s** | 20.33 G/s | **40.95 G/s** |

- **Tier A1 (TS4 with `hash=sha1`).**
  - Same session: 1.62 h vs 1.71 h for SHA-256 TS4 on a 4090, and 1.14 h vs 1.23 h on a 5090.
  - Security rises from 89.7 to **91.6 bits**.
  - Against RIPEMD tier B at the same 91.6 bits it's 15–18% cheaper.
  - Both measured runs are within 22–27% of the two-stage floor.
- **Why SHA-1 is safe here.** Known SHA-1 attacks need a chosen message. Here every hashed input is a
  recovered EC key or the previous chain output, so the attacker can't choose it.
- **Validation.**
  - 129 consensus vectors (`menu_sha1.py`), 0 unexpected.
  - GPU SHA-1 hits CPU-verified 300/300 per run on both cards: chain m=8 across all 8 levels, and
    three encodings × three levels.
- **3-stage designs don't improve with SHA-1.** Those designs are op-limited to short chains, so they
  are EC-bound. The higher P costs as much as the faster hash saves: 116 bits is 6.1 h with SHA-1 vs
  5.22 h with SHA-256. The SHA-256 tiers C–E stay.
- **What would close the 3-stage gap (5.2 h vs the ~2.0 h floor).** Long chains in all three stages.
  Those cost about 2.5 ops per level, and each HORS selection costs 11 ops for about 5 bits. Under the
  201-op limit, you can't have both.
- **Ideas that don't close it:**
  - *Spreading stages across several inputs.* An attacker can drop the helper inputs, so each input's
    funds are only as safe as that input's own stages.
  - *Binary IF-chains.* They save ops only for m ≥ 16.
  - *SegWit/tapscript.* They have no FindAndDelete and no SIGHASH_SINGLE bug, and tapscript's Schnorr
    signatures don't allow key recovery.

## 15. Round 7: optimize total cost, not GPU-hours (fee-lean TS4)

**The spend's on-chain bytes now cost far more than its GPU time.**
- QSB scripts are bare legacy scripts, so every byte is non-witness data: 1 vB per byte.
- Tier A1 puts 9,219 bytes of script in the funding output and 574 bytes of scriptSig in the spend.
  That's about 9.85 kvB over the output's life, or 49k sats at 5 sat/vB.
- Its GPU time is 1.62 RTX 4090-hours, about 1,100 sats. That assumes $0.69 per GPU-hour and
  $100k/BTC, i.e. 690 sats per GPU-hour.
- So every earlier round optimized the smaller cost.

**Where the bytes go in TS4.**

| part | bytes |
|---|---|
| pool (300 sigs × 11 B) | 3.3 kB |
| signed-j commitments (64 × 21 B) | 1.3 kB |
| dummies + HORS commitments (120 × 31 B) | 3.7 kB |

- **The pool only needs a few dozen sigs.** It spreads the sighash and fixed-base setup (about
  3–7 ns) over many keys. With 16-level chains, 16 sigs already give 512 candidates per sighash, so
  going to 300 buys little.
- **The dummy region can shrink too.** Fewer dummies (n) with more selections (t) keeps the round's
  search space: C(56, 12) ≈ C(120, 8)/15, and the lost factor is recovered with chain levels and the
  signed pool index.

**Search.** `fee_menu.py` searched 57,581 two-stage designs at ≥ 89.5 bits for the Pareto frontier of
(script + scriptSig bytes) against GPU-hours. It rebuilt the 47 frontier points exactly, ran
`design_check` on each, and measured a real honest scriptSig for each. Consensus: 46 of 47 designs
pass all their vectors. The failing one is a dominated 9.5 kB design whose test-mode stand-in pushes
exceed 10,000 bytes; its production script is 9,469 bytes.

**Selected points.** Totals are in sats: fees plus GPU at 690 sats per 4090-hour.

| design | security | script / scriptSig / total vB | RTX 4090 | 1 sat/vB | 5 sat/vB | 20 sat/vB |
|---|---|---|---|---|---|---|
| A1 (TS4-SHA1, round 6) | 91.6 | 9,219 / 574 / 9,853 | 1.62 h | 10,970 | 50,382 | 198,177 |
| SHA-1, n96 t8, pool 64 | 91.6 | 5,698 / 574 / 6,332 | 1.73 h | 7,525 | 32,853 | 127,833 |
| **L: SHA-256, n64 t11, pool 16, k1 16, chains 8/8, signed j + level** | **89.7** | **3,034 / 743 / 3,837** | 2.32 h | **5,437** | **20,785** | **78,340** |
| SHA-256, n56 t12, pool 16, k1 16, chains 4/8, signed | 89.7 | 2,800 / 799 / 3,659 | 2.64 h | 5,480 | 20,116 | 75,001 |

- **Tier L** has a 3.0 kB script: 3.0x smaller than A1 and 2.6x smaller in total bytes. It is
  2.0–2.5x cheaper in total at any realistic fee rate, for 0.7 more GPU-hours.
- **Why SHA-256 wins when bytes are tight.** Its lower P (45.37) needs about 1 bit less search space
  per stage than SHA-1, and bits of search space are exactly what dummies cost.
- **Caveat.** L's GPU-hours come from the SHA-256 cost model (fitted to measurements within about 4%),
  not from a measured run of its exact shapes.

## 16. Reproduce

```bash
cd research
(cd consensus_check && cargo build --release)            # builds Core's libbitcoinconsensus
python3 gen_vectors.py      | consensus_check/target/release/cchk   # 114 mechanism vectors
python3 qsb_pool.py --vectors | consensus_check/target/release/cchk # 131 end-to-end vectors
python3 qsb_pool.py --report                              # config table (report.txt)
S="$(ls -d ~/.cargo/registry/src/*/bitcoinconsensus-0.106*/)depend/bitcoin/src/secp256k1"
cc -O3 -mcpu=native -I"$S/src" -I"$S" -DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_PREC_BITS=4 \
   -w -o bench/pool_bench bench/pool_bench.c
bench/pool_bench 262144 0    # pinning-shaped sighash
bench/pool_bench 262144 24   # round-shaped sighash
```

| file | purpose |
|---|---|
| `qsbcore.py` | secp256k1, DER, script/tx serialization, FindAndDelete, legacy sighash |
| `gen_vectors.py` | mechanism consensus vectors T1–T6 |
| `qsb_pool.py` | full script generator (production and test mode), spend builder, security/cost model, E2E vectors |
| `trace.py` | tracing interpreter for the opcode subset (debugging) |
| `consensus_check/` | Rust runner over libbitcoinconsensus |
| `bench/pool_bench.c`, `bench/results_m_series.txt` | CPU cost-per-shot benchmark and results |
| `report.txt` | generated config table |
| `SECURITY_MENU.md`, `final_menu.py`, `security_menu.py`, `menu_fine3.py` | final security tiers A–E and their generators/tests |
| `gpu/pool2.cu`, `gpu/field2.cuh`, `gpu/fasthash.cuh`, `gpu/microbench.cu`, `gpu/sweep2.sh`, `gpu/dump_compare2.py` | tuned kernel, field/hash code, primitive benchmark, matrix, exact dump check |
| `gpu/` | CUDA pool kernel, hit verifier, dump comparer, sweep scripts, RTX 4090 results (`gpu/README.md`) |
| `ripemd160.py` | pure-Python RIPEMD-160 fallback (OpenSSL 3 hashlib lacks it) |
