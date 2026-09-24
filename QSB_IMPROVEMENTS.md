# Order-of-magnitude cheaper QSB spends: nonce-signature pools and a DER-only puzzle check

Status: research note, 2026-09-24. Scope: Avihu Levy's *Quantum-Safe Bitcoin Transactions Without
Softforks* (QSB, [`../avihu`](../avihu)) and the Layr-Labs grinding benchmark ([`../layr`](../layr)).

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

- **The floor.** Hashing plus EC work is at its floor on both cards; only ~22% overhead remains.
  Below ~2 h per spend on a single GPU isn't reachable for any strict-DER design. See §10 and §11,
  and [`gpu/README.md`](gpu/README.md).

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
`bitcoinconsensus` crate, consensus flags `VERIFY_ALL_PRE_TAPROOT`). The results are **195 of 195
as expected, 0 unexpected**.

- **`gen_vectors.py`, 114 mechanism vectors (T1–T6):**
  - T1 (24): one z serves all 4 pool signatures × 2 recovery IDs × 3 encodings.
  - T2 (4): control, where minimal pushes are deleted.
  - T3/T4 (65): CHECKMULTISIG round shape (the subset changes z, j doesn't), including the 2^248
    SINGLE-bug value.
  - T5 (19): DER-only check, including off-curve r and non-DER aborts.
  - T6 (2): OP_SHA1.
  - Plus 8 algebra checks, Q = ±s·A − B.
- **`qsb_pool.py --vectors`, 81 end-to-end vectors on four complete scripts** (NB: n140 8/7 k64 at
  196 ops; BK: n148 7+1b/8 k12 at 201 ops; TS: 2-stage n250 t16 k127 at 196 ops; TS2: 2-stage
  pool-first, forced-compressed, pinning pool 300, at 198 ops):
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

### Not validated yet

- A real puzzle hit through the production script, which needs about 2^46 GPU work per stage.
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
2. **Production script generator and one real spend on signet/regtest.** `qsb_pool.build()`
   already emits the production script. It still needs the grinding driver (pinning → round 1 →
   round 2) and a real ~2^46 search per stage, or a signet-sized dry run.
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
   84–85 bits second-preimage, ~81 bits collision.
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

## 12. Reproduce

```bash
cd research
(cd consensus_check && cargo build --release)            # builds Core's libbitcoinconsensus
python3 gen_vectors.py      | consensus_check/target/release/cchk   # 114 mechanism vectors
python3 qsb_pool.py --vectors | consensus_check/target/release/cchk # 81 end-to-end vectors
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
| `gpu/pool2.cu`, `gpu/field2.cuh`, `gpu/fasthash.cuh`, `gpu/microbench.cu`, `gpu/sweep2.sh`, `gpu/dump_compare2.py` | tuned kernel, field/hash code, primitive benchmark, matrix, exact dump check |
| `gpu/` | CUDA pool kernel, hit verifier, dump comparer, sweep scripts, RTX 4090 results (`gpu/README.md`) |
| `ripemd160.py` | pure-Python RIPEMD-160 fallback (OpenSSL 3 hashlib lacks it) |
