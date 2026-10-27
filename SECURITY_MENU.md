# QSB security menu: five designs covering up to 116 bits

Choose the cheapest tier whose security meets your target.

## What "security" means here

- **2nd-preimage (classical)** is the headline number. It's log₂ of the expected number of puzzle
  hash evaluations an attacker needs to redirect an honest spend to a different transaction. Each
  evaluation costs an EC key recovery (amortized) plus a SHA-256 or RIPEMD-160 block.
  `SECURITY_PROOF.md`, Theorem 1.
- **Quantum queries** is ½·log₂(1/λ) − 1.5: the number of *sequential* superposition oracle calls
  (each a full sighash + key-recovery + hash circuit) for constant success probability. Theorem 2.
- **Collision** is log₂ of the work for the spender to make two transactions with the same digest.
  It only matters for protocols that need non-equivocation. Theorem 3.

Paper Config A, recounted with the same model, is 116.3 / ≈55 / ≈78 bits at **≈101 RTX 4090-hours**
(on Layr's tuned kernels).

## The tiers

| tier | covers | stages / hash | 2nd-pre | quantum | collision | ops / bytes | RTX 4090 | RTX 5090 | vs Config A |
|---|---|---|---|---|---|---|---|---|---|
| **A: TS4** | ≤ 89.7 | 2 / SHA-256 | **89.7** | 36.0 | 65.2 | 196 / 9,219 | **1.76 h** | **1.21 h** (measured) | 58x |
| **A1: TS4-SHA1** (round 6) | ≤ 91.6 | 2 / SHA-1 | **91.6** | 36.9 | 66.2 | 196 / 9,219 | **1.62 h** | **1.14 h** (measured) | 63x |
| **L: fee-lean TS4** (round 7) | ≤ 89.7 | 2 / SHA-256 | **89.7** | 38.6 | 65.4 | 193 / **3,034** | 2.32 h (model) | ≈1.6 h (est.) | cheapest in total |
| B: TS4-R (superseded by A1) | ≤ 91.6 | 2 / RIPEMD-160 | 91.6 | 36.9 | 66.2 | 196 / 9,219 | 1.91 h | ≈1.32 h | 53x |
| **C** | ≤ 108 | 3 / SHA-256 | **108.0** | 47.1 | 77.4 | 201 / 9,551 | **3.94 h** | ≈2.72 h | 26x |
| **D** | ≤ 111.8 | 3 / SHA-256 | **111.8** | 49.8 | 78.4 | 201 / 9,472 | **4.81 h** | ≈3.32 h | 21x |
| **E** | ≤ 116 | 3 / SHA-256 | **116.2** | 52.0 | 82.6 | 200 / 9,551 | **5.22 h** | ≈3.60 h | **19x at equal security** |

**Where the times come from.** RTX 4090 times use stage rates **measured** on the real problem shapes
(`gpu/results4/`, `gpu/results5/`). RTX 5090: tier A is measured; the others are scaled by the
measured 4090→5090 ratio (×0.69). Every time includes retries when a round has no solution.

**Choosing a tier.** Fees usually decide it. The whole spend is about 3.8 kvB for L and 9.9 kvB for A1,
so at any fee rate from 1 to 20 sat/vB, **L** is 2.0–2.5x cheaper in total (QSB_IMPROVEMENTS §15).
Take A1 when GPU time or the extra 1.9 bits matter more than fees.
Up to 91.6 bits, take **A1**. It uses the same script as A with `OP_SHA1` as the
puzzle hash, and it is cheaper than A while giving 1.9 more bits. SHA-1's collision weaknesses don't
apply: the puzzle needs a structured-output preimage on inputs the attacker can't choose, since they
are recovered EC keys and earlier chain outputs. Between 91.6 and 108 bits, take C. There is no cheaper
three-stage design (the search found none under 3.9 h).

## Exact definitions

Instantiate any tier with `qsb_pool.build(cfg)` (production script) and spend with
`qsb_pool.spend(...)`. All tiers use the pool-first layout, so run `design_check()` once per script.
It must return no findings.

| tier | `cfg` |
|---|---|
| A | `hash=sha256, n=120, t1=8, k=300, k1=64, chain_pin=16, chain_r=16, sign_j=True, sign_lvl=True, force_comp=True, pool_deep=True` |
| A1 | as A with `hash=sha1` (OP_SHA1) |
| L | `hash=sha256, n=64, t1=11, k=16, k1=16, chain_pin=8, chain_r=8, sign_j=True, sign_lvl=True, force_comp=True, pool_deep=True` |
| B | as A with `hash=rmd` |
| C | `hash=sha256, n=130, k=96, chain_pin=3, t1=6, b1=1, k1=96, chain1=2, t2=7, k2=96, chain2=3, pool_deep=True` |
| D | `hash=sha256, n=140, k=32, chain_pin=3, t1=6, b1=1, k1=16, chain1=2, t2=7, k2=32, chain2=3, pool_deep=True` |
| E | `hash=sha256, n=130, k=96, chain_pin=1, t1=7, k1=48, chain1=3, t2=7, k2=96, chain2=2, pool_deep=True` |

**Glossary:**
- **n**: dummies and commitments per round.
- **t_i**: signed selections in round i.
- **b_i**: bonus selections.
- **k**: pool size (shared). **k_i**: round i's pool bound.
- **chain_pin, chain_i**: hash-chain lengths.
- **sign_j / sign_lvl**: HORS-signed pool index and chain level.
- **force_comp**: rounds accept only compressed keys.

The honest spender should hash all three key encodings in tiers C–E (their rounds accept them); in
A and B only compressed keys.

**Honest expected solutions per pinned transaction (E):**

| tier | E |
|---|---|
| A | 38 |
| A1, B | 20 |
| C | 19 / 4 |
| D | 5.3 / 2.3 |
| E | 2.0 / 2.7 |

A round fails for a given pinned transaction with probability e^-E (13% for tier E's first round);
the times above include those retries.

## Validation

- **Consensus (libbitcoinconsensus, Bitcoin Core 26):** every tier's production script and
  test-mode spends; `final_menu_vectors.txt` has 118 vectors, 0 unexpected. The mechanisms each tier
  uses have their own suites: 245 vectors in `gen_vectors.py` + `qsb_pool.py --vectors`, and 232 in
  `security_menu_vectors.txt`.
- **A1:** 129 more vectors, 0 unexpected, in `menu_sha1_vectors.txt`. GPU SHA-1 hits were CPU-verified,
  300/300 on each card (chain m=8, and three encodings with m=3), in `gpu/results6/`.
- **Real puzzle solution:** a production TS2 spend with GPU-found strict-DER SHA-256 hits is VALID in
  Core (`gpu/README.md`, "Real spend"). Tiers A–E use the same components plus hash chains and signed
  indices, whose GPU hits were CPU-verified at every level and encoding.
- **Security:** `SECURITY_PROOF.md` (ROM/QROM), assuming Core's legacy semantics as tested.

## Operational rules (all tiers)

1. **One-time use.** Never open HORS preimages for two digests of one output. Fee bumping must
   rebroadcast the same transaction, never re-sign.
2. **Input position.** The QSB input's index must be ≥ the number of outputs (dummy SIGHASH_SINGLE
   bug).
3. **Submission.** Submit directly to a miner; the transaction is non-standard. Second-preimage
   attacks must finish before confirmation, which the quantum-query figures assume.
4. **Parallelism.** Spends are embarrassingly parallel: N GPUs divide wall-clock time by N at the same
   GPU-hour cost.
