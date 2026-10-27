# Security of QSB with nonce-signature pools: definitions, theorems, proofs

This note proves security bounds for the generalized QSB construction in `QSB_IMPROVEMENTS.md`.
That covers pinning plus R ∈ {1, 2} digest rounds, nonce-signature pools, the DER-only puzzle check,
optional forced-compressed rounds and the pool-first layout. The paper's Config A is the special case
k = 1 with the `CHECKSIGVERIFY` puzzle check.

The proofs are in the random-oracle model (ROM) for classical adversaries and in the quantum ROM
(QROM) for quantum ones. The adversary is assumed to break elliptic-curve discrete logs outright
(Shor). One assumption is not proved and is stated explicitly: that Bitcoin Core's legacy-script
semantics are as described (§2, A1). The 245 consensus test vectors check that assumption.

---

## 1. The construction (abstract view)

**Parameters:**

| symbol | meaning |
|---|---|
| R | number of digest rounds (1 for TS2, 2 for the 3-stage designs) |
| n | dummies and commitments per round |
| t_i, b_i | signed and bonus selections in round i |
| k_pin | pinning pool bound |
| k_i | round-i pool bound |
| e_i ∈ {1, 3} | key encodings accepted in round i (1 when the round forces compressed keys) |
| H | the puzzle hash (SHA-256 or RIPEMD-160) applied to a key encoding |
| D | the set of byte strings of the hash's output length that pass BIP66 strict DER |
| p = \|D\| / 2^{8L} | the DER probability: 2^-45.37 for L = 32, 2^-46.31 for L = 20 |

**Locking script.** It contains:
- k pool signatures σ_s = DER(r = 1, s, SIGHASH_ALL), s = 1..k, each pushed with `OP_PUSHDATA1`;
- for each round i, n dummy signatures δ_{i,a} = DER(r_a, s_a, SIGHASH_SINGLE) (minimal pushes) and
  n HORS commitments c_{i,a} = HASH160(x_{i,a}), where the x_{i,a} are secret;
- the code of §2 of `QSB_IMPROVEMENTS.md`.

**Sighash.** For a transaction T, write z_pin(T) = SIGHASH_ALL(T, script). For a deletion set
U ⊆ [n], write z_i(T, U) = SIGHASH_ALL(T, script with every minimal push of δ_{i,a}, a ∈ U,
removed).

**Keys.** Keys(σ_s, z) is the set of public keys that pass ECDSA verification of (σ_s, z).

**A spend (T, w) of the output.** Informally, by Lemma 1, a spend is valid iff:
- (pinning) there are s ≤ k_pin, a key Q ∈ Keys(σ_s, z_pin(T)) and an encoding such that
  H(enc(Q)) ∈ D; and
- (round i) for a signed set I_i of size t_i with opened preimages x_{i,a} (a ∈ I_i), and a bonus
  choice B_i, there are s ≤ k_i, Q ∈ Keys(σ_s, z_i(T, I_i ∪ B_i)) and an allowed encoding such
  that H(enc(Q)) ∈ D.

**Extensions (§12 of `QSB_IMPROVEMENTS.md`).**
- **Hash-chain OR** (length m_pin in pinning, m_i in round i). The puzzle input becomes
  h_L = H^L(enc(Q)) for a witness-chosen level L ∈ [1, m], and h_L must be in D.
- **Signed pool index / signed level.** The chosen j (resp. L) must also open a HORS commitment
  cj_{i,j} (resp. cl_{i,L}). It then joins the digest: d = (I_i, j_i, L_i)_i.

**Digest.** The spend's digest is d = (I_1, …, I_R), extended with (j_i, L_i) where those are signed. The one-time rule: an honest spender opens
preimages for at most one digest per output, ever.

---

## 2. Assumptions

**A1 (consensus semantics).** Bitcoin Core's legacy (pre-SegWit) script interpreter behaves as follows:
- FindAndDelete removes only minimal-push encodings at opcode boundaries;
- `OP_MIN` and `OP_PICK`/`OP_ROLL` have their documented semantics;
- BIP66 strict DER is enforced whenever a signature is checked; an empty signature, or an invalid
  pubkey, makes CHECKSIG return false without failing;
- the SIGHASH_SINGLE bug returns the message 2^248 when the input index ≥ the number of outputs;
- pubkeys are accepted in 33-byte (02/03) or 65-byte (04/06/07) encodings;
- NULLDUMMY, the 201-opcode limit (CHECKMULTISIG counts its keys) and the 10,000-byte script limit
  are enforced.

These are facts about software, not mathematics. `gen_vectors.py` (114 vectors) and
`qsb_pool.py --vectors` (81 vectors) check each one against libbitcoinconsensus (Core 26).

**A2 (random oracles).** H (on key encodings), HASH160 (on HORS preimages) and the sighash function
SHA256d (on transaction serializations) are independent random oracles. In the quantum setting the
adversary may query them in superposition (QROM).

**A3 (elliptic curves give no security).** The adversary may compute any discrete logarithm.
Security never relies on ECDLP.

**A4 (parameters).** Pool signatures use r = 1 with s ∈ [1, k], k < 2^15, and the dummies' (r_a, s_a)
are distinct small values. In the pool-first layout the script passes `design_check()`.

---

## 3. Lemmas

**Mechanized form (Lean, `lean/QSB/Soundness.lean`).** The machine-checked version of Lemma 1 splits
into two outcomes:
- **Good (`Authorised`).** There is exactly one CHECKMULTISIG per round, with distinct in-region
  selections, where the first t_r are among round r's revealed positions. The nonce is a pool
  signature within its bound, or (pool-first layout) a region item, which A4's `design_check` rules
  out.
- **Bad (`BadHashEvent`).** Some `OP_HASH160` output equals its comparison target, and that target
  is not one of the current round's revealed commitments. Possible targets are:
  - an unrevealed commitment;
  - another round's revealed commitment;
  - a non-commitment 20-byte value, such as a RIPEMD-160/SHA-1 chain level left on the stack.

  Each of these is a HASH160 preimage or a cross-hash collision, so it is bounded by the ROM terms
  below.

Every accepting execution satisfies Good ∨ Bad. This is proven for every design in the TS2 family,
including the real spend Core accepted (`ts2_family_sound`, `realTs2_sound`; axioms are only
propext, Classical.choice and Quot.sound, plus `native_decide` for the per-instance side check).
Chains, signed indices and two rounds are milestones M4 and M5 in FORMAL_VERIFICATION.md.

For M5 there is one layout condition to watch: the items above a region must not outnumber the
region, or else an above-region opening must be counted as Bad. In the TS2 family this follows
from 2t ≤ n.

**Lemma 1 (acceptance).** Under A1, the locking script accepts (T, w) iff the conditions of §1 hold
with these exact freedom sets:
- (a) s ranges over [1, k_pin] in pinning and [1, k_i] in round i. With an **unsigned** round index
  and a pinning chain (chain_pin > 1), the nonce pick also reaches the pinning chain's leftover levels.
  The pinning hit among them is a valid DER signature, so the round has up to k_i + chain_pin nonce
  options, and `analyse()` counts all of them. The challenge judge's freedom audit found this case
  (`challenge/`). It moved tiers C and D by 0.1–0.4 bits and doesn't affect signed-index designs;
- (b) Q ranges over Keys(σ_s, z) (Lemma 2);
- (c) the encoding ranges over the three encodings, or only the compressed one when round i forces
  compressed keys;
- (d) the opened signed set equals the set of dummies deleted by the round's signed selections;
- (e) with a chain, the level ranges over [1, m] (`OP_MIN`-clamped; a negative level makes `OP_PICK`
fail), and with signed j or level the opened commitment must be the one at the chosen index (test
vectors `neg_signed_j_preimage_for_other_index`, `neg_signed_level_preimage_for_other_level`);
(e′) the bonus choice ranges over exactly β_i options, where β_i is the product over bonus keys of
  (A + m − 1). This counts picks above the region, which reach earlier-selected sigs and, in the
  interleaved layout, pool signatures.

In the pool-first layout, an index below the pool reaches region items. Those make the spend fail
under A4.

*Proof sketch.* For (a), `OP_MIN` clamps the index and `OP_PICK` rejects negative depths. In the
pool-first layout, depths below P1 reach region items:
- a commitment is not DER, so CHECKSIG aborts;
- a dummy δ verifies only under the fixed keys Keys(δ, 2^248), and A4 says no encoding of those keys
  hashes into D, so the puzzle aborts.

For (d), commitments and dummies are removed in lockstep by `OP_ROLL` at the same relative index, and
`OP_HASH160 … OP_EQUALVERIFY` forces an opened preimage for each signed selection. Size mismatches
(20-byte hash vs a 9-byte, empty or number item) make selections outside the region fail. Round 1's
regions sit above round 2's, so the only 20-byte items round 2 can reach out of range are round 1's
unrevealed commitments. Opening one needs a HASH160 preimage that is never published, since round 1
reveals only its selected preimages and rolls those commitments away. So this case adds no attacker
freedom. The Lean check `hors_select` in `lean/QSB/Proofs.lean` confirms the case is reachable only
when the items above the region outnumber the region itself. That happens in round 2 of tiers C, D
and E (about 250 items above a 130-item region), and never in the two-stage tiers. Repeats fail
because rolled items are gone.

For (b), (c) and (e): the nonce signature is checked inside CHECKMULTISIG (or CHECKSIGVERIFY for
pinning) against the witness key. Pool pushes are non-minimal, so FindAndDelete removes exactly the
selected dummies (A1), and each dummy verifies under its fixed SINGLE-bug key. The consensus vectors
exercise each of these branches in both directions. ∎

**Lemma 2 (keys are determined, even with Shor).** For σ_s with r = 1 and any z, |Keys(σ_s, z)| = 2.
The keys are Q = ±s·A − z·G with A = R₁ (R₁ is the curve point with x = 1 and even y). The
alternative R with x = 1 + n is not on secp256k1. For a dummy with small r, |Keys| ∈ {2, 4}, with 4
exactly when r + n is an x-coordinate (24 of the small on-curve r values).

*Proof.* ECDSA verification accepts Q iff x(u₁G + u₂Q) ≡ r (mod n), where u₁ = z/s and u₂ = r/s. So
u₁G + u₂Q must be a point R with x(R) ∈ {r, r + n} (and r + n < p), which forces
Q = r⁻¹(s·R − z·G). Checking whether 1 + n lifts to the curve settles the rest. The check is
`recover_all` in `qsbcore.py`. Knowing discrete logs doesn't change the verification equation, so A3
gives the adversary no extra keys. ∎

**Lemma 2′ (chains).** For a fixed key encoding u, the chain points u, H(u), H²(u), … are distinct
H-inputs except with probability ≤ q²·2^-L·8 (a cycle or collision in the random oracle). Chain
inputs (20- or 32-byte strings) never coincide with key encodings (33- or 65-byte strings). So every
(context, s, ±, encoding, level) tuple is an independent Bernoulli(p) event, and each additional
level is one more oracle point, counted in S.

**Lemma 3 (distinct oracle points).** Let q_S be the number of sighash-oracle queries and k_max the
largest pool. Except with probability

ε_col ≤ q_S² · 2^-256 + q_S² · (2k_max)² · 2^-255,

all the H-inputs enc(Q) arising from distinct pairs (context, s, ±, encoding) are distinct. Here
"context" means (T, pinning) or (T, round i, U).

*Proof.* Distinct contexts serialize distinct sighash preimages. The pool signatures are never
deleted and the dummies' deletions are the U's, so SHA256d outputs collide or agree mod n with
probability ≤ 2^-256 per pair. Within one z, the keys ±s·A − zG for different (s, ±) differ unless
s ≡ ±s' (mod n), which can't happen for s, s' < 2^15.

Across contexts, ±s·A − zG = ±s'·A − z'G requires z − z' ≡ ±(s ∓ s')·ρ (mod n), where ρ is the fixed
discrete log of A. For uniform z, z' that's probability ≤ (2k)²/n per pair of contexts. Different
encodings of different points are different byte strings. ∎

**Lemma 4 (one-time HORS).** An adversary who has seen the openings for digest d* can open some
index a ∉ d*_i in round i only by finding a HASH160 preimage of c_{i,a}. The probability is at most
q·nR·2^-160 classically, and O(q²·nR·2^-160) quantumly (multi-target Grover bound).

---

## 4. Second-preimage (spend forgery) resistance

**Game.** The honest spender publishes one valid spend (T*, w*) with digest d* = (I*_1, …, I*_R). The
adversary wins if it outputs a valid spend (T', w') with T' ≠ T*, meaning any change to what
SIGHASH_ALL commits to.

**Freedom counts.**

S_i = 2 · e_i · β_i · (k_i unless j is signed, else 1) · (m_i unless the level is signed, else 1),

S_pin = 2 · e_pin · k_pin · m_pin.

The honest spender's freedom per subset is always 2·e_i·k_i·m_i·β_i. Signing j and the level
removes them from the attacker's side only. The extra factor 2 is the recovery-ID parity, which a
script cannot constrain.

**Theorem 1 (classical ROM).** For any adversary making at most q queries to H,

Pr[win] ≤ q·p · ∏_{i=1..R} min(1, S_i·p) + ε_col + q·nR·2^-160.

So the classical security in hash evaluations ("shots") is at least

λ_2nd = log₂(1/p) + Σ_i (log₂(1/p) − log₂ S_i).

*Proof.* By Lemma 4, except with the HORS term, w' opens exactly the sets I*_i in round i. By
Lemma 1 and Lemma 2, validity of T' requires:
- (i) a pinning point u₀ ∈ U₀(T') with H(u₀) ∈ D, where |U₀(T')| = S_pin; and
- (ii) for each round i, a point u_i ∈ U_i(T') with H(u_i) ∈ D, where
  U_i(T') = {enc(Q) : Q ∈ Keys(σ_s, z_i(T', I*_i ∪ B)), s ≤ k_i, B a bonus choice, allowed
  encodings} and |U_i(T')| ≤ S_i.

By Lemma 3, all these point sets are pairwise disjoint across T' and across stages, except for ε_col.

To output a valid T' the adversary must know that condition (i) holds, i.e. it must have queried
some pinning hit u₀. (Guessing contributes at most p per output, which we absorb by counting the
output as one more query.) Let N be the number of pinning hits among queried points; E[N] ≤ q·p.
For each pinning hit, the round points of the corresponding T' are disjoint from everything that
determined the hit and are uniformly distributed. So each round condition holds with probability
≤ min(1, S_i·p), independently across rounds. A union bound over the pinning hits gives the claim. ∎

**Theorem 2 (quantum ROM).** For any quantum adversary making at most q superposition queries to H
(and polynomially many to the other oracles),

Pr[win] ≤ 8(q+1)² · λ + ε_col^Q + O(q²·nR·2^-160),

where λ = min(1, S_pin·p) · ∏_i min(1, S_i·p) and ε_col^Q = O(q_S³ · 2^-256) (Zhandry's collision
bound). So the quantum security, in oracle queries, is at least ½·log₂(1/λ) − 1.5.

*Proof.* Define the block function F(T') = (H|_{U₀(T')}, H|_{U₁(T')}, …, H|_{U_R(T')}). By Lemma 3
the blocks are disjoint across T', so the values F(T') are independent across T'. Let
g(T') = 1 iff every block contains a hit. The g(T') are then independent Bernoulli variables with
parameter ≤ λ. Any H-query algorithm can be simulated with the same number of F-queries: to answer a
query to point u, query the block containing u; points outside every block are independent and are
simulated directly. A winning adversary outputs some T' with g(T') = 1. The QROM search bound for
independent Bernoulli marks (Zhandry 2012; also Hülsing–Rijneveld–Song 2016, Lemma 3) gives
Pr ≤ 8(q+1)²·λ. The collision and HORS terms follow from Lemmas 3–4 in their quantum forms. ∎

*Remarks.*
- Theorem 2 loses the factor S_pin that Theorem 1 does not. The block oracle reveals a whole pinning
  pool per query, whereas a real circuit evaluating all S_pin keys per Grover iteration is S_pin
  times wider. The bound is therefore conservative for large pinning pools.
- Queries must also run **sequentially** before T* confirms. A second-preimage attacker gains
  nothing after confirmation, short of reorganizing the chain.

---

## 5. Collision resistance (non-equivocation)

**Game.** The adversary knows every secret and wins if it outputs two valid spends (T, w) and
(T', w') with T ≠ T' and the same digest d. This property matters only for protocols that rely on
digest uniqueness, such as BitVM-style dispute games. It is not needed for the honest spender's own
safety.

**Theorem 3 (classical ROM).** For any adversary making at most q queries to H,

Pr[win] ≤ q²·p·∏_i (S_i·p)² / (2·Σ_i S_i) + (q·p·∏_i min(1, E_i))² / (2·∏_i C(n, t_i)) + ε_col,

where E_i = C(n, t_i)·C(n − t_i, b_i)·S_i·p is the expected number of valid round-i solutions per
pinned transaction. The first term covers **fixed-digest** strategies, the second **birthday
over digests**.

Equivalently, λ_col ≥ min(λ_fixed, λ_bday) with

λ_fixed = ½·(log₂(1/p) + 2·Σ_i(log₂(1/p) − log₂ S_i) + log₂ Σ_i S_i + 1).

*Proof sketch.* Let N ≤ q·p + O(1) be the number of pinned transactions the adversary learns. For a
digest d and a pinned T, let a_{T,d,i} be the number of queried points in T's round-i block for d;
then Pr[(T, d) valid and learned] ≤ ∏_i a_{T,d,i}·p. The expected number of colliding pairs is at
most Σ_d (Σ_T ∏_i a_{T,d,i}·p)² / 2, subject to Σ_{T,d,i} a_{T,d,i} ≤ q and a ≤ S_i. Because the
value is multiplicative in the a's and the cost additive, full blocks (a = S_i) are optimal. With
each digest tested on all N pinned transactions this gives the first term. The second term is the
standard birthday count for strategies that enumerate digests honestly. ∎

This bound is tight up to constants: the fixed-digest attack achieves it. That attack is new here,
and it lowers my earlier estimate for 2-stage designs.

---

## 6. Concrete numbers (from `qsb_pool.py --report`)

"Shots" are H evaluations of recovered keys (each ~0.1 ns on an RTX 5090).

| design | honest shots | 2nd-preimage, classical (Thm 1) | 2nd-preimage, quantum queries (Thm 2) | collision, classical (Thm 3) |
|---|---|---|---|---|
| Paper Config A, recounted (RIPEMD, CHECKSIGVERIFY) | 2^48.9 | 116.3 | ≈55 | ≈78* |
| 3-stage RIPEMD n148 7+1b/8 k12 | 2^47.9 | 119.3 | 55.0 | 83.7 |
| 3-stage SHA-256 n140 7+1b/8 k24 | 2^47.0 | 114.4 | 52.1 | 81.9 |
| 2-stage TS2 SHA-256 kpin300, k1=32, compressed | 2^46.4 | 84.7 | 35.5 | **65.6** |
| 2-stage TS2 SHA-256 kpin300, k1=64, compressed | 2^46.4 | 83.7 | 35.0 | **65.1** |
| 2-stage **TS4**: TS2 + chains 16/16 + signed j and level (menu tier A) | 2^46.4 | **89.7** | 36.0 | 65.2 |
| menu tier B (TS4 with RIPEMD-160) | 2^47.3 | 91.6 | 36.9 | 66.2 |
| menu tier C (3-stage) | 2^47.0 | 108.0 | 47.1 | 77.4 |
| menu tier D (3-stage) | 2^47.1 | 111.8 | 49.8 | 78.4 |
| menu tier E (3-stage) | 2^47.1 | 116.2 | 52.0 | 82.6 |

\* The paper's figure, not recomputed with Theorem 3.

How to read this:
- **Three-stage designs** keep security equal to or better than Config A on every property, at
  roughly 15–23x less compute.
- **TS2** trades security for speed:
  - second preimage: 84 bits classically, and about 2^35 *sequential* quantum oracle calls, each a
    full sighash + key-recovery + hash circuit, all before confirmation;
  - collision (only relevant to non-equivocation protocols): 65 bits.
- **When TS2 fits:** it's appropriate when the output only needs to protect its owner and the spend
  goes directly to a miner. It is not appropriate for protocols that need non-equivocation at ≥80
  bits.

---

## 7. What is and isn't proved

**Also covered:** hash chains and signed indices (Lemma 2′, the freedom counts in §4, and the
designer check over all chain levels). The theorems apply unchanged with the extended S_i.

**Proved,** relative to A1–A4:
- the bounds of Theorems 1–3;
- Lemmas 2–4, which are pure mathematics.

**Assumed (A1), not proved:** that Bitcoin Core's interpreter matches the semantics used in Lemma 1.
It is tested by 245 consensus vectors plus a production spend with real GPU-found puzzle
hits (see `gpu/README.md`, "Real spend"). A machine-checked proof would need a formal model of the legacy
interpreter (e.g., in Isabelle or Lean) plus a proof that the generated script meets Lemma 1.

**Operational requirements the proofs rely on:**
- **One-time use.** Never open HORS preimages for two different digests of the same output. Fee
  bumping must reuse the same transaction and digest, never re-sign with a new one.
- **Input position.** The QSB input's index must be ≥ the number of outputs, or the dummies'
  SIGHASH_SINGLE bug doesn't apply and the spend is invalid. This holds for the original QSB too.
- **Designer check.** For the pool-first layout, `design_check()` must pass (the probability of a
  failure is ~2^-45 per item).
- **Malleability.** The scriptSig isn't signed, so third parties can re-encode it and change the
  txid. They can't change the effects. The same is true of any legacy spend.

**Not covered:**
- attacks on SHA-256 or RIPEMD-160 beyond generic ones, which the random-oracle model idealizes
  away;
- miner behavior;
- denial-of-service.

## Judge 3 extension: spacer selection with destructive round chains

The owner-authorized promotion adds `selection_layout="spacer"` and
`destructive_chain=true` to the data-only design language. The promoted spacer
family requires pool-first layout, no bonus selections, and unsigned pool and
level indices. Its security confidence is **audited**, not proven.

Each independent round has bottom-first layout
`Z D[n-1] 0 C[n-1] ... D[0] 0 C[0]`. `Z` is a permanent zero sentinel.
After moving the witness index x to the top, MIN clamps it to one less than
the depth of Z. DUP/ROLL selects a commitment, the HORS check consumes it,
and ROLL with the retained x selects its paired dummy. The spacer offsets
the two intervening removals. The local Lean theorem
`QSB.SpacerSelection.selects_paired_dummy` proves the exact list transformation
for arbitrary prefix/suffix and values. Selecting a previously removed
commitment fails; remaining pairs retain their relative spacing in any order.

The sentinel prevents a selector from reaching another round or witness-held
fake pairs below its region. Dummies and zeros cannot equal a 20-byte HORS
commitment. Matching an unrevealed commitment or another unexpected 20-byte
value is charged to the existing BadHashEvent. Commitments from an earlier
round that have not been opened remain unknown; each round has independent
secrets. The adversarial tests remove the bound and the HORS check separately;
the former admits a concrete fake-pair attack, and the freedom audit detects
both mutated whole scripts.

For round hash chains, ROLL presents the same selected bytes as PICK and
removes that level. Clearing the other m-1 values leaves exactly the previous
suffix. `QSB.DestructiveChain.same_selected_value_and_suffix` proves this local
equivalence for any acceptance predicate. Pinning is unchanged and its leftover
chain values remain available to the attacker as potential nonce signatures.
Thus, for the promoted unsigned, all-encoding, no-bonus family:

```
S_pin = 2 * k * 3 * chain_pin
S_i   = 2 * (k_i + extra_pin) * 3 * chain_i
extra_pin = chain_pin if chain_pin > 1 else 0
E_i   = C(n,t_i) * 2 * k_i * 3 * chain_i * p_DER
```

FindAndDelete depends only on the selected dummy set. The interleaved zero and
commitment pushes neither create another deletion nor another authorized
sighash. Hence the existing reduction and these freedom counts apply under
the gadget argument, designer checks, and the existing random-oracle and
ECDSA abstractions. Deep adaptive audits and independent Core/Lean replay
provide evidence for the full script; the local lemmas alone are insufficient.

The existing frozen `SelectionSound` theorem covers TS2, whose pinning has no
chain. Its `NonceOk` does not include leftover pin-chain hashes. Rather than
weaken that proved statement, judge 3 adds the explicit, **unproved** target
`QSB.SpacerSoundness.SelectionSoundWithPinChain`: the nonce must satisfy the
original condition or be one of the bounded hashes of the actual pinning
witness key. The definition is pinned in the new manifest, is not an axiom,
and does not confer a `proven` label. The original TS2 family is explicitly
restricted to the original selection and cleanup flags, and its examples and
proof still check.

Judge 3 also fixes two pre-existing counts: both DER integers must be nonempty
(20-byte probability 390405/2^65; 32-byte probability 780555/2^65), and a round
with t signed plus b bonus selections has C(n,t+b) distinct honest deletion
sets, not C(n,t)C(n-t,b). The collision calculation still accounts for which
signed subsets a passing union can represent. Historical judge-2 scores are
retained under their old manifest and are not silently reinterpreted.
