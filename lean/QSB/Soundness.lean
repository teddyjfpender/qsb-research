import QSB.Script
import QSB.Build

/-!
# The soundness statement (FROZEN: `check.sh` pins this file by hash)

`SECURITY_PROOF.md` reduces second-preimage security to a script-level fact. This file states that
fact in game-hopping form, with every hash function and the ECDSA check abstract; the only hash
assumption is that `HASH160` outputs are 20 bytes.

For every accepting execution, with any initial stack and any oracle, **either**
* the script made exactly one CHECKMULTISIG per round, and each one's signature list is
  `Authorised`: the round's selected dummies (distinct region positions, the signed ones among the
  positions whose HORS preimages were revealed) followed by an allowed nonce signature; **or**
* a `BadHashEvent` happened: some `HASH160` step produced a value equal to the stack item below it
  (the value the following `EQUALVERIFY` compares against) that is not one of the current round's
  *revealed* commitments. That covers an unrevealed commitment of any round, a revealed commitment
  of another round, and any non-commitment value (for example a leftover 20-byte hash-chain level).

Bounding `Pr[BadHashEvent]` is the probabilistic part of `SECURITY_PROOF.md` (a preimage or
second-preimage of HASH160 per event). The CHECKMULTISIG scriptCode is not part of the statement:
Core computes it from the signature list (`cmsExec`), so it is determined by what is stated here.
-/

namespace QSB.Soundness
open QSB QSB.Build

/-! ## Execution trace -/

inductive Ev where
  /-- a CHECKMULTISIG(VERIFY) was executed; its signature list (top of stack first) -/
  | cms (sigs : List Bytes)
  /-- an OP_HASH160 was executed on `pre`, with `target` the stack item just below it -/
  | heq (pre target : Bytes)
  deriving DecidableEq

/-- The signature list a CHECKMULTISIG(VERIFY) about to execute will use. -/
def cmsSigs (s : St) : Option (List Bytes) :=
  match s.stack with
  | nkb :: r =>
    match r.drop (numDec nkb).toNat with
    | nsb :: r3 => some (r3.take (numDec nsb).toNat)
    | [] => none
  | [] => none

/-- Events emitted by one instruction, from its pre-state. -/
def here (i : Instr) (s : St) : List Ev :=
  match i, s.stack with
  | .op .hash160, w :: v :: _ => [.heq w v]
  | .op .checkMultiSig, _ => (cmsSigs s).toList.map .cms
  | .op .checkMultiSigVerify, _ => (cmsSigs s).toList.map .cms
  | _, _ => []

/-- All events of an execution, in order (up to and including the failing step, if any). -/
def trace (c : Ctx) : List Instr → St → List Ev
  | [], _ => []
  | i :: is, s =>
    here i s ++ match step c i s with
      | .ok s' => trace c is s'
      | .error _ => []

def Ev.isCms : Ev → Bool
  | .cms _ => true
  | _ => false

def Ev.sigs? : Ev → Option (List Bytes)
  | .cms sg => some sg
  | _ => none

/-- The round an event belongs to: the number of multisigs executed before it. -/
def roundAt (evs : List Ev) (k : Nat) : Nat := (evs.take k).countP Ev.isCms

/-! ## Script constants (as built by `Build.build`) -/

def commit (rnd : Rand) (r i : Nat) : Bytes := Hash.hash160 (rnd.pre[r]![i]!)
def commitJ (rnd : Rand) (r s : Nat) : Bytes := Hash.hash160 (rnd.preJ[r]![s - 1]!)
def commitL (rnd : Rand) (r l : Nat) : Bytes := Hash.hash160 (rnd.preL[r]![l]!)
def dummy (rnd : Rand) (r i : Nat) : Bytes := rnd.dummies[r]![i]!
def poolSig (s : Nat) : Bytes := derSig 1 s 0x01

/-! ## What the one-time signer revealed -/

structure Reveal where
  /-- round -> region positions whose HORS preimages were published -/
  hors : Nat → List Nat
  /-- round -> pool indices whose signed-j preimage was published -/
  j : Nat → List Nat
  /-- round -> chain levels whose signed-level preimage was published -/
  lvl : Nat → List Nat

/-- A HASH160 match is *good* in round `r` iff its target is one of round `r`'s revealed commitments. -/
def Good (p : Params) (rnd : Rand) (rev : Reveal) (r : Nat) (v : Bytes) : Prop :=
  (∃ i ∈ rev.hors r, i < p.n ∧ v = commit rnd r i) ∨
  (p.signJ = true ∧ ∃ s ∈ rev.j r, 1 ≤ s ∧ s ≤ p.kbound[r + 1]! ∧ v = commitJ rnd r s) ∨
  (p.signLvl = true ∧ ∃ l ∈ rev.lvl r, l < p.chains[r]! ∧ v = commitL rnd r l)

def BadHashEvent (h160 : Bytes → Bytes) (p : Params) (rnd : Rand) (rev : Reveal) (evs : List Ev) : Prop :=
  ∃ k w v, evs[k]? = some (.heq w v) ∧ h160 w = v ∧ ¬ Good p rnd rev (roundAt evs k) v

/-! ## Authorised multisigs -/

/-- The nonce signature: a pool signature `P_s`, `1 <= s <= k_r` (signed `s` if `sign_j`), or, for
the pool-first layout where a deep index reaches the regions, a region dummy or commitment. The
latter is excluded under real ECDSA by `design_check()` (a dummy verifies only under its fixed
SIGHASH_SINGLE-bug key, whose hash is checked not to be DER; a commitment is checked not to be DER). -/
def NonceOk (p : Params) (rnd : Rand) (rev : Reveal) (r : Nat) (sig : Bytes) : Prop :=
  (∃ s, 1 ≤ s ∧ s ≤ p.kbound[r + 1]! ∧ sig = poolSig s ∧ (p.signJ = true → s ∈ rev.j r)) ∨
  (p.poolDeep = true ∧ ∃ r' i, r' < p.ts.length ∧ i < p.n ∧ (sig = dummy rnd r' i ∨ sig = commit rnd r' i))

/-- Round `r`'s multisig signature list (head = top of stack): the `t_r + b_r` selected dummies,
last selected first, then the nonce. The first `t_r` selections are HORS-signed and revealed. -/
def Authorised (p : Params) (rnd : Rand) (rev : Reveal) (r : Nat) (sigs : List Bytes) : Prop :=
  ∃ (nonce : Bytes) (sel : List Nat),
    NonceOk p rnd rev r nonce ∧
    sel.Nodup ∧ sel.length = p.ts[r]! + p.bs[r]! ∧ (∀ i ∈ sel, i < p.n) ∧
    (∀ i ∈ sel.take p.ts[r]!, i ∈ rev.hors r) ∧
    sigs = (sel.map (dummy rnd r)).reverse ++ [nonce]

/-- **The soundness statement** for the production script of design `(p, rnd)`. -/
def SelectionSound (p : Params) (rnd : Rand) : Prop :=
  ∀ (cr : Crypto) (rev : Reveal) (W : List Bytes) (is : List Instr) (s' : St),
    (∀ b, (cr.hash160 b).length = 20) →
    parse (build p rnd).script = some is →
    run ⟨cr, (build p rnd).script⟩ is ⟨W, 0⟩ = .ok s' →
    s'.stack.head?.map castToBool = some true →
    let evs := trace ⟨cr, (build p rnd).script⟩ is ⟨W, 0⟩
    ((evs.filterMap Ev.sigs?).length = p.ts.length ∧
      ∀ r (h : r < (evs.filterMap Ev.sigs?).length), Authorised p rnd rev r (evs.filterMap Ev.sigs?)[r])
    ∨ BadHashEvent cr.hash160 p rnd rev evs

end QSB.Soundness
