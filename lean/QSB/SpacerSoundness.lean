import QSB.Soundness
import QSB.SpacerSelection
import QSB.DestructiveChain

/-!
# Audited spacer family's proof target (judge 3)

This is a statement, NOT a theorem or an axiom. The existing TS2 statement and
proof remain unchanged. Its NonceOk omits residual pin-chain hashes because
TS2 has no chain. The promoted audited family needs those bounded extra nonce
choices: they are already charged in the Python analyser's S_i.

The pairing and destructive-cleanup lemmas are proved separately. They do not
establish this arbitrary-witness, whole-script statement.
-/
namespace QSB.SpacerSoundness
open QSB QSB.Build QSB.Soundness

def puzzleHash (cr : Crypto) (p : Params) : Bytes → Bytes :=
  if p.hashOp = 0xa8 then cr.sha256 else if p.hashOp = 0xa7 then cr.sha1 else cr.ripemd160

/-- The fixed witness suffix places keyp at this top-first index. Extra initial
stack items lie beneath the named witness, not above its pinning inputs. -/
def pinKey (p : Params) (W : List Bytes) : Bytes :=
  W[(witness p).reverse.idxOf "keyp"]?.getD []

def iterateHash (H : Bytes → Bytes) (key : Bytes) : Nat → Bytes
  | 0 => key
  | n+1 => H (iterateHash H key n)

def NonceWithPinChain (cr : Crypto) (p : Params) (rnd : Rand) (rev : Reveal)
    (W : List Bytes) (r : Nat) (sig : Bytes) : Prop :=
  NonceOk p rnd rev r sig ∨
  (p.chainPin > 1 ∧ ∃ level, 1 ≤ level ∧ level ≤ p.chainPin ∧
    sig = iterateHash (puzzleHash cr p) (pinKey p W) level)

def AuthorisedWithPinChain (cr : Crypto) (p : Params) (rnd : Rand) (rev : Reveal)
    (W : List Bytes) (r : Nat) (sigs : List Bytes) : Prop :=
  ∃ (nonce : Bytes) (sel : List Nat),
    NonceWithPinChain cr p rnd rev W r nonce ∧
    sel.Nodup ∧ sel.length = p.ts[r]! ∧ (∀ i ∈ sel, i < p.n) ∧
    (∀ i ∈ sel, i ∈ rev.hors r) ∧
    sigs = (sel.map (dummy rnd r)).reverse ++ [nonce]

/-- Intended full-family security target; currently AUDITED, not proved. -/
def SelectionSoundWithPinChain (p : Params) (rnd : Rand) : Prop :=
  ∀ (cr : Crypto) (rev : Reveal) (W : List Bytes) (is : List Instr) (s' : St),
    (∀ b, (cr.hash160 b).length = 20) →
    parse (build p rnd).script = some is →
    run ⟨cr, (build p rnd).script⟩ is ⟨W, 0⟩ = .ok s' →
    s'.stack.head?.map castToBool = some true →
    let evs := trace ⟨cr, (build p rnd).script⟩ is ⟨W, 0⟩
    ((evs.filterMap Ev.sigs?).length = p.ts.length ∧
      ∀ r (h : r < (evs.filterMap Ev.sigs?).length),
        AuthorisedWithPinChain cr p rnd rev W r (evs.filterMap Ev.sigs?)[r])
    ∨ BadHashEvent cr.hash160 p rnd rev evs

end QSB.SpacerSoundness
