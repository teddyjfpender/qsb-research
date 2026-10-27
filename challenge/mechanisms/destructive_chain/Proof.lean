import QSB.Script

/- A local, generic stack lemma. This does not prove full D/E family soundness.
   The hashes are listed top-first, as in QSB.Script's stack representation.
   PICK retains every hash; ROLL erases exactly the selected position. Both
   present the same selected bytes to CHECKSIG, then discard all residual hashes.
   DER-check acceptance is abstract here, so the result holds for any predicate. -/
namespace QSB.DestructiveChain
open QSB

def pickThenClear (accept : Bytes → Bool) (hashes rest : List Bytes) (i : Nat) :
    Option (List Bytes) := do
  let selected ← (hashes ++ rest)[i]?
  if accept selected then some ((hashes ++ rest).drop hashes.length) else none

def rollThenClear (accept : Bytes → Bool) (hashes rest : List Bytes) (i : Nat) :
    Option (List Bytes) := do
  let selected ← (hashes ++ rest)[i]?
  if accept selected then
    some (((hashes ++ rest).eraseIdx i).drop (hashes.length - 1))
  else none

theorem clear_after_roll (hashes rest : List Bytes) (i : Nat) (hi : i < hashes.length) :
    ((hashes ++ rest).eraseIdx i).drop (hashes.length - 1) = rest := by
  rw [List.eraseIdx_append_of_lt_length hi]
  have he : (hashes.eraseIdx i).length = hashes.length - 1 := by
    simp [List.length_eraseIdx, hi]
  rw [← he]
  simp

theorem same_selected_value_and_suffix (accept : Bytes → Bool)
    (hashes rest : List Bytes) (i : Nat) (hi : i < hashes.length) :
    rollThenClear accept hashes rest i = pickThenClear accept hashes rest i := by
  simp only [rollThenClear, pickThenClear, clear_after_roll hashes rest i hi,
             List.drop_left]

#print axioms same_selected_value_and_suffix
end QSB.DestructiveChain
