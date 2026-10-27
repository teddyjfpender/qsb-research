import QSB.Script

/- Local stack identity for the proposed selection gadget. Lists are top-first.
   The witness index is one greater than the commitment's position, because its
   original copy is still on the stack during the first ROLL. After authenticating
   and consuming the commitment and removing the index, that same number names
   the paired dummy. This does not prove full-family script soundness. -/
namespace QSB.SpacerSelection
open QSB

def pairAt (items : List Bytes) (i : Nat) : Option (Bytes × Bytes × List Bytes) := do
  let c ← items[i]?
  let afterC := items.eraseIdx i
  let d ← afterC[i+1]?
  pure (c, d, afterC.eraseIdx (i+1))

theorem selects_paired_dummy (front suffix : List Bytes) (c spacer d : Bytes) :
    pairAt (front ++ c :: spacer :: d :: suffix) front.length =
      some (c, d, front ++ spacer :: suffix) := by
  simp [pairAt, List.eraseIdx_append_of_length_le]

end QSB.SpacerSelection
