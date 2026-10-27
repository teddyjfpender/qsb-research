import QSB.Script

/- Local interpreter facts used to reject candidate shortcuts. These lemmas do
   not classify every possible Bitcoin construction or every Script program. -/
namespace QSB.PredicateCatalog
open QSB

theorem long_values_are_not_numbers (b : Bytes) (h : 4 < b.length) :
    num4 b = .error .numOverflow := by simp [num4, h]

theorem hash20_not_number (b : Bytes) (h : b.length = 20) :
    num4 b = .error .numOverflow := by simp [num4, h]

theorem hash32_not_number (b : Bytes) (h : b.length = 32) :
    num4 b = .error .numOverflow := by simp [num4, h]

theorem size_only_reveals_length (c : Ctx) (b : Bytes) (tail : List Bytes)
    (ops L : Nat) (h : b.length = L) :
    stepOp c .size ⟨b :: tail, ops⟩ = .ok ⟨numEnc L :: b :: tail, ops⟩ := by
  simp [stepOp, h]

theorem bool_false_condition (b : Bytes) (last : UInt8) (h : b.getLast? = some last) :
    castToBool b = false ↔
      b.dropLast.any (· != 0) = false ∧ (last = 0 ∨ last = 0x80) := by
  by_cases hzero : last = 0 <;> simp [castToBool, h, hzero]

theorem nonder_is_error (c : Ctx) (sig pk : Bytes) (tail : List Bytes) (ops : Nat)
    (hne : sig ≠ []) (hder : isValidSigEncoding sig = false) :
    stepOp c .checkSig ⟨pk :: sig :: tail, ops⟩ = .error .sigDer := by
  simp [stepOp, hne, hder]

theorem cms_can_skip_arbitrary_second_signature (c : Ctx)
    (sc first second badKey otherKey : Bytes)
    (hder : isValidSigEncoding first = true)
    (hfail : c.crypto.checkSig first badKey sc = false) :
    cmsLoop c sc [first, second] [badKey, otherKey] = .ok false := by
  simp [cmsLoop, hder, hfail]

#print axioms long_values_are_not_numbers
#print axioms hash20_not_number
#print axioms hash32_not_number
#print axioms size_only_reveals_length
#print axioms bool_false_condition
#print axioms nonder_is_error
#print axioms cms_can_skip_arbitrary_second_signature
end QSB.PredicateCatalog
