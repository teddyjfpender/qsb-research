import QSB.Script

/- Local lemmas for the cost-model finding. This is not a formal security proof
   for D/E, a formal derivation of the rate table, or a universal time bound. -/
namespace QSB.DERBudget
open QSB

theorem valid_has_nonempty_s (sig : Bytes)
    (h : isValidSigEncoding sig = true) :
    (sig.getD (5 + (sig.getD 3 0).toNat) 0).toNat ≠ 0 := by
  intro hs
  simp only [List.getD_eq_getElem?_getD] at hs
  simp [isValidSigEncoding, hs] at h

theorem valid_layout_range (L r s : Nat)
    (hr : 0 < r) (hs : 0 < s) (hlen : r + s + 7 = L) :
    1 ≤ r ∧ r < L - 7 := by omega

theorem excluded_endpoint_has_empty_s (L r s : Nat)
    (hlen : r + s + 7 = L) (hr : r = L - 7) : s = 0 := by omega

/- For success probabilities a/b and c/d, clear the positive common denominator
   a*c. The retry cost A/(p1*p2) + B/p2 + C is at least A+B+C. This integer
   inequality is the numerator statement for nonnegative rational stage costs,
   after also clearing their common denominator. -/
theorem retries_cannot_reduce_cost (A B C a b c d : Nat)
    (h1 : a ≤ b) (h2 : c ≤ d) :
    (A + B + C) * (a * c) ≤ A * (b * d) + B * (a * d) + C * (a * c) := by
  have h3 : a * c ≤ b * d := Nat.mul_le_mul h1 h2
  have h4 : a * c ≤ a * d := Nat.mul_le_mul_left a h2
  rw [Nat.add_mul, Nat.add_mul]
  exact Nat.add_le_add_right
    (Nat.add_le_add (Nat.mul_le_mul_left A h3) (Nat.mul_le_mul_left B h4)) _

/- Arithmetic checks for the exact fractions emitted in results.json. The Python
   certificate, not these two closed inequalities, derives them from rates.json. -/
theorem frozen_fraction_exceeds_two :
    2 * 10929834741729111328125 < 26928499352725973106688 := by decide

theorem corrected_fraction_exceeds_two :
    2 * 5044792580520732421875 < 13464249676362986553344 := by decide

#print axioms valid_has_nonempty_s
#print axioms valid_layout_range
#print axioms excluded_endpoint_has_empty_s
#print axioms retries_cannot_reduce_cost
#print axioms frozen_fraction_exceeds_two
#print axioms corrected_fraction_exceeds_two
end QSB.DERBudget
