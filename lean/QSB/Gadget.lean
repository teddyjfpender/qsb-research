import QSB.Exec

/-!
# M2 (part 2): the HORS selection gadget on a region with holes

`gadget_spec` is the block lemma the selection loop is built from: exact stack effect and exact
trace of one selection, for any unknown witness suffix and any crypto.
-/

namespace QSB.Gadget
open QSB QSB.Soundness QSB.Exec

def gadget (dx B c1 dp : Nat) : List Instr :=
  [.push (numEnc dx), .op .roll, .push (numEnc B), .op .min, .op .dup, .push (numEnc c1), .op .add,
   .op .roll, .push (numEnc dp), .op .roll, .op .hash160, .op .equalVerify, .op .roll]

def g1 (dx B c1 dp : Nat) : List Instr :=
  [.push (numEnc dx), .op .roll, .push (numEnc B), .op .min, .op .dup, .push (numEnc c1), .op .add,
   .op .roll, .push (numEnc dp), .op .roll]

theorem gadget_split (dx B c1 dp : Nat) : gadget dx B c1 dp =
    g1 dx B c1 dp ++ (.op .hash160 :: [.op .equalVerify, .op .roll]) := rfl

theorem eraseIdx_region (P D C S : List Bytes) (j : Nat) (hj : j < C.length) :
    (P ++ D ++ C ++ S).eraseIdx (P.length + D.length + j) = P ++ D ++ C.eraseIdx j ++ S := by
  simp only [List.append_assoc]
  rw [List.eraseIdx_append_of_length_le (l := P) (by omega),
    List.eraseIdx_append_of_length_le (l := D) (by omega)]
  have e : P.length + D.length + j - P.length - D.length = j := by omega
  rw [e, List.eraseIdx_append_of_lt_length (l := C) hj]

theorem eraseIdx_region2 (P D C S : List Bytes) (j : Nat) (hj : j < D.length) :
    (P ++ D ++ C ++ S).eraseIdx (P.length + j) = P ++ D.eraseIdx j ++ C ++ S := by
  simp only [List.append_assoc]
  rw [List.eraseIdx_append_of_length_le (l := P) (by omega)]
  have e : P.length + j - P.length = j := by omega
  rw [e, List.eraseIdx_append_of_lt_length (l := D) hj]

theorem get_region_C (P D C S : List Bytes) (j : Nat) (hj : j < C.length) :
    (P ++ D ++ C ++ S)[P.length + D.length + j]? = C[j]? := by
  rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (by omega),
    List.getElem?_append_right (by omega), List.getElem?_append_left (by omega)]
  congr 1; omega

theorem get_region_D (P D C S : List Bytes) (j : Nat) (hj : j < D.length) :
    (P ++ D ++ C ++ S)[P.length + j]? = D[j]? := by
  rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (by omega),
    List.getElem?_append_left (by omega)]
  congr 1; omega

/-- **The selection gadget on a region with holes.** Above the region: `A` items `P`; then the `m`
remaining dummies and their `m` commitments (aligned), then the pool `Ps` (length `k`) and an
unknown witness suffix. If the region is at least as large as `P` and no dummy is 20 bytes, a
successful run selects some `j < m`: HASH160 of a witness item equals the `j`-th remaining
commitment, the `j`-th remaining dummy ends on top, and both leave the region. The trace is that
single HASH160 event. -/
theorem gadget_spec (c : Ctx) (h20 : ∀ b, (c.crypto.hash160 b).length = 20)
    (P D C Ps W : List Bytes) (A m k dx dp : Nat)
    (hP : P.length = A) (hD : D.length = m) (hC : C.length = m) (hK : Ps.length = k)
    (hAm : A ≤ m) (hm : 1 ≤ m) (hsmall : m + 1 < 2 ^ 31)
    (hdx : A + 2 * m + k ≤ dx) (hdp : A + 2 * m + 1 + k ≤ dp)
    (hshort : ∀ y ∈ D, y.length ≠ 20) (n0 : Nat) (s1 : St)
    (h : run c (gadget dx (A + m - 1) (m + 1) dp) ⟨P ++ D ++ C ++ Ps ++ W, n0⟩ = .ok s1) :
    ∃ j Cj Dj Pre W', j < m ∧ C[j]? = some Cj ∧ D[j]? = some Dj ∧ c.crypto.hash160 Pre = Cj ∧
      s1.stack = Dj :: (P ++ D.eraseIdx j ++ C.eraseIdx j ++ Ps ++ W') ∧
      trace c (gadget dx (A + m - 1) (m + 1) dp) ⟨P ++ D ++ C ++ Ps ++ W, n0⟩ = [.heq Pre Cj] := by
  obtain ⟨pre, hpre⟩ : ∃ pre, pre = P ++ D ++ C ++ Ps := ⟨_, rfl⟩
  have hlen : pre.length = A + 2 * m + k := by subst hpre; simp; omega
  have hst0 : P ++ D ++ C ++ Ps ++ W = pre ++ W := by subst hpre; rfl
  rw [hst0] at h ⊢
  rw [gadget_split] at h ⊢
  obtain ⟨s10, h1, h2⟩ := run_append_ok h
  rw [trace_append_ok h1, trace_plain c _ _ rfl, List.nil_append]
  obtain ⟨s11, hstep, -, h3⟩ := step_ok_of_run h2
  rw [trace_cons_ok hstep, trace_plain c _ _ rfl, List.append_nil]
  -- the first ten instructions
  simp only [g1] at h1
  have h1 := peel_push h1
  obtain ⟨X, W1, _, h1⟩ := peel_roll_deep (pre := pre) (by omega) h1
  have h1 := peel_push h1
  obtain ⟨v, hvB, _, h1⟩ := peel_minB h1
  obtain ⟨_, h1⟩ := peel_dup h1
  have h1 := peel_push h1
  obtain ⟨_, h1⟩ := peel_add h1
  obtain ⟨st5, n5, h5, h1⟩ := peel_op h1
  obtain ⟨nb, r, u, Y, hst, hu, hu0, hY, hs⟩ := roll_ok h5
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc' rfl hu
  simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
  have h1 := peel_push h1
  rcases hut : (v + ((m + 1 : Nat) : Int)).toNat with _ | u'
  · -- index 0 re-rolls the number: EQUALVERIFY would equate a 20-byte hash with a short number
    exfalso
    rw [hut] at hY h1
    simp only [List.getElem?_cons_zero, Option.some.injEq] at hY; subst hY
    simp only [List.eraseIdx_cons_zero] at h1
    obtain ⟨Z, W2, _, h1⟩ := peel_roll_deep (pre := numEnc v :: pre) (by simp; omega) h1
    cases run_nil h1
    obtain ⟨_, h3'⟩ := peel_hash160 h2
    obtain ⟨he, -⟩ := peel_eqv h3'
    have hl := congrArg List.length he
    rw [h20] at hl
    have hv : v = -((m + 1 : Nat) : Int) := by omega
    have := numEnc_short v (by omega)
    omega
  · rw [hut] at hY h1
    have hu' : (u' : Int) = v + m := by omega
    have hu'lt : u' < pre.length := by omega
    simp only [List.getElem?_cons_succ] at hY
    rw [List.getElem?_append_left hu'lt] at hY
    simp only [List.eraseIdx_cons_succ] at h1
    rw [List.eraseIdx_append_of_lt_length hu'lt] at h1
    obtain ⟨Z, W2, _, h1⟩ := peel_roll_deep (pre := Y :: numEnc v :: pre.eraseIdx u')
      (by simp [List.length_eraseIdx, hu'lt]; omega) h1
    cases run_nil h1
    obtain ⟨_, h3'⟩ := peel_hash160 h2
    obtain ⟨he, _, h3'⟩ := peel_eqv h3'
    obtain ⟨st6, n6, h6, h3'⟩ := peel_op h3'
    obtain ⟨nb, r, w, Dj, hst, hw, hw0, hDj, hs⟩ := roll_ok h6
    obtain ⟨rfl, rfl⟩ := List.cons.inj hst
    cases num4_numEnc' rfl hw
    simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
    cases run_nil h3'
    -- v >= A: otherwise the "commitment" is a dummy, never equal to a 20-byte hash
    by_cases hvA : v < A
    · exfalso
      have hget := get_region_D P D C Ps (u' - A) (by omega)
      rw [hP, show A + (u' - A) = u' by omega, ← hpre, hY] at hget
      have hmem := List.mem_of_getElem? hget.symm
      have := hshort Y hmem
      rw [← he, h20] at this
      exact this rfl
    · obtain ⟨j, hj⟩ : ∃ j : Nat, v = A + j := ⟨(v - A).toNat, by omega⟩
      subst hj
      have hjm : j < m := by omega
      have hCj := get_region_C P D C Ps j (by omega)
      rw [hP, hD, show A + m + j = u' by omega, ← hpre, hY] at hCj
      have hvt : ((A : Int) + j).toNat = A + j := by omega
      rw [hvt] at hDj ⊢
      simp only [List.append_eq] at hDj ⊢
      rw [List.getElem?_append_left (by simp [List.length_eraseIdx, hu'lt]; omega),
        List.getElem?_eraseIdx_of_lt (by omega)] at hDj
      have hDj' := get_region_D P D C Ps j (by omega)
      rw [hP, ← hpre, hDj] at hDj'
      refine ⟨j, Y, Dj, Z, W2, hjm, hCj.symm, hDj'.symm, he, ?_, rfl⟩
      rw [List.eraseIdx_append_of_lt_length (by simp [List.length_eraseIdx, hu'lt]; omega)]
      have e1 := eraseIdx_region P D C Ps j (by omega)
      rw [hP, hD, show A + m + j = u' by omega, ← hpre] at e1
      rw [e1]
      have e2 := eraseIdx_region2 P D (C.eraseIdx j) Ps j (by omega)
      rw [hP] at e2
      rw [e2]

end QSB.Gadget
