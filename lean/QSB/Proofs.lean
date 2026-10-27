import QSB.Script
import Std.Tactic.BVDecide

/-!
# Proofs about the script model

* `numDec_numEnc`: CScriptNum decoding inverts encoding (for every integer).
* per-opcode success characterisations (`roll_ok`, `min_ok`, ...).
* `hors_gadget`: exact effect of the HORS selection gadget on an arbitrary stack.
* `hors_select`: on the builder's region layout, a successful selection opens the commitment and
  deletes-selects the dummy *at the same position* (the binding the security proof relies on).
* FindAndDelete facts: PUSHDATA1 pushes are never matched by a minimal-push pattern, and
  `findAndDelete` is the identity when no opcode of the script starts with the pattern's first byte.
* `run_no_opcount`: the static op count bounds the runtime counter, so `staticOps <= 201` rules out
  an op-count failure on *every* execution (any witness, any crypto).
-/

namespace QSB


theorem leVal_append (l : Bytes) (a : UInt8) : leVal (l ++ [a]) = leVal l + 256 ^ l.length * a.toNat := by
  induction l with
  | nil => simp [leVal]
  | cons b bs ih =>
    simp only [List.cons_append, leVal, ih, List.length_cons, Nat.pow_succ, Nat.mul_add]
    rw [Nat.mul_comm (256 ^ bs.length) 256, Nat.mul_assoc]; omega

theorem u8_fin (P : UInt8 → Prop) [DecidablePred P] (h : ∀ n : Fin 256, P (UInt8.ofNat n.val)) (a : UInt8) : P a := by
  have := h ⟨a.toNat, a.toNat_lt⟩
  simpa using this

theorem u8_or (a : UInt8) (h : a < 128) : 128 ≤ a ||| 0x80 := by
  revert h
  exact u8_fin (fun a => a < 128 → 128 ≤ a ||| 0x80) (by decide +kernel) a
theorem u8_orand (a : UInt8) (h : a < 128) : (a ||| 0x80) &&& 0x7f = a := by
  revert h
  exact u8_fin (fun a => a < 128 → (a ||| 0x80) &&& 0x7f = a) (by decide +kernel) a
theorem u8_and0 : ((0x80 : UInt8) &&& 0x7f) = 0 := by decide

theorem leVal_natLE (n : Nat) : leVal (natLE n) = n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    unfold natLE
    split
    · simp_all [leVal]
    · simp only [leVal]
      rw [ih (n / 256) (by omega)]
      simp [UInt8.toNat_ofNat]; omega

theorem natLE_nil_iff (n : Nat) : natLE n = [] ↔ n = 0 := by
  unfold natLE; split <;> simp_all

theorem numDec_numEnc (i : Int) : numDec (numEnc i) = i := by
  unfold numEnc
  have hv := leVal_natLE i.natAbs
  generalize natLE i.natAbs = m at hv ⊢
  rcases List.eq_nil_or_concat m with h | ⟨init, last, h⟩
  · subst h; simp [leVal] at hv; simp [numDec]; omega
  · subst h
    rw [List.concat_eq_append] at hv ⊢
    simp only [List.getLast?_append, List.getLast?_singleton, Option.some_or]
    rw [leVal_append] at hv
    by_cases htop : 128 ≤ last.toNat
    · rw [if_pos htop]
      by_cases hi : i < 0
      · simp only [hi, if_true, numDec, List.getLast?_append, List.getLast?_singleton, Option.some_or, List.dropLast_concat, List.dropLast_append_of_ne_nil]
        rw [if_pos (by decide), u8_and0, leVal_append, leVal_append]
        simp
        have e : ((leVal init : Int) + 256 ^ init.length * (last.toNat : Int)) = ((leVal init + 256 ^ init.length * last.toNat : Nat) : Int) := by rw [Int.natCast_add, Int.natCast_mul, Int.natCast_pow]; rfl
        rw [e, hv]; omega
      · simp only [hi, if_false, numDec, List.getLast?_append, List.getLast?_singleton, Option.some_or, List.dropLast_concat, List.dropLast_append_of_ne_nil]
        rw [if_neg (by decide), leVal_append, leVal_append]
        simp
        have e : ((leVal init : Int) + 256 ^ init.length * (last.toNat : Int)) = ((leVal init + 256 ^ init.length * last.toNat : Nat) : Int) := by rw [Int.natCast_add, Int.natCast_mul, Int.natCast_pow]; rfl
        rw [e, hv]; omega
    · rw [if_neg htop]
      have hlt : last < 128 := by
        rw [UInt8.lt_iff_toNat_lt]; simp; omega
      by_cases hi : i < 0
      · simp only [hi, if_true, numDec, List.dropLast_concat, List.dropLast_append_of_ne_nil, List.getLast?_append, List.getLast?_singleton, Option.some_or]
        have h1 := u8_or last hlt
        rw [UInt8.le_iff_toNat_le] at h1
        simp only [UInt8.toNat_ofNat] at h1
        rw [if_pos (by simpa using h1), u8_orand last hlt, leVal_append]
        omega
      · simp only [hi, if_false, numDec, List.getLast?_append, List.getLast?_singleton, Option.some_or]
        rw [if_neg htop, leVal_append]
        omega

theorem bind_ok {α β ε} {x : Except ε α} {f : α → Except ε β} {y : β} (h : x.bind f = .ok y) :
    ∃ a, x = .ok a ∧ f a = .ok y := by
  cases x with
  | error e => simp [Except.bind] at h
  | ok a => exact ⟨a, rfl, by simpa [Except.bind] using h⟩

theorem run_cons_ok {c i is s s'} (h : run c (i :: is) s = .ok s') :
    ∃ s1, stepCore c i s = .ok s1 ∧ run c is s1 = .ok s' := by
  simp only [run] at h
  obtain ⟨s0, h0, h1⟩ := bind_ok h
  simp only [step] at h0
  obtain ⟨s1, h2, h3⟩ := bind_ok h0
  split at h3
  · simp at h3
  · injection h3 with h3; subst h3; exact ⟨_, h2, h1⟩

theorem push_ok {c d s s1} (h : stepCore c (.push d) s = .ok s1) : s1 = { s with stack := d :: s.stack } := by
  simp only [stepCore] at h; split at h <;> simp_all

theorem op_ok {c o s s1} (h : stepCore c (.op o) s = .ok s1) : stepOp c o { s with ops := s.ops + 1 } = .ok s1 := by
  simp only [stepCore] at h; split at h <;> simp_all

theorem num4_ok {b v} (h : num4 b = .ok v) : v = numDec b := by
  unfold num4 at h; split at h <;> simp_all

theorem roll_ok {c st ops s'} (h : stepOp c .roll ⟨st, ops⟩ = .ok s') :
    ∃ nb r n y, st = nb :: r ∧ num4 nb = .ok n ∧ 0 ≤ n ∧ r[n.toNat]? = some y ∧
      s' = ⟨y :: r.eraseIdx n.toNat, ops⟩ := by
  rcases st with _ | ⟨nb, _ | ⟨b, r⟩⟩ <;> simp [stepOp] at h
  obtain ⟨n, hn, h⟩ := bind_ok h
  split at h
  · rename_i hc; cases h
    exact ⟨nb, b :: r, n, _, rfl, hn, hc.1, List.getElem?_eq_getElem _, rfl⟩
  · simp at h

theorem min_ok {c st ops s'} (h : stepOp c .min ⟨st, ops⟩ = .ok s') :
    ∃ b a r x y, st = b :: a :: r ∧ num4 a = .ok x ∧ num4 b = .ok y ∧
      s' = ⟨numEnc (if x < y then x else y) :: r, ops⟩ := by
  rcases st with _ | ⟨b, _ | ⟨a, r⟩⟩ <;> simp [stepOp] at h
  obtain ⟨x, hx, h⟩ := bind_ok h
  obtain ⟨y, hy, h⟩ := bind_ok h
  cases h; exact ⟨b, a, r, x, y, rfl, hx, hy, rfl⟩

theorem add_ok {c st ops s'} (h : stepOp c .add ⟨st, ops⟩ = .ok s') :
    ∃ b a r x y, st = b :: a :: r ∧ num4 a = .ok x ∧ num4 b = .ok y ∧
      s' = ⟨numEnc (x + y) :: r, ops⟩ := by
  rcases st with _ | ⟨b, _ | ⟨a, r⟩⟩ <;> simp [stepOp] at h
  obtain ⟨x, hx, h⟩ := bind_ok h
  obtain ⟨y, hy, h⟩ := bind_ok h
  cases h; exact ⟨b, a, r, x, y, rfl, hx, hy, rfl⟩

theorem dup_ok {c st ops s'} (h : stepOp c .dup ⟨st, ops⟩ = .ok s') :
    ∃ a r, st = a :: r ∧ s' = ⟨a :: a :: r, ops⟩ := by
  rcases st with _ | ⟨a, r⟩ <;> simp [stepOp] at h
  cases h; exact ⟨a, r, rfl, rfl⟩

theorem hash160_ok {c st ops s'} (h : stepOp c .hash160 ⟨st, ops⟩ = .ok s') :
    ∃ a r, st = a :: r ∧ s' = ⟨c.crypto.hash160 a :: r, ops⟩ := by
  rcases st with _ | ⟨a, r⟩ <;> simp [stepOp] at h
  cases h; exact ⟨a, r, rfl, rfl⟩

theorem eqv_ok {c st ops s'} (h : stepOp c .equalVerify ⟨st, ops⟩ = .ok s') :
    ∃ a r, st = a :: a :: r ∧ s' = ⟨r, ops⟩ := by
  rcases st with _ | ⟨a, _ | ⟨b, r⟩⟩ <;> simp [stepOp] at h
  split at h
  · rename_i hab; cases h; subst hab; exact ⟨a, r, rfl, rfl⟩
  · simp at h

theorem natLE_length_le (n k : Nat) (h : n < 256 ^ k) : (natLE n).length ≤ k := by
  induction k generalizing n with
  | zero => simp at h; subst h; simp [natLE]
  | succ k ih =>
    unfold natLE
    split
    · simp
    · simp only [List.length_cons]
      have := ih (n / 256) (by rw [Nat.pow_succ] at h; omega)
      omega

theorem numEnc_length_le (i : Int) : (numEnc i).length ≤ (natLE i.natAbs).length + 1 := by
  unfold numEnc
  generalize natLE i.natAbs = m
  rcases List.eq_nil_or_concat m with h | ⟨init, last, h⟩
  · subst h; simp
  · subst h
    rw [List.concat_eq_append]
    simp only [List.getLast?_append, List.getLast?_singleton, Option.some_or]
    split
    · simp
    · split <;> simp

/-- A script number of magnitude < 2^31 is at most 5 bytes, so never a 20-byte hash. -/
theorem numEnc_short (i : Int) (h : i.natAbs < 2 ^ 31) : (numEnc i).length ≤ 5 := by
  have := natLE_length_le i.natAbs 4 (by omega)
  have := numEnc_length_le i
  omega

/-- The HORS selection gadget emitted once per signed selection (qsb_pool.build, round loop):
`<dx> ROLL <B> MIN DUP <c1> ADD ROLL <dpre> ROLL HASH160 EQUALVERIFY ROLL`. -/
def horsGadget (dx B c1 dpre : Int) : List Instr :=
  [.push (numEnc dx), .op .roll, .push (numEnc B), .op .min, .op .dup, .push (numEnc c1), .op .add,
   .op .roll, .push (numEnc dpre), .op .roll, .op .hash160, .op .equalVerify, .op .roll]

theorem num4_numEnc {v x : Int} (h : num4 (numEnc v) = .ok x) : x = v := by
  rw [num4_ok h, numDec_numEnc]

theorem hors_gadget (c : Ctx) (dx B c1 dpre : Int) (hc1 : 1 ≤ c1) (hc1' : c1 < 2 ^ 31) (hdpre : 2 ≤ dpre)
    (h20 : ∀ b, (c.crypto.hash160 b).length = 20)
    (st : List Bytes) (ops : Nat) (s' : St)
    (h : run c (horsGadget dx B c1 dpre) ⟨st, ops⟩ = .ok s') :
    ∃ (X : Bytes) (x : Int), 0 ≤ dx ∧ st[dx.toNat]? = some X ∧ num4 X = .ok x ∧
      0 ≤ min x B ∧
      ∃ C Pre D,
        (st.eraseIdx dx.toNat)[(min x B + c1 - 1).toNat]? = some C ∧
        ((st.eraseIdx dx.toNat).eraseIdx (min x B + c1 - 1).toNat)[(dpre - 2).toNat]? = some Pre ∧
        c.crypto.hash160 Pre = C ∧
        (((st.eraseIdx dx.toNat).eraseIdx (min x B + c1 - 1).toNat).eraseIdx (dpre - 2).toNat)[(min x B).toNat]? = some D ∧
        s' = ⟨D :: ((((st.eraseIdx dx.toNat).eraseIdx (min x B + c1 - 1).toNat).eraseIdx (dpre - 2).toNat).eraseIdx
                (min x B).toNat), ops + 9⟩ := by
  simp only [horsGadget] at h
  -- <dx> ROLL: the witness index x comes to the top
  obtain ⟨s1, h1, h⟩ := run_cons_ok h; cases push_ok h1
  obtain ⟨s2, h2, h⟩ := run_cons_ok h
  obtain ⟨nb, r, n, X, hst, hn4, hn0, hX, rfl⟩ := roll_ok (op_ok h2)
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc hn4
  -- <B> MIN
  obtain ⟨s3, h3, h⟩ := run_cons_ok h; cases push_ok h3
  obtain ⟨s4, h4, h⟩ := run_cons_ok h
  obtain ⟨b, a, r2, x, y, hst, hx, hy, rfl⟩ := min_ok (op_ok h4)
  simp only [List.cons.injEq] at hst; obtain ⟨rfl, rfl, rfl⟩ := hst
  cases num4_numEnc hy
  have hmin : (if x < B then x else B) = min x B := by
    by_cases hxb : x < B
    · rw [if_pos hxb]; omega
    · rw [if_neg hxb]; omega
  rw [hmin] at h
  -- DUP <c1> ADD
  obtain ⟨s5, h5, h⟩ := run_cons_ok h
  obtain ⟨a5, r5, hst, rfl⟩ := dup_ok (op_ok h5)
  simp only [List.cons.injEq] at hst; obtain ⟨rfl, rfl⟩ := hst
  obtain ⟨s6, h6, h⟩ := run_cons_ok h; cases push_ok h6
  obtain ⟨s7, h7, h⟩ := run_cons_ok h
  obtain ⟨b7, a7, r7, x7, y7, hst, hx7, hy7, rfl⟩ := add_ok (op_ok h7)
  simp only [List.cons.injEq] at hst; obtain ⟨rfl, rfl, rfl⟩ := hst
  cases num4_numEnc hx7; cases num4_numEnc hy7
  -- ROLL: the commitment
  obtain ⟨s8, h8, h⟩ := run_cons_ok h
  obtain ⟨nb8, r8, n8, C, hst, hn8, hn80, hCget, rfl⟩ := roll_ok (op_ok h8)
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc hn8
  rcases hk : (min x B + c1).toNat with _ | k
  · -- index 0 re-rolls the number itself: EQUALVERIFY would compare a hash with a <= 5-byte number
    exfalso
    rw [hk] at hCget; simp at hCget; subst hCget
    obtain ⟨s9, h9, h⟩ := run_cons_ok h; cases push_ok h9
    obtain ⟨s10, h10, h⟩ := run_cons_ok h
    obtain ⟨nb10, r10, n10, Pre, hst, hn10, hn100, hPget, rfl⟩ := roll_ok (op_ok h10)
    obtain ⟨rfl, rfl⟩ := List.cons.inj hst
    cases num4_numEnc hn10
    obtain ⟨s11, h11, h⟩ := run_cons_ok h
    obtain ⟨a11, r11, hst, rfl⟩ := hash160_ok (op_ok h11)
    obtain ⟨rfl, rfl⟩ := List.cons.inj hst
    obtain ⟨s12, h12, h⟩ := run_cons_ok h
    obtain ⟨a12, r12, hst, rfl⟩ := eqv_ok (op_ok h12)
    have hdp : dpre.toNat = (dpre - 2).toNat + 2 := by omega
    rw [hk, hdp] at hst
    simp only [List.eraseIdx_cons_zero, List.eraseIdx_cons_succ, List.cons.injEq] at hst
    obtain ⟨hH, hC, -⟩ := hst
    have e := congrArg List.length (hH.trans hC.symm)
    rw [h20] at e
    have := numEnc_short (min x B) (by omega)
    omega
  -- <dpre> ROLL: the preimage
  obtain ⟨s9, h9, h⟩ := run_cons_ok h; cases push_ok h9
  obtain ⟨s10, h10, h⟩ := run_cons_ok h
  obtain ⟨nb10, r10, n10, Pre, hst, hn10, hn100, hPget, rfl⟩ := roll_ok (op_ok h10)
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc hn10
  -- HASH160 EQUALVERIFY
  obtain ⟨s11, h11, h⟩ := run_cons_ok h
  obtain ⟨a11, r11, hst, rfl⟩ := hash160_ok (op_ok h11)
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  obtain ⟨s12, h12, h⟩ := run_cons_ok h
  obtain ⟨a12, r12, hst, rfl⟩ := eqv_ok (op_ok h12)
  -- ROLL: the dummy
  obtain ⟨s13, h13, h⟩ := run_cons_ok h
  simp only [run] at h; cases h
  obtain ⟨nb13, r13, n13, D, hst13, hn13, hn130, hDget, rfl⟩ := roll_ok (op_ok h13)
  subst hst13
  have hdp : dpre.toNat = (dpre - 2).toNat + 2 := by omega
  rw [hdp] at hst hPget ⊢
  rw [hk] at hst hPget
  simp only [List.eraseIdx_cons_succ, List.getElem?_cons_succ, List.cons.injEq] at hst hPget
  obtain ⟨hH, hC, h3', h4'⟩ := hst
  subst h3'; subst h4'
  cases num4_numEnc hn13
  have hk' : (min x B + c1 - 1).toNat = k := by omega
  rw [hk] at hCget
  simp only [List.getElem?_cons_succ] at hCget
  refine ⟨_, x, hn0, hX, hx, hn130, C, Pre, D, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hk']; exact hCget
  · rw [hk']; exact hPget
  · rw [hH, hC]
  · rw [hk']; exact hDget
  · rw [hk']

/-- The HORS selection on the builder's region layout: above the region sit `A` items `P`, then the
`m` remaining dummies `Ds` (topmost first), then their `m` commitments `Cs` in the same order, then
the rest `S`, with the preimage below the region. If no dummy is 20 bytes long (they are 9-10 byte
signatures), every successful run either

* selected some region position `j < m`: it opened *that* position's commitment and put *that*
  position's dummy on top; or
* (only possible when `A > m`) opened an item `P[i]`, `m <= i < A`, *above* the region, i.e. the
  witness supplied a HASH160 preimage of that item.

Nothing is assumed about `P`. For the 2-stage tiers `A <= m` holds at every selection
(`TierProofs.plan_in_region`) so only the first case exists. For 3-stage tiers, round 2's `P` holds
round 1's unused region (its unrevealed commitments), so the second case needs a preimage the
HORS signer never revealed. -/
theorem hors_select (c : Ctx) (h20 : ∀ b, (c.crypto.hash160 b).length = 20)
    (P Ds Cs S : List Bytes) (A m : Nat) (hP : P.length = A) (hD : Ds.length = m) (hC : Cs.length = m)
    (hm : 1 ≤ m) (hsz : m + 1 < 2 ^ 31) (hshort : ∀ y ∈ Ds, y.length ≠ 20)
    (dx dpre : Int) (hdpre : (A + 2 * m + 1 : Int) ≤ dpre)
    (st : List Bytes) (hst : st.eraseIdx dx.toNat = P ++ Ds ++ Cs ++ S) (ops : Nat) (s' : St)
    (h : run c (horsGadget dx (A + m - 1 : Nat) (1 + m : Nat) dpre) ⟨st, ops⟩ = .ok s') :
    (∃ j Pre, j < m ∧ Cs[j]? = some (c.crypto.hash160 Pre) ∧ ∃ rest, s'.stack = Ds[j]! :: rest) ∨
    (∃ i Pre, m ≤ i ∧ i < A ∧ P[i]? = some (c.crypto.hash160 Pre)) := by
  obtain ⟨X, x, hdx, hX, hx, hv0, C, Pre, D, hCg, hPg, hH, hDg, rfl⟩ :=
    hors_gadget c dx _ _ dpre (by omega) (by omega) (by omega) h20 st ops s' h
  rw [hst] at hCg hPg hDg
  have hvle : min x ((A + m - 1 : Nat) : Int) ≤ A + m - 1 := by omega
  generalize hv : min x ((A + m - 1 : Nat) : Int) = v at *
  have hci : (v + ((1 + m : Nat) : Int) - 1).toNat = v.toNat + m := by omega
  rw [hci] at hCg hPg hDg
  by_cases hvA : A ≤ v.toNat
  · left
    refine ⟨v.toNat - A, Pre, by omega, ?_, ?_⟩
    · have : (P ++ Ds ++ Cs ++ S)[v.toNat + m]? = Cs[v.toNat - A]? := by
        rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (by omega),
            List.getElem?_append_right (by omega), List.getElem?_append_left (by omega)]
        congr 1; omega
      rw [← this, hCg, hH]
    · -- the dummy index v sits above both removed positions (v + m and the preimage)
      have hDeq : D = Ds[v.toNat - A]! := by
        rw [List.getElem?_eraseIdx_of_lt (by omega), List.getElem?_eraseIdx_of_lt (by omega)] at hDg
        have : (P ++ Ds ++ Cs ++ S)[v.toNat]? = Ds[v.toNat - A]? := by
          rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (by omega),
              List.getElem?_append_left (by omega), hP]
        rw [this] at hDg
        rw [List.getElem!_eq_getElem?_getD, hDg]; rfl
      subst hDeq
      exact ⟨_, rfl⟩
  · by_cases hin : v.toNat + m < A
    · right
      refine ⟨v.toNat + m, Pre, by omega, hin, ?_⟩
      rw [hH, ← hCg, List.append_assoc, List.append_assoc, List.getElem?_append_left (by omega)]
    · exfalso
      have e : (P ++ Ds ++ Cs ++ S)[v.toNat + m]? = Ds[v.toNat + m - A]? := by
        rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (by omega),
            List.getElem?_append_left (by omega), hP]
      rw [e] at hCg
      have hmem : C ∈ Ds := List.mem_of_getElem? hCg
      have := hshort C hmem
      rw [← hH, h20] at this
      exact this rfl

/-! ## FindAndDelete -/

/-- A minimal push of a short signature (< 76 bytes) never matches at a PUSHDATA1 opcode: the
pattern starts with the length byte (< 0x4c), the opcode byte is 0x4c. This is why the nonce-pool
signatures, pushed with PUSHDATA1, survive every FindAndDelete. -/
theorem pushMin_not_prefix_pushdata1 (sig d rest : Bytes) (h : sig.length < 0x4c) :
    (pushMin sig).isPrefixOf (0x4c :: d.length.toUInt8 :: d ++ rest) = false := by
  unfold pushMin
  rw [if_pos h]
  simp only [List.isPrefixOf, List.cons_append, Bool.and_eq_false_iff]
  left
  have : sig.length.toUInt8 ≠ 0x4c := by
    intro e
    have := congrArg UInt8.toNat e
    simp [Nat.toUInt8, UInt8.toNat_ofNat] at this
    omega
  simpa using this

/-- First byte of every operation of a script (Core's GetOp boundaries), with fuel. -/
def opHeadsF : Nat → Bytes → List UInt8
  | _, [] => []
  | 0, _ => []
  | f + 1, b :: rest =>
    b :: (match opLen (b :: rest) with
          | some n => opHeadsF f ((b :: rest).drop n)
          | none => [])

def opHeads (s : Bytes) : List UInt8 := opHeadsF (s.length + 1) s

theorem stripMatches_nomatch (pat s : Bytes) (h : pat.isPrefixOf s = false) : stripMatches pat s = s := by
  unfold stripMatches
  rw [dif_neg]
  simp [h]

theorem findAndDeleteF_id (p0 : UInt8) (pr : Bytes) :
    ∀ (f : Nat) (s : Bytes), p0 ∉ opHeadsF f s → findAndDeleteF (p0 :: pr) f s = s := by
  intro f
  induction f with
  | zero => intro s _; simp [findAndDeleteF]
  | succ f ih =>
    intro s hs
    cases s with
    | nil =>
      simp only [findAndDeleteF]
      rw [stripMatches_nomatch _ _ (by simp [List.isPrefixOf])]
      simp [opLen]
    | cons b rest =>
      simp only [opHeadsF, List.mem_cons, not_or] at hs
      obtain ⟨hb, hs⟩ := hs
      simp only [findAndDeleteF]
      rw [stripMatches_nomatch _ _ (by simp [List.isPrefixOf]; intro e; exact (hb e).elim)]
      split
      · rfl
      · rename_i n hn
        rw [hn] at hs
        simp only at hs
        rw [ih _ hs, List.take_append_drop]

/-- FindAndDelete is the identity when no operation of the script starts with the pattern's first byte. -/
theorem findAndDelete_id (p0 : UInt8) (pr s : Bytes) (h : p0 ∉ opHeads s) :
    findAndDelete (p0 :: pr) s = s :=
  findAndDeleteF_id p0 pr _ s h


/-! ## The 201-op limit is a static property -/

/-- Every CHECKMULTISIG(VERIFY) is immediately preceded by a push (its key count). -/
def cmsPreceded : List Instr → Bool
  | [] => true
  | .push _ :: .op .checkMultiSig :: rest => cmsPreceded rest
  | .push _ :: .op .checkMultiSigVerify :: rest => cmsPreceded rest
  | .push _ :: rest => cmsPreceded rest
  | .op .checkMultiSig :: _ => false
  | .op .checkMultiSigVerify :: _ => false
  | .op _ :: rest => cmsPreceded rest
  | .other _ :: rest => cmsPreceded rest

def notCms (o : Op) : Prop := o ≠ .checkMultiSig ∧ o ≠ .checkMultiSigVerify

theorem num4_ne {b : Bytes} {e : Err} (h : num4 b = .error e) : e = .numOverflow := by
  unfold num4 at h; split at h <;> simp_all

/-- Non-multisig opcodes never touch the op counter and never fail with `opCount`. -/
theorem stepOp_plain (c : Ctx) (o : Op) (ho : notCms o) (s : St) :
    (∀ s', stepOp c o s = .ok s' → s'.ops = s.ops) ∧ (∀ e, stepOp c o s = .error e → e ≠ .opCount) := by
  obtain ⟨st, ops⟩ := s
  cases o <;> simp only [notCms, ne_eq, not_true_eq_false, and_false, false_and, reduceCtorEq] at ho <;>
    rcases st with _ | ⟨a, _ | ⟨b, r⟩⟩ <;>
    simp only [stepOp, Except.bind, bind] <;>
    (constructor <;> intro x hx) <;>
    (try split at hx) <;> (try split at hx) <;> (try split at hx) <;>
    (try simp_all) <;> (try (cases hx; rfl)) <;> (try (subst_vars; simp_all [num4_ne]))
  all_goals (revert ‹num4 _ = .error _›; unfold num4; split <;> simp_all <;> (intro e; subst e; decide))


theorem cmsLoop_err (c : Ctx) (sc : Bytes) (sigs keys : List Bytes) (e : Err)
    (h : cmsLoop c sc sigs keys = .error e) : e = .sigDer := by
  fun_induction cmsLoop c sc sigs keys <;> simp_all

theorem cmsExec_spec (c : Ctx) (v : Bool) (s : St) (nkb : Bytes) (r : List Bytes) (hs : s.stack = nkb :: r) :
    (∀ s', cmsExec c v s = .ok s' → s'.ops = s.ops + (numDec nkb).toNat) ∧
    (cmsExec c v s = .error .opCount → s.ops + (numDec nkb).toNat > MAX_OPS) := by
  obtain ⟨st, ops⟩ := s
  simp only at hs; subst hs
  have key : ∀ nk, num4 nkb = .ok nk → nk = numDec nkb := fun _ h => num4_ok h
  constructor
  · intro s' h
    simp only [cmsExec, Except.bind, bind] at h
    split at h
    · simp at h
    · rename_i nk hnk
      cases key _ hnk
      repeat' (split at h)
      all_goals first | (simp at h; done) | (injection h with h; subst h; rfl)
  · intro h
    simp only [cmsExec, Except.bind, bind] at h
    split at h
    · rename_i e he; injection h with h; subst h; have := num4_ne he; simp at this
    · rename_i nk hnk
      cases key _ hnk
      repeat' (split at h)
      all_goals first
        | (simp at h; done)
        | (simp only [MAX_OPS] at *; omega)
        | (injection h with h; subst h
           first | (have := cmsLoop_err _ _ _ _ _ ‹cmsLoop _ _ _ _ = .error _›; simp at this)
                 | (have := num4_ne ‹num4 _ = .error _›; simp at this))


theorem step_bind {c : Ctx} {i : Instr} {s : St} :
    step c i s = (stepCore c i s).bind (fun s' => if s'.stack.length > 1000 then .error .stackSize else .ok s') := rfl

theorem step_push (c : Ctx) (d : Bytes) (s : St) :
    (∀ s1, step c (.push d) s = .ok s1 → s1.ops = s.ops ∧ s1.stack = d :: s.stack) ∧
    (step c (.push d) s = .error .opCount → False) := by
  simp only [step_bind, stepCore]
  constructor
  · intro s1 h; split at h
    · simp [Except.bind] at h
    · simp only [Except.bind] at h; split at h
      · simp at h
      · injection h with h; subst h; simp
  · intro h; split at h
    · simp [Except.bind] at h
    · simp only [Except.bind] at h; split at h <;> simp at h

theorem step_plain (c : Ctx) (o : Op) (ho : notCms o) (s : St) :
    (∀ s1, step c (.op o) s = .ok s1 → s1.ops = s.ops + 1) ∧
    (step c (.op o) s = .error .opCount → s.ops + 1 > MAX_OPS) := by
  have hp := stepOp_plain c o ho { s with ops := s.ops + 1 }
  simp only [step_bind, stepCore]
  constructor
  · intro s1 h; split at h
    · simp [Except.bind] at h
    · cases hs : stepOp c o { s with ops := s.ops + 1 } with
      | error e => rw [hs] at h; simp [Except.bind] at h
      | ok s2 =>
        rw [hs] at h; simp only [Except.bind] at h; split at h
        · simp at h
        · injection h with h; subst h; exact hp.1 _ hs
  · intro h; split at h
    · assumption
    · exfalso
      cases hs : stepOp c o { s with ops := s.ops + 1 } with
      | error e => rw [hs] at h; simp only [Except.bind] at h; injection h with h; subst h; exact hp.2 _ hs rfl
      | ok s2 => rw [hs] at h; simp only [Except.bind] at h; split at h <;> simp at h

theorem step_cms (c : Ctx) (o : Op) (ho : o = .checkMultiSig ∨ o = .checkMultiSigVerify) (s : St)
    (d : Bytes) (r : List Bytes) (hs : s.stack = d :: r) :
    (∀ s1, step c (.op o) s = .ok s1 → s1.ops = s.ops + 1 + (numDec d).toNat) ∧
    (step c (.op o) s = .error .opCount → s.ops + 1 + (numDec d).toNat > MAX_OPS) := by
  have hc : ∀ v, (cmsExec c v { s with ops := s.ops + 1 }).isOk = (cmsExec c v { s with ops := s.ops + 1 }).isOk := fun _ => rfl
  have spec := fun v => cmsExec_spec c v { s with ops := s.ops + 1 } d r hs
  have hso : stepOp c o { s with ops := s.ops + 1 } = cmsExec c (o == .checkMultiSigVerify) { s with ops := s.ops + 1 } := by
    rcases ho with rfl | rfl <;> rfl
  simp only [step_bind, stepCore, hso]
  constructor
  · intro s1 h; split at h
    · simp [Except.bind] at h
    · cases he : cmsExec c (o == .checkMultiSigVerify) { s with ops := s.ops + 1 } with
      | error e => rw [he] at h; simp [Except.bind] at h
      | ok s2 =>
        rw [he] at h; simp only [Except.bind] at h; split at h
        · simp at h
        · injection h with h; subst h; exact (spec _).1 _ he
  · intro h; split at h
    · rename_i hgt; simp only [MAX_OPS] at *; omega
    · cases he : cmsExec c (o == .checkMultiSigVerify) { s with ops := s.ops + 1 } with
      | error e =>
        rw [he] at h; simp only [Except.bind] at h; injection h with h; subst h
        exact (spec _).2 he
      | ok s2 => rw [he] at h; simp only [Except.bind] at h; split at h <;> simp at h

theorem run_cons_eq (c : Ctx) (i : Instr) (is : List Instr) (s : St) :
    run c (i :: is) s = (step c i s).bind (run c is) := rfl

theorem bind_err {α β ε} {x : Except ε α} {f : α → Except ε β} {e : ε} (h : x.bind f = .error e) :
    x = .error e ∨ ∃ a, x = .ok a ∧ f a = .error e := by
  cases x with
  | error e' => left; simp [Except.bind] at h; rw [h]
  | ok a => right; exact ⟨a, rfl, by simpa [Except.bind] using h⟩

/-- **The 201-op limit is static.** On any script whose multisigs take their key count from the
push just before them, every run (any initial stack, any crypto) ends with at most
`start + staticOps` counted ops, and can only fail with `opCount` if `start + staticOps > 201`. -/
theorem run_opcount (c : Ctx) : ∀ (is : List Instr) (s : St), cmsPreceded is = true →
    (∀ s', run c is s = .ok s' → s'.ops ≤ s.ops + staticOps is) ∧
    (run c is s = .error .opCount → s.ops + staticOps is > MAX_OPS) := by
  intro is
  induction h : is.length using Nat.strongRecOn generalizing is with
  | _ n ih =>
    intro s hp
    -- generic "one instruction then the rest" step
    have gen : ∀ (i : Instr) (rest : List Instr) (k : Nat), (i :: rest).length = n →
        cmsPreceded rest = true →
        (∀ s1, step c i s = .ok s1 → s1.ops = s.ops + k) →
        (step c i s = .error .opCount → s.ops + k > MAX_OPS) →
        (∀ s', run c (i :: rest) s = .ok s' → s'.ops ≤ s.ops + (k + staticOps rest)) ∧
        (run c (i :: rest) s = .error .opCount → s.ops + (k + staticOps rest) > MAX_OPS) := by
      intro i rest k hl hr hok herr
      have ihr := fun s1 => ih rest.length (by simp at hl; omega) rest rfl s1 hr
      constructor
      · intro s' hrun
        rw [run_cons_eq] at hrun
        obtain ⟨s1, h1, h2⟩ := bind_ok hrun
        have := (ihr s1).1 s' h2; have := hok s1 h1; omega
      · intro hrun
        rw [run_cons_eq] at hrun
        rcases bind_err hrun with h1 | ⟨s1, h1, h2⟩
        · have := herr h1; omega
        · have := (ihr s1).2 h2; have := hok s1 h1; omega
    -- two instructions: push d then a multisig
    have gen2 : ∀ (d : Bytes) (o : Op) (rest : List Instr),
        (o = .checkMultiSig ∨ o = .checkMultiSigVerify) → (.push d :: .op o :: rest).length = n →
        cmsPreceded rest = true →
        (∀ s', run c (.push d :: .op o :: rest) s = .ok s' → s'.ops ≤ s.ops + (1 + (numDec d).toNat + staticOps rest)) ∧
        (run c (.push d :: .op o :: rest) s = .error .opCount → s.ops + (1 + (numDec d).toNat + staticOps rest) > MAX_OPS) := by
      intro d o rest ho hl hr
      have ihr := fun s1 => ih rest.length (by simp at hl; omega) rest rfl s1 hr
      have hpush := step_push c d s
      constructor
      · intro s' hrun
        rw [run_cons_eq] at hrun
        obtain ⟨s1, h1, h2⟩ := bind_ok hrun
        obtain ⟨hops1, hst1⟩ := hpush.1 s1 h1
        rw [run_cons_eq] at h2
        obtain ⟨s2, h3, h4⟩ := bind_ok h2
        have := (step_cms c o ho s1 d s.stack hst1).1 s2 h3
        have := (ihr s2).1 s' h4
        omega
      · intro hrun
        rw [run_cons_eq] at hrun
        rcases bind_err hrun with h1 | ⟨s1, h1, h2⟩
        · exact (hpush.2 h1).elim
        · obtain ⟨hops1, hst1⟩ := hpush.1 s1 h1
          rw [run_cons_eq] at h2
          rcases bind_err h2 with h3 | ⟨s2, h3, h4⟩
          · have := (step_cms c o ho s1 d s.stack hst1).2 h3; omega
          · have := (step_cms c o ho s1 d s.stack hst1).1 s2 h3
            have := (ihr s2).2 h4; omega
    match is, h, hp with
    | [], _, _ =>
      constructor
      · intro s' hrun; simp [run] at hrun; subst hrun; simp [staticOps]
      · intro hrun; simp [run] at hrun
    | .push d :: [], hl, hp =>
      simpa [staticOps] using gen (.push d) [] 0 hl rfl (fun s1 h => by simp [(step_push c d s).1 s1 h])
        (fun h => ((step_push c d s).2 h).elim)
    | .push d :: .push d' :: rest, hl, hp =>
      simp only [cmsPreceded] at hp
      simpa [staticOps] using gen (.push d) (.push d' :: rest) 0 hl hp
        (fun s1 h => by simp [(step_push c d s).1 s1 h]) (fun h => ((step_push c d s).2 h).elim)
    | .push d :: .other x :: rest, hl, hp =>
      simp only [cmsPreceded] at hp
      simpa [staticOps] using gen (.push d) (.other x :: rest) 0 hl hp
        (fun s1 h => by simp [(step_push c d s).1 s1 h]) (fun h => ((step_push c d s).2 h).elim)
    | .push d :: .op o :: rest, hl, hp =>
      by_cases hc : o = .checkMultiSig ∨ o = .checkMultiSigVerify
      · have hp' : cmsPreceded rest = true := by
          rcases hc with rfl | rfl <;> exact hp
        have e : staticOps (.push d :: .op o :: rest) = 1 + (numDec d).toNat + staticOps rest := by
          rcases hc with rfl | rfl <;> rfl
        rw [e]; exact gen2 d o rest hc hl hp'
      · have ho : notCms o := ⟨fun e => hc (.inl e), fun e => hc (.inr e)⟩
        have hp' : cmsPreceded (.op o :: rest) = true := by
          clear ih gen gen2
          cases o <;> simp only [cmsPreceded] at hp ⊢ <;> first | exact hp | exact absurd rfl ho.1 | exact absurd rfl ho.2
        have hs : staticOps (.push d :: .op o :: rest) = staticOps (.op o :: rest) := by
          clear ih gen gen2
          cases o <;> first | rfl | exact absurd rfl ho.1 | exact absurd rfl ho.2
        have hs2 : staticOps (.op o :: rest) = 1 + staticOps rest := by
          clear ih gen gen2
          cases o <;> first | rfl | exact absurd rfl ho.1 | exact absurd rfl ho.2
        rw [hs, hs2]
        have := gen (.push d) (.op o :: rest) 0 hl hp'
          (fun s1 h => by simp [(step_push c d s).1 s1 h]) (fun h => ((step_push c d s).2 h).elim)
        rw [hs2] at this; simpa using this
    | .op o :: rest, hl, hp =>
      have ho : notCms o := by
        constructor <;> (intro e; subst e; simp [cmsPreceded] at hp)
      have hp' : cmsPreceded rest = true := by
        clear ih gen gen2
        cases o <;> simp only [cmsPreceded] at hp ⊢ <;> first | exact hp | exact absurd rfl ho.1 | exact absurd rfl ho.2
      have hs : staticOps (.op o :: rest) = 1 + staticOps rest := by
        clear ih gen gen2
        cases o <;> first | rfl | exact absurd rfl ho.1 | exact absurd rfl ho.2
      rw [hs]
      exact gen (.op o) rest 1 hl hp' (step_plain c o ho s).1 (step_plain c o ho s).2
    | .other x :: rest, hl, hp =>
      simp only [cmsPreceded] at hp
      have herr : step c (.other x) s = .error (.unsupported x) := rfl
      constructor
      · intro s' hrun; rw [run_cons_eq, herr] at hrun; simp [Except.bind] at hrun
      · intro hrun; rw [run_cons_eq, herr] at hrun; simp [Except.bind] at hrun

/-- Corollary: if a script parses, satisfies `cmsPreceded`, and has `staticOps <= 201`, then no
execution of it (from a fresh op counter) can fail with the op-count error. -/
theorem no_opcount_failure (c : Ctx) (is : List Instr) (hp : cmsPreceded is = true)
    (hs : staticOps is ≤ MAX_OPS) (st : List Bytes) : run c is ⟨st, 0⟩ ≠ .error .opCount := by
  intro h
  have := (run_opcount c is ⟨st, 0⟩ hp).2 h
  simp at this; omega


/-- Does `pat` occur at some GetOp boundary of `s` (with fuel)? -/
def matchAtBoundaryF (pat : Bytes) : Nat → Bytes → Bool
  | 0, _ => false
  | f + 1, s =>
    pat.isPrefixOf s ||
      match opLen s with
      | some n => matchAtBoundaryF pat f (s.drop n)
      | none => false

def matchAtBoundary (pat s : Bytes) : Bool := matchAtBoundaryF pat (s.length + 1) s

theorem findAndDeleteF_id' (pat : Bytes) :
    ∀ (f : Nat) (s : Bytes), matchAtBoundaryF pat f s = false → findAndDeleteF pat f s = s := by
  intro f
  induction f with
  | zero => intro s _; simp [findAndDeleteF]
  | succ f ih =>
    intro s hs
    simp only [matchAtBoundaryF, Bool.or_eq_false_iff] at hs
    obtain ⟨hp, hs⟩ := hs
    simp only [findAndDeleteF]
    rw [stripMatches_nomatch _ _ hp]
    split
    · rfl
    · rename_i n hn
      rw [hn] at hs
      simp only at hs
      rw [ih _ hs, List.take_append_drop]

/-- FindAndDelete is the identity when the pattern occurs at no opcode boundary. -/
theorem findAndDelete_id' (pat s : Bytes) (h : matchAtBoundary pat s = false) : findAndDelete pat s = s :=
  findAndDeleteF_id' pat _ s h

end QSB
