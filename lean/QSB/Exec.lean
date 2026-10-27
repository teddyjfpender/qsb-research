import QSB.Proofs
import QSB.Soundness

/-!
# M2 (part 1): execution framework

Composition of runs and traces over concatenated code, and "peel" lemmas: from a successful run
of `i :: is`, the run of `is` from the (explicitly described) state after `i`.
Every lemma goes in the direction *success implies shape*, so the stack-size limit and op counter
never need to be tracked.
-/

namespace QSB.Exec
open QSB QSB.Soundness

/-! ## lists -/

theorem map_eraseIdx {α β} (f : α → β) : ∀ (l : List α) (j : Nat), (l.map f).eraseIdx j = (l.eraseIdx j).map f
  | [], _ => by simp
  | a :: l, 0 => by simp
  | a :: l, j + 1 => by simp [List.eraseIdx_cons_succ, map_eraseIdx f l j]

theorem perm_getElem_eraseIdx {α} : ∀ (l : List α) (j : Nat) (h : j < l.length), l.Perm (l[j] :: l.eraseIdx j)
  | [], _, h => by simp at h
  | a :: l, 0, _ => by simp
  | a :: l, j + 1, h => by
    simp only [List.getElem_cons_succ, List.eraseIdx_cons_succ]
    have := perm_getElem_eraseIdx l j (by simp at h; omega)
    exact (this.cons a).trans (List.Perm.swap _ _ _)

theorem length_eraseIdx_lt {α} (l : List α) (j : Nat) (h : j < l.length) : (l.eraseIdx j).length = l.length - 1 := by
  simp [List.length_eraseIdx, h]

/-! ## running and tracing concatenations -/

theorem run_append (c : Ctx) : ∀ (a b : List Instr) (s : St), run c (a ++ b) s = (run c a s).bind (run c b)
  | [], b, s => by simp [run, Except.bind]
  | i :: a, b, s => by
    simp only [List.cons_append, run]
    cases h : step c i s with
    | error e => simp [Except.bind, bind]
    | ok s1 => simp only [bind, Except.bind]; exact run_append c a b s1

theorem run_append_ok {c : Ctx} {a b : List Instr} {s s' : St} (h : run c (a ++ b) s = .ok s') :
    ∃ s1, run c a s = .ok s1 ∧ run c b s1 = .ok s' := by
  rw [run_append] at h; exact bind_ok h

theorem trace_append (c : Ctx) : ∀ (a b : List Instr) (s : St),
    trace c (a ++ b) s = trace c a s ++ (match run c a s with | .ok s1 => trace c b s1 | .error _ => [])
  | [], b, s => by simp [trace, run]
  | i :: a, b, s => by
    simp only [List.cons_append, trace, run]
    cases h : step c i s with
    | error e => simp [Except.bind, bind]
    | ok s1 =>
      simp only [bind, Except.bind, List.append_assoc]
      rw [trace_append c a b s1]

theorem trace_append_ok {c : Ctx} {a b : List Instr} {s s1 : St} (h : run c a s = .ok s1) :
    trace c (a ++ b) s = trace c a s ++ trace c b s1 := by
  rw [trace_append, h]

/-- An instruction that emits no event. -/
def Plain : Instr → Bool
  | .op .hash160 => false
  | .op .checkMultiSig => false
  | .op .checkMultiSigVerify => false
  | _ => true

theorem here_plain (i : Instr) (s : St) (h : Plain i = true) : here i s = [] := by
  unfold here
  split <;> simp_all [Plain]

theorem trace_plain (c : Ctx) : ∀ (is : List Instr) (s : St), is.all Plain = true → trace c is s = []
  | [], _, _ => by simp [trace]
  | i :: is, s, h => by
    simp only [List.all_cons, Bool.and_eq_true] at h
    simp only [trace, here_plain i s h.1, List.nil_append]
    split
    · exact trace_plain c is _ h.2
    · rfl

theorem trace_cons_ok {c : Ctx} {i : Instr} {is : List Instr} {s s1 : St} (h : step c i s = .ok s1) :
    trace c (i :: is) s = here i s ++ trace c is s1 := by
  simp only [trace, h]

theorem trace_single (c : Ctx) (i : Instr) (s : St) : trace c [i] s = here i s := by
  simp only [trace]; split <;> simp [trace]

/-! ## peeling one instruction -/

theorem step_ok_of_run {c : Ctx} {i : Instr} {is : List Instr} {s s' : St} (h : run c (i :: is) s = .ok s') :
    ∃ s1, step c i s = .ok s1 ∧ stepCore c i s = .ok s1 ∧ run c is s1 = .ok s' := by
  simp only [run] at h
  obtain ⟨s1, h1, h2⟩ := bind_ok h
  refine ⟨s1, h1, ?_, h2⟩
  simp only [step] at h1
  obtain ⟨s0, h3, h4⟩ := bind_ok h1
  split at h4
  · simp at h4
  · injection h4 with h4; subst h4; exact h3

theorem peel_push {c : Ctx} {d : Bytes} {is : List Instr} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.push d :: is) ⟨st, n⟩ = .ok s') : run c is ⟨d :: st, n⟩ = .ok s' := by
  obtain ⟨s1, -, h1, h2⟩ := step_ok_of_run h
  cases push_ok h1; exact h2

theorem peel_op {c : Ctx} {o : Op} {is : List Instr} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op o :: is) ⟨st, n⟩ = .ok s') :
    ∃ st1 n1, stepOp c o ⟨st, n + 1⟩ = .ok ⟨st1, n1⟩ ∧ run c is ⟨st1, n1⟩ = .ok s' := by
  obtain ⟨⟨st1, n1⟩, -, h1, h2⟩ := step_ok_of_run h
  exact ⟨st1, n1, op_ok h1, h2⟩

theorem num4_numEnc' {v : Int} {x : Int} {b : Bytes} (hb : b = numEnc v) (h : num4 b = .ok x) : x = v := by
  subst hb; rw [num4_ok h, numDec_numEnc]

/-- ROLL at a depth inside the known prefix. -/
theorem peel_roll_in {c : Ctx} {is : List Instr} {pre W : List Bytes} {d n : Nat} {s' : St}
    (hd : d < pre.length) (h : run c (.op .roll :: is) ⟨numEnc d :: (pre ++ W), n⟩ = .ok s') :
    ∃ n1, run c is ⟨pre[d] :: (pre.eraseIdx d ++ W), n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  obtain ⟨nb, r, v, y, hst, hv, hv0, hy, hs⟩ := roll_ok h1
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc' rfl hv
  simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
  simp only [Int.toNat_natCast] at hy ⊢
  rw [List.getElem?_append_left hd, List.getElem?_eq_getElem hd] at hy
  cases hy
  simp only [Int.toNat_natCast] at h2
  rw [List.eraseIdx_append_of_lt_length hd] at h2
  exact ⟨_, h2⟩

/-- ROLL at a depth past the known prefix: some item of the unknown suffix comes to the top. -/
theorem peel_roll_deep {c : Ctx} {is : List Instr} {pre W : List Bytes} {d n : Nat} {s' : St}
    (hd : pre.length ≤ d) (h : run c (.op .roll :: is) ⟨numEnc d :: (pre ++ W), n⟩ = .ok s') :
    ∃ y W' n1, run c is ⟨y :: (pre ++ W'), n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  obtain ⟨nb, r, v, y, hst, hv, hv0, hy, hs⟩ := roll_ok h1
  obtain ⟨rfl, rfl⟩ := List.cons.inj hst
  cases num4_numEnc' rfl hv
  simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
  simp only [Int.toNat_natCast] at h2
  rw [List.eraseIdx_append_of_length_le hd] at h2
  exact ⟨y, _, _, h2⟩

theorem peel_min {c : Ctx} {is : List Instr} {b a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .min :: is) ⟨b :: a :: st, n⟩ = .ok s') :
    ∃ x y n1, num4 a = .ok x ∧ num4 b = .ok y ∧ run c is ⟨numEnc (if x < y then x else y) :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  obtain ⟨b', a', r, x, y, hst, hx, hy, hs⟩ := min_ok h1
  simp only [List.cons.injEq] at hst; obtain ⟨rfl, rfl, rfl⟩ := hst
  simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
  exact ⟨x, y, _, hx, hy, h2⟩

theorem peel_minB {c : Ctx} {is : List Instr} {a : Bytes} {st : List Bytes} {B n : Nat} {s' : St}
    (h : run c (.op .min :: is) ⟨numEnc B :: a :: st, n⟩ = .ok s') :
    ∃ v : Int, v ≤ B ∧ ∃ n1, run c is ⟨numEnc v :: st, n1⟩ = .ok s' := by
  obtain ⟨x, y, n1, -, hy, h2⟩ := peel_min h
  cases num4_numEnc' rfl hy
  exact ⟨_, by split <;> omega, n1, h2⟩

theorem peel_pick {c : Ctx} {is : List Instr} {v : Int} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .pick :: is) ⟨numEnc v :: st, n⟩ = .ok s') :
    ∃ (hv : 0 ≤ v ∧ v.toNat < st.length) (n1 : Nat), run c is ⟨st[v.toNat] :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  rcases st with _ | ⟨a, r⟩
  · simp [stepOp] at h1
  simp only [stepOp] at h1
  obtain ⟨m, hm, h1⟩ := bind_ok h1
  cases num4_numEnc' rfl hm
  split at h1
  · rename_i hc; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
    exact ⟨hc, _, h2⟩
  · simp at h1

theorem peel_dup {c : Ctx} {is : List Instr} {a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .dup :: is) ⟨a :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨a :: a :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
  exact ⟨_, h2⟩

theorem peel_drop {c : Ctx} {is : List Instr} {a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .drop :: is) ⟨a :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
  exact ⟨_, h2⟩

theorem peel_swap {c : Ctx} {is : List Instr} {a b : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .swap :: is) ⟨a :: b :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨b :: a :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
  exact ⟨_, h2⟩

theorem peel_csv {c : Ctx} {is : List Instr} {a b : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .checkSigVerify :: is) ⟨a :: b :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1
  split at h1
  · simp at h1
  · split at h1
    · injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1; exact ⟨_, h2⟩
    · simp at h1

theorem peel_checksig {c : Ctx} {is : List Instr} {a b : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .checkSig :: is) ⟨a :: b :: st, n⟩ = .ok s') : ∃ z n1, run c is ⟨z :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1
  split at h1
  · simp at h1
  · injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1; exact ⟨_, _, h2⟩

/-- Any one-input hash opcode other than HASH160. -/
theorem peel_hash {c : Ctx} {o : Op} (ho : o = .sha256 ∨ o = .ripemd160 ∨ o = .sha1)
    {is : List Instr} {a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op o :: is) ⟨a :: st, n⟩ = .ok s') : ∃ z n1, run c is ⟨z :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  rcases ho with rfl | rfl | rfl <;>
  · simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
    exact ⟨_, _, h2⟩

theorem peel_hash160 {c : Ctx} {is : List Instr} {a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .hash160 :: is) ⟨a :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨c.crypto.hash160 a :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
  exact ⟨_, h2⟩

theorem peel_eqv {c : Ctx} {is : List Instr} {a b : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .equalVerify :: is) ⟨a :: b :: st, n⟩ = .ok s') : a = b ∧ ∃ n1, run c is ⟨st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1
  split at h1
  · rename_i hab; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1; exact ⟨hab, _, h2⟩
  · simp at h1

theorem peel_size {c : Ctx} {is : List Instr} {a : Bytes} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .size :: is) ⟨a :: st, n⟩ = .ok s') : ∃ n1, run c is ⟨numEnc a.length :: a :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  simp only [stepOp] at h1; injection h1 with h1; simp only [St.mk.injEq] at h1; obtain ⟨rfl, rfl⟩ := h1
  exact ⟨_, h2⟩

theorem peel_add {c : Ctx} {is : List Instr} {v : Int} {w : Nat} {st : List Bytes} {n : Nat} {s' : St}
    (h : run c (.op .add :: is) ⟨numEnc w :: numEnc v :: st, n⟩ = .ok s') :
    ∃ n1, run c is ⟨numEnc (v + w) :: st, n1⟩ = .ok s' := by
  obtain ⟨st1, n1, h1, h2⟩ := peel_op h
  obtain ⟨b', a', r, x, y, hst, hx, hy, hs⟩ := add_ok h1
  simp only [List.cons.injEq] at hst; obtain ⟨rfl, rfl, rfl⟩ := hst
  cases num4_numEnc' rfl hx; cases num4_numEnc' rfl hy
  simp only [St.mk.injEq] at hs; obtain ⟨rfl, rfl⟩ := hs
  exact ⟨_, h2⟩

theorem run_nil {c : Ctx} {s s' : St} (h : run c [] s = .ok s') : s' = s := by
  simp [run] at h; exact h.symm

end QSB.Exec
