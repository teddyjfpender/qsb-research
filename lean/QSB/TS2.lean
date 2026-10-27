import QSB.Gadget
import QSB.Blocks

/-!
# M3: soundness of the TS2 family

TS2 family: one round, no chains, no signing, forced-compressed round key, pool-first layout (the
design of the real GPU spend accepted by Bitcoin Core). `ts2_family_sound` proves
`SelectionSound p rnd` for every `(p, rnd)` with `SideTS2 p rnd = true`.
-/

namespace QSB.TS2
open QSB QSB.Build QSB.Soundness QSB.Exec QSB.Gadget QSB.Blocks

section
variable (p : Params) (rnd : Rand)

def Ds : List Bytes := (List.range p.n).map (dummy rnd 0)
def Cs : List Bytes := (List.range p.n).map (commit rnd 0)
def Ps : List Bytes := (List.range p.k).map (fun i => poolSig (i + 1))

end

/-! ## pushes -/

theorem run_pushes (c : Ctx) : ∀ (L : List Bytes) (st : List Bytes) (n : Nat) (s1 : St),
    run c (L.map Instr.push) ⟨st, n⟩ = .ok s1 → s1.stack = L.reverse ++ st
  | [], st, n, s1, h => by cases run_nil h; simp
  | d :: L, st, n, s1, h => by
    have h := peel_push h
    rw [run_pushes c L (d :: st) n s1 h]; simp

theorem pushes_instrs (p : Params) (rnd : Rand) :
    (pushesB p rnd).map CI.instr =
      (((Ps p).reverse ++ (Cs p rnd).reverse ++ (Ds p rnd).reverse)).map Instr.push := by
  simp [pushesB, Ps, Cs, Ds, List.map_reverse, Function.comp_def, CI.instr]

theorem pushes_spec (p : Params) (rnd : Rand) (c : Ctx) (W : List Bytes) (n : Nat) (s1 : St)
    (h : run c ((pushesB p rnd).map CI.instr) ⟨W, n⟩ = .ok s1) :
    s1.stack = Ds p rnd ++ Cs p rnd ++ Ps p ++ W := by
  rw [pushes_instrs] at h
  rw [run_pushes c _ W n s1 h]; simp

theorem plain_pushes (p : Params) (rnd : Rand) : ((pushesB p rnd).map CI.instr).all Plain = true := by
  rw [pushes_instrs]; simp [Plain]

theorem plain_hashOp (b : UInt8) : Plain (.op (hashOpOf b)) = true := by
  unfold hashOpOf; split
  · rfl
  · split <;> rfl

theorem hashOp_cases (b : UInt8) : hashOpOf b = .sha256 ∨ hashOpOf b = .ripemd160 ∨ hashOpOf b = .sha1 := by
  unfold hashOpOf; split
  · simp
  · split <;> simp

/-! ## pinning -/

theorem plain_pin (p : Params) : ((pinB p).map CI.instr).all Plain = true := by
  simp only [pinB, List.map, CI.instr, List.all_cons, List.all_nil, plain_hashOp]; rfl

theorem pin_spec (p : Params) (c : Ctx) (pre W : List Bytes) (n : Nat) (s1 : St)
    (hpre : pre.length = N0 p) (h : run c ((pinB p).map CI.instr) ⟨pre ++ W, n⟩ = .ok s1) :
    ∃ W', s1.stack = pre ++ W' := by
  simp only [pinB, List.map, CI.instr] at h
  have h := peel_push h
  obtain ⟨y, W1, _, h⟩ := peel_roll_deep (pre := pre) (by omega) h
  have h := peel_push h
  obtain ⟨v, _, _, h⟩ := peel_minB h
  obtain ⟨_, _, h⟩ := peel_pick h
  have h := peel_push h
  obtain ⟨_, _, h⟩ := peel_pick h
  obtain ⟨_, h⟩ := peel_csv h
  have h := peel_push h
  obtain ⟨y2, W2, _, h⟩ := peel_roll_deep (pre := pre) (by omega) h
  obtain ⟨z, _, h⟩ := peel_hash (hashOp_cases p.hashOp) h
  have h := peel_push h
  obtain ⟨z', _, h⟩ := peel_checksig h
  obtain ⟨_, h⟩ := peel_drop h
  cases run_nil h
  exact ⟨W2, rfl⟩

/-! ## round prologue: NULL, the nonce signature -/

theorem null_enc : numEnc ((0 : Nat) : Int) = [] := by simp [numEnc, natLE]

theorem plain_pro (p : Params) : ((proB p).map CI.instr).all Plain = true := by
  simp [proB, CI.instr, Plain]

theorem pro_spec (p : Params) (c : Ctx) (Q W : List Bytes) (n : Nat) (s1 : St)
    (hQ : Q.length = N0 p) (hk : k1 p ≤ p.k)
    (h : run c ((proB p).map CI.instr) ⟨Q ++ W, n⟩ = .ok s1) :
    ∃ v nsig W', v ≤ 2 * p.n + k1 p ∧ ([] :: Q)[v]? = some nsig ∧
      s1.stack = nsig :: [] :: Q ++ W' := by
  simp only [proB, List.map, CI.instr, null_enc] at h
  have h := peel_push h
  have h := peel_push h
  obtain ⟨y, W1, _, h⟩ := peel_roll_deep (pre := [] :: Q) (by simp; omega) h
  have h := peel_push h
  obtain ⟨v, hvB, _, h⟩ := peel_minB h
  obtain ⟨hv, _, h⟩ := peel_pick h
  cases run_nil h
  have hlt : v.toNat < ([] :: Q).length := by simp [N0] at hQ ⊢; omega
  refine ⟨v.toNat, _, W1, by omega, ?_, rfl⟩
  have e : ([] :: Q ++ W1)[v.toNat]? = some (([] :: Q ++ W1)[v.toNat]'hv.2) := List.getElem?_eq_getElem hv.2
  generalize ([] :: Q ++ W1)[v.toNat]'hv.2 = x at e ⊢
  rw [show ([] :: Q ++ W1) = ([] :: Q) ++ W1 from rfl, List.getElem?_append_left hlt] at e
  exact e

/-- What the nonce PICK can return. -/
theorem nonce_cases (p : Params) (rnd : Rand) (v : Nat) (nsig : Bytes) (hk : k1 p ≤ p.k)
    (hv : v ≤ 2 * p.n + k1 p)
    (h : ([] :: (Ds p rnd ++ Cs p rnd ++ Ps p))[v]? = some nsig) :
    nsig = [] ∨ (∃ i < p.n, nsig = dummy rnd 0 i) ∨ (∃ i < p.n, nsig = commit rnd 0 i) ∨
      (∃ s, 1 ≤ s ∧ s ≤ k1 p ∧ nsig = poolSig s) := by
  rcases v with _ | v
  · left; simp at h; exact h
  simp only [List.getElem?_cons_succ] at h
  by_cases h1 : v < p.n
  · rw [List.append_assoc, List.getElem?_append_left (by simp [Ds]; omega)] at h
    simp only [Ds, List.getElem?_map, List.getElem?_range h1, Option.map_some, Option.some.injEq] at h
    right; left; exact ⟨v, h1, h.symm⟩
  by_cases h2 : v < 2 * p.n
  · rw [List.append_assoc, List.getElem?_append_right (by simp [Ds]; omega),
      List.getElem?_append_left (by simp [Ds, Cs]; omega)] at h
    simp only [Ds, Cs, List.length_map, List.length_range, List.getElem?_map,
      List.getElem?_range (show v - p.n < p.n by omega), Option.map_some, Option.some.injEq] at h
    right; right; left; exact ⟨v - p.n, by omega, h.symm⟩
  · rw [List.append_assoc, List.getElem?_append_right (by simp [Ds]; omega),
      List.getElem?_append_right (by simp [Ds, Cs]; omega)] at h
    have hvk : v - p.n - p.n < p.k := by
      have := (List.getElem?_eq_some_iff.mp h).1; simp [Ds, Cs, Ps] at this; omega
    simp only [Ds, Cs, Ps, List.length_map, List.length_range, List.getElem?_map,
      List.getElem?_range hvk, Option.map_some, Option.some.injEq] at h
    right; right; right; exact ⟨v - p.n - p.n + 1, by omega, by omega, h.symm⟩

/-! ## the selection loop -/

def selCode (p : Params) (i : Nat) : List Instr := ((List.range i).flatMap (selB p)).map CI.instr

theorem selCode_succ (p : Params) (i : Nat) : selCode p (i + 1) = selCode p i ++ (selB p i).map CI.instr := by
  simp [selCode, List.range_succ, List.flatMap_append]

theorem selB_gadget (p : Params) (i : Nat) (hi : i < p.n) :
    (selB p i).map CI.instr = gadget (2 * p.n + p.k + tT p + 1 - 2 * i) ((i + 2) + (p.n - i) - 1) ((p.n - i) + 1)
      (2 * (p.n - i) + p.k + 2 * tT p + 1 - i) := by
  simp only [selB, gadget, List.map, CI.instr]
  rw [show i + 2 + (p.n - i) - 1 = p.n + 1 by omega]

/-- Loop invariant after `i` selections: the selected positions `sel` (their dummies on top, last
selected first), the remaining positions `rem` in region order, the pool, and an unknown witness
suffix; every event so far opened the commitment of a selected position, and each selected
position was opened. -/
def Inv (p : Params) (rnd : Rand) (c : Ctx) (nsig : Bytes) (i : Nat) (s : St) (evs : List Ev) : Prop :=
  ∃ (sel rem : List Nat) (W : List Bytes), sel.length = i ∧ rem.length = p.n - i ∧ (sel ++ rem).Nodup ∧ (∀ x ∈ sel ++ rem, x < p.n) ∧
    s.stack = ((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) ++ rem.map (dummy rnd 0) ++
      rem.map (commit rnd 0) ++ Ps p ++ W ∧
    (∀ e ∈ evs, ∃ w x, e = .heq w (commit rnd 0 x) ∧ x ∈ sel ∧ c.crypto.hash160 w = commit rnd 0 x) ∧
    (∀ x ∈ sel, ∃ w, Ev.heq w (commit rnd 0 x) ∈ evs ∧ c.crypto.hash160 w = commit rnd 0 x)

theorem loop (p : Params) (rnd : Rand) (c : Ctx) (h20 : ∀ b, (c.crypto.hash160 b).length = 20)
    (hn : 2 * tT p ≤ p.n) (hbig : 4 * p.n + 2 * p.k + 4 * tT p + 16 < 2 ^ 31)
    (hshort : ∀ i < p.n, (dummy rnd 0 i).length ≠ 20) (nsig : Bytes) (s0 : St) (h0 : Inv p rnd c nsig 0 s0 []) :
    ∀ i, i ≤ tT p → ∀ s, run c (selCode p i) s0 = .ok s → Inv p rnd c nsig i s (trace c (selCode p i) s0) := by
  intro i
  induction i with
  | zero => intro _ s h; simp only [selCode, List.range_zero, List.flatMap_nil, List.map_nil] at h ⊢; cases run_nil h; simpa [trace] using h0
  | succ i ih =>
    intro hi s h
    rw [selCode_succ] at h ⊢
    obtain ⟨si, hsi, hg⟩ := run_append_ok h
    rw [trace_append_ok hsi]
    obtain ⟨sel, rem, W, hsl, hrl, hnd, hlt, hst, hev1, hev2⟩ := ih (by omega) si hsi
    obtain ⟨st, o⟩ := si
    simp only at hst; subst hst
    rw [selB_gadget p i (by omega)] at hg ⊢
    have hPl : ((sel.map (dummy rnd 0)).reverse ++ [nsig, []]).length = i + 2 := by simp [hsl]
    obtain ⟨j, Cj, Dj, Pre, W', hj, hCj, hDj, hPre, hst', htr⟩ :=
      gadget_spec c h20 ((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) (rem.map (dummy rnd 0))
        (rem.map (commit rnd 0)) (Ps p) W (i + 2) (p.n - i) p.k _ _ hPl (by simp [hrl]) (by simp [hrl])
        (by simp [Ps]) (by omega) (by omega) (by omega) (by omega) (by omega)
        (by
          intro y hy
          obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hy
          exact hshort x (hlt x (List.mem_append_right _ hx)))
        o s hg
    rw [htr]
    have hjr : j < rem.length := by omega
    simp only [List.getElem?_map, List.getElem?_eq_getElem hjr, Option.map_some, Option.some.injEq] at hCj hDj
    subst hCj; subst hDj
    refine ⟨sel ++ [rem[j]], rem.eraseIdx j, W', by simp [hsl], by rw [length_eraseIdx_lt rem j hjr, hrl]; omega,
      ?_, ?_, ?_, ?_, ?_⟩
    · have hp := perm_getElem_eraseIdx rem j hjr
      have : (sel ++ [rem[j]] ++ rem.eraseIdx j).Perm (sel ++ rem) := by
        simp only [List.append_assoc, List.singleton_append]
        exact (hp.symm).append_left sel
      exact this.nodup_iff.mpr hnd
    · intro x hx
      have hp := perm_getElem_eraseIdx rem j hjr
      have : (sel ++ [rem[j]] ++ rem.eraseIdx j).Perm (sel ++ rem) := by
        simp only [List.append_assoc, List.singleton_append]
        exact (hp.symm).append_left sel
      exact hlt x (this.mem_iff.mp hx)
    · rw [hst']
      simp only [List.map_append, List.map_cons, List.map_nil, List.reverse_append, List.reverse_cons,
        List.reverse_nil, List.nil_append, map_eraseIdx, List.cons_append, List.append_assoc]
    · intro e he
      rcases List.mem_append.mp he with he | he
      · obtain ⟨w, x, rfl, hx, hw⟩ := hev1 e he
        exact ⟨w, x, rfl, List.mem_append_left _ hx, hw⟩
      · simp at he; subst he
        exact ⟨Pre, rem[j], rfl, by simp, hPre⟩
    · intro x hx
      rcases List.mem_append.mp hx with hx | hx
      · obtain ⟨w, hw, hw'⟩ := hev2 x hx
        exact ⟨w, List.mem_append_left _ hw, hw'⟩
      · simp at hx; subst hx
        exact ⟨Pre, by simp, hPre⟩

/-! ## the multisig -/

theorem cmsLoop_true_ne (c : Ctx) (sc : Bytes) (sigs keys : List Bytes) (h : cmsLoop c sc sigs keys = .ok true) :
    ∀ sg ∈ sigs, sg ≠ [] := by
  fun_induction cmsLoop c sc sigs keys with
  | case1 => simp
  | case2 => simp at h
  | case3 => simp at h
  | case4 => simp at h
  | case5 sig sigs key keys' hder ok hok hlen ih =>
    intro sg hsg
    rcases List.mem_cons.mp hsg with rfl | hsg
    · intro e; subst e; simp [ok] at hok
    · exact ih h sg hsg
  | case6 => simp at h
  | case7 sig sigs key keys' hder ok hok hl1 hl2 ih => exact ih h

theorem cms_accept (c : Ctx) (nkb : Bytes) (r : List Bytes) (n : Nat) (s1 : St)
    (h : cmsExec c false ⟨nkb :: r, n⟩ = .ok s1) (hacc : s1.stack.head?.map castToBool = some true) :
    ∃ sigs sc keys, cmsSigs ⟨nkb :: r, n⟩ = some sigs ∧ cmsLoop c sc sigs keys = .ok true := by
  simp only [cmsExec, bind, Except.bind] at h
  split at h
  · simp at h
  rename_i nk hnk
  have hnk' := num4_ok hnk; subst hnk'
  split at h; · simp at h
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  rename_i nsb r3 hr2
  split at h
  · simp at h
  rename_i ns hns
  have hns' := num4_ok hns; subst hns'
  split at h; · simp at h
  split at h; · simp at h
  split at h
  · simp at h
  rename_i okv hloop
  split at h
  · simp at h
  split at h; · simp at h
  simp only [Bool.false_eq_true, if_false] at h
  injection h with h; subst h
  have hok : okv = true := by
    cases okv
    · simp [vFalse, castToBool] at hacc
    · rfl
  subst hok
  refine ⟨_, _, _, ?_, hloop⟩
  simp only [cmsSigs, hr2]

/-! ## epilogue: round key, dummy keys, CHECKMULTISIG -/

def rollsCode (d j : Nat) : List Instr := ((List.range j).flatMap (fun _ => [CI.num d, CI.op .roll])).map CI.instr

theorem rolls_spec (c : Ctx) (d : Nat) (R : List Bytes) :
    ∀ j (Ks W : List Bytes) (n0 : Nat) (s : St), Ks.length + R.length + j ≤ d + 1 →
      run c (rollsCode d j) ⟨Ks ++ R ++ W, n0⟩ = .ok s →
      ∃ Ks' W', Ks'.length = Ks.length + j ∧ s.stack = Ks' ++ R ++ W' ∧
        trace c (rollsCode d j) ⟨Ks ++ R ++ W, n0⟩ = [] := by
  intro j
  induction j with
  | zero =>
    intro Ks W n0 s _ h
    simp only [rollsCode, List.range_zero, List.flatMap_nil, List.map_nil] at h ⊢
    cases run_nil h; exact ⟨Ks, W, rfl, rfl, rfl⟩
  | succ j ih =>
    intro Ks W n0 s hl h
    have e : rollsCode d (j + 1) = rollsCode d j ++ [.push (numEnc d), .op .roll] := by
      simp [rollsCode, List.range_succ, List.flatMap_append, CI.instr]
    rw [e] at h ⊢
    obtain ⟨s1, h1, h2⟩ := run_append_ok h
    obtain ⟨Ks', W', hK, hst, htr⟩ := ih Ks W n0 s1 (by omega) h1
    rw [trace_append_ok h1, htr, trace_plain c _ _ rfl]
    obtain ⟨st1, o1⟩ := s1
    simp only at hst; subst hst
    have h2 := peel_push h2
    obtain ⟨y, W'', _, h2⟩ := peel_roll_deep (pre := Ks' ++ R) (by simp; omega) h2
    cases run_nil h2
    exact ⟨y :: Ks', W'', by simp [hK]; omega, by simp, rfl⟩

theorem epi_split (p : Params) : (epiB p).map CI.instr =
    [.push (numEnc (2 * p.n + p.k + 2 - tT p : Nat)), .op .roll, .op .size, .push (numEnc (33 : Nat)), .op .equalVerify,
     .op .dup, .op (hashOpOf p.hashOp), .push (numEnc (1 : Nat)), .op .checkSig, .op .drop,
     .push (numEnc (tT p + 1 : Nat)), .op .swap] ++
    rollsCode (2 * p.n + p.k + 3) (tT p) ++ [.push (numEnc (tT p + 1 : Nat)), .op .checkMultiSig] := by
  simp [epiB, rollsCode, CI.instr]

theorem numEnc_33 : numEnc ((33 : Nat) : Int) = [33] := by simp [numEnc, natLE]

theorem epi_spec (p : Params) (rnd : Rand) (c : Ctx) (sel rem : List Nat) (nsig : Bytes) (W : List Bytes)
    (n0 : Nat) (s' : St) (hsl : sel.length = tT p) (hrl : rem.length = p.n - tT p) (hn : 2 * tT p ≤ p.n)
    (h : run c ((epiB p).map CI.instr)
      ⟨((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) ++ rem.map (dummy rnd 0) ++ rem.map (commit rnd 0) ++ Ps p ++ W, n0⟩
      = .ok s')
    (hacc : s'.stack.head?.map castToBool = some true) :
    trace c ((epiB p).map CI.instr)
      ⟨((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) ++ rem.map (dummy rnd 0) ++ rem.map (commit rnd 0) ++ Ps p ++ W, n0⟩
      = [.cms ((sel.map (dummy rnd 0)).reverse ++ [nsig])] ∧ nsig ≠ [] := by
  obtain ⟨Q, hQ⟩ : ∃ Q, Q = ((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) ++ rem.map (dummy rnd 0) ++
      rem.map (commit rnd 0) ++ Ps p := ⟨_, rfl⟩
  have hQl : Q.length = 2 * p.n + p.k + 2 - tT p := by subst hQ; simp [hsl, hrl, Ps]; omega
  have hst : ((sel.map (dummy rnd 0)).reverse ++ [nsig, []]) ++ rem.map (dummy rnd 0) ++ rem.map (commit rnd 0) ++
      Ps p ++ W = Q ++ W := by subst hQ; rfl
  rw [hst] at h ⊢
  rw [epi_split] at h ⊢
  obtain ⟨s2, h12, h3⟩ := run_append_ok h
  obtain ⟨s1, h1, h2⟩ := run_append_ok h12
  rw [trace_append_ok h12, trace_append_ok h1,
    trace_plain c _ _ (by simp only [List.all_cons, List.all_nil, plain_hashOp]; rfl)]
  -- the first twelve instructions
  have h1 := peel_push h1
  obtain ⟨key, W1, _, h1⟩ := peel_roll_deep (pre := Q) (by omega) h1
  obtain ⟨_, h1⟩ := peel_size h1
  have h1 := peel_push h1
  obtain ⟨_, _, h1⟩ := peel_eqv h1
  obtain ⟨_, h1⟩ := peel_dup h1
  obtain ⟨_, _, h1⟩ := peel_hash (hashOp_cases p.hashOp) h1
  have h1 := peel_push h1
  obtain ⟨_, _, h1⟩ := peel_checksig h1
  obtain ⟨_, h1⟩ := peel_drop h1
  have h1 := peel_push h1
  obtain ⟨_, h1⟩ := peel_swap h1
  cases run_nil h1
  -- the dummy-key rolls
  have hR : [] ++ (key :: numEnc (tT p + 1 : Nat) :: Q) ++ W1 = key :: numEnc (tT p + 1 : Nat) :: (Q ++ W1) := by simp
  obtain ⟨Ks, W2, hK, hst2, htr2⟩ := rolls_spec c (2 * p.n + p.k + 3) (key :: numEnc (tT p + 1 : Nat) :: Q)
    (tT p) [] W1 _ s2 (by simp [hQl]; omega) (by rw [hR]; exact h2)
  rw [hR] at htr2
  rw [htr2, List.nil_append, List.nil_append]
  -- the multisig
  obtain ⟨st2, o2⟩ := s2
  simp only at hst2; subst hst2
  obtain ⟨s4, hs4, hc4, h4⟩ := step_ok_of_run h3
  cases push_ok hc4
  obtain ⟨s5, hs5, hc5, h5⟩ := step_ok_of_run h4
  cases run_nil h5
  rw [trace_cons_ok hs4, trace_cons_ok hs5]
  simp only [trace, here, List.nil_append, List.append_nil]
  have hop := op_ok hc5
  simp only [stepOp] at hop
  -- the signature list the multisig sees
  have hK' : Ks.length = tT p := by simpa using hK
  have hsigs : ∀ o, cmsSigs ⟨numEnc (tT p + 1 : Nat) :: (Ks ++ key :: numEnc (tT p + 1 : Nat) :: Q ++ W2), o⟩ =
      some ((sel.map (dummy rnd 0)).reverse ++ [nsig]) := by
    intro o
    have hm : (numDec (numEnc ((tT p + 1 : Nat) : Int))).toNat = tT p + 1 := by rw [numDec_numEnc]; omega
    have e1 : (Ks ++ key :: numEnc (tT p + 1 : Nat) :: Q ++ W2).drop (tT p + 1) =
        numEnc (tT p + 1 : Nat) :: (Q ++ W2) := by
      rw [show Ks ++ key :: numEnc (tT p + 1 : Nat) :: Q ++ W2 =
        (Ks ++ [key]) ++ (numEnc (tT p + 1 : Nat) :: (Q ++ W2)) by simp]
      rw [List.drop_append_of_le_length (by simp; omega)]
      rw [List.drop_of_length_le (by simp; omega)]
      simp
    unfold cmsSigs
    simp only
    rw [hm, e1]
    simp only
    rw [hm, hQ]
    simp only [List.append_assoc, List.cons_append, List.nil_append]
    rw [List.take_append, List.take_of_length_le (by simp [hsl])]
    simp [hsl]
  rw [hsigs]
  refine ⟨rfl, ?_⟩
  obtain ⟨sigs, sc, keys, hs, hl⟩ := cms_accept c _ _ _ _ hop hacc
  rw [hsigs] at hs
  injection hs with hs; subst hs
  exact cmsLoop_true_ne c sc _ keys hl nsig (by simp)

/-! ## assembling the theorem -/

theorem inj_range_map {β : Type} (f : Nat → β) (n : Nat) : ((List.range n).map f).Nodup →
    ∀ x y, x < n → y < n → f x = f y → x = y := by
  induction n with
  | zero => intro _ x y hx; omega
  | succ n ih =>
    intro h x y hx hy he
    rw [List.range_succ, List.map_append, List.nodup_append] at h
    obtain ⟨h1, -, h3⟩ := h
    have hmem : ∀ z, z < n → f z ∈ (List.range n).map f := fun z hz => List.mem_map.mpr ⟨z, List.mem_range.mpr hz, rfl⟩
    by_cases hxn : x < n
    · by_cases hyn : y < n
      · exact ih h1 x y hxn hyn he
      · have : y = n := by omega
        rw [this] at he; exact absurd he (h3 _ (hmem x hxn) _ (by simp))
    · have : x = n := by omega
      rw [this] at he
      by_cases hyn : y < n
      · exact absurd he.symm (h3 _ (hmem y hyn) _ (by simp))
      · omega

theorem isTS2_facts (p : Params) (h : isTS2 p = true) :
    p.ts.length = 1 ∧ p.bs = [0] ∧ p.signJ = false ∧ p.signLvl = false ∧ p.poolDeep = true := by
  simp only [isTS2, Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at h
  have h := h.1.1
  exact ⟨h.1.1.1.1.1.1.1.1.1, h.1.1.1.1.1.1.1.1.2, h.1.1.1.1.1.2, h.1.1.1.1.2, h.1.1.2⟩

theorem blocks_instrs (p : Params) (rnd : Rand) : (blocksTS2 p rnd).map CI.instr =
    (pushesB p rnd).map CI.instr ++ (pinB p).map CI.instr ++ (proB p).map CI.instr ++ selCode p (tT p) ++
      (epiB p).map CI.instr := by
  simp [blocksTS2, selCode, List.map_append]

/-- **M3: soundness of the TS2 family.** -/
theorem ts2_family_sound (p : Params) (rnd : Rand) (hside : SideTS2 p rnd = true) : SelectionSound p rnd := by
  intro cr rev W is s' h20 hparse hrun hacc
  dsimp only
  have hp := parse_build_TS2 p rnd hside
  rw [hp] at hparse; injection hparse with hparse; subst hparse
  simp only [SideTS2, Bool.and_eq_true] at hside
  obtain ⟨⟨⟨⟨hts2, -⟩, -⟩, harith⟩, hdata⟩ := hside
  obtain ⟨hlen1, hbs, hsj, hsl, hdeep⟩ := isTS2_facts p hts2
  simp only [sideArith, Bool.and_eq_true, decide_eq_true_eq] at harith
  obtain ⟨⟨⟨⟨ht1, htn⟩, hk1⟩, hkp⟩, hbig⟩ := harith
  simp only [sideData, Bool.and_eq_true, List.all_eq_true, List.mem_range, bne_iff_ne, ne_eq,
    decide_eq_true_eq] at hdata
  obtain ⟨hdum, hcnd⟩ := hdata
  generalize hc : (⟨cr, (build p rnd).script⟩ : Ctx) = c at hrun ⊢
  have h20' : ∀ b, (c.crypto.hash160 b).length = 20 := by subst hc; exact h20
  rw [blocks_instrs] at hrun ⊢
  obtain ⟨s4, h1234, h5⟩ := run_append_ok hrun
  obtain ⟨s3, h123, h4⟩ := run_append_ok h1234
  obtain ⟨s2, h12, h3⟩ := run_append_ok h123
  obtain ⟨s1, h1, h2⟩ := run_append_ok h12
  rw [trace_append_ok h1234, trace_append_ok h123, trace_append_ok h12, trace_append_ok h1,
    trace_plain c _ _ (plain_pushes p rnd)]
  -- pushes, pinning, prologue
  have hs1 := pushes_spec p rnd c W 0 s1 h1
  obtain ⟨st1, o1⟩ := s1; simp only at hs1; subst hs1
  have hpre : (Ds p rnd ++ Cs p rnd ++ Ps p).length = N0 p := by simp [Ds, Cs, Ps, N0]; omega
  rw [trace_plain c _ _ (plain_pin p)]
  obtain ⟨W2, hs2⟩ := pin_spec p c (Ds p rnd ++ Cs p rnd ++ Ps p) W o1 s2 hpre (by simpa using h2)
  obtain ⟨st2, o2⟩ := s2; simp only at hs2; subst hs2
  rw [trace_plain c _ _ (plain_pro p)]
  obtain ⟨v, nsig, W3, hv, hnsig, hs3⟩ := pro_spec p c _ W2 o2 s3 hpre hk1 h3
  obtain ⟨st3, o3⟩ := s3; simp only at hs3; subst hs3
  -- selections
  have hinv0 : Inv p rnd c nsig 0 ⟨nsig :: [] :: (Ds p rnd ++ Cs p rnd ++ Ps p) ++ W3, o3⟩ [] := by
    refine ⟨[], List.range p.n, W3, rfl, by simp, by simpa using List.nodup_range, by simp, ?_, by simp, by simp⟩
    simp [Ds, Cs]
  obtain ⟨sel, rem, W4, hsl', hrl, hnd, hlt, hst4, hev1, hev2⟩ :=
    loop p rnd c h20' htn hbig (fun i hi => (hdum i hi).1) nsig _ hinv0 (tT p) (Nat.le_refl _) s4 h4
  obtain ⟨st4, o4⟩ := s4; simp only at hst4; subst hst4
  -- epilogue and multisig
  obtain ⟨htr5, hne⟩ := epi_spec p rnd c sel rem nsig W4 o4 s' hsl' hrl htn h5 hacc
  rw [htr5]
  simp only [List.nil_append]
  obtain ⟨evs, htr4⟩ : ∃ evs, trace c (selCode p (tT p)) ⟨nsig :: [] :: (Ds p rnd ++ Cs p rnd ++ Ps p) ++ W3, o3⟩ = evs :=
    ⟨_, rfl⟩
  rw [htr4] at hev1 hev2
  simp only [htr4]
  have hnocms : evs.filterMap Ev.sigs? = [] := by
    rw [List.filterMap_eq_nil_iff]
    intro e he
    obtain ⟨w, x, rfl, -, -⟩ := hev1 e he
    rfl
  have hfm : (evs ++ [Ev.cms ((sel.map (dummy rnd 0)).reverse ++ [nsig])]).filterMap Ev.sigs? =
      [(sel.map (dummy rnd 0)).reverse ++ [nsig]] := by
    rw [List.filterMap_append, hnocms]; rfl
  have hselnd : sel.Nodup := (List.nodup_append.mp hnd).1
  by_cases hall : ∀ x ∈ sel, x ∈ rev.hors 0
  · left
    simp only [hfm]
    refine ⟨by simp [hlen1], ?_⟩
    intro r hr
    simp only [List.length_singleton] at hr
    have hr0 : r = 0 := by omega
    subst hr0
    refine ⟨nsig, sel, ?_, hselnd, ?_, fun x hx => hlt x (List.mem_append_left _ hx), ?_, rfl⟩
    · rcases nonce_cases p rnd v nsig hk1 hv hnsig with h0 | ⟨i, hi, rfl⟩ | ⟨i, hi, rfl⟩ | ⟨s, hs1, hs2, rfl⟩
      · exact absurd h0 hne
      · exact Or.inr ⟨hdeep, 0, i, by omega, hi, Or.inl rfl⟩
      · exact Or.inr ⟨hdeep, 0, i, by omega, hi, Or.inr rfl⟩
      · exact Or.inl ⟨s, hs1, hs2, rfl, by simp [hsj]⟩
    · simp [hsl', hbs, tT]
    · intro x hx; exact hall x (List.mem_of_mem_take hx)
  · right
    obtain ⟨x, hx, hxr⟩ : ∃ x ∈ sel, x ∉ rev.hors 0 := by
      apply Classical.byContradiction
      intro hh
      exact hall (fun x hx => Classical.byContradiction fun hx' => hh ⟨x, hx, hx'⟩)
    obtain ⟨w, hw, hwh⟩ := hev2 x hx
    obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hw
    have hkl : k < evs.length := (List.getElem?_eq_some_iff.mp hk).1
    refine ⟨k, w, commit rnd 0 x, by rw [List.getElem?_append_left hkl]; exact hk, ?_, ?_⟩
    · subst hc; exact hwh
    · have hround : roundAt (evs ++ [Ev.cms ((sel.map (dummy rnd 0)).reverse ++ [nsig])]) k = 0 := by
        simp only [roundAt]
        rw [List.take_append_of_le_length (by omega), List.countP_eq_zero]
        intro e he
        obtain ⟨w', x', rfl, -, -⟩ := hev1 e (List.mem_of_mem_take he)
        simp [Ev.isCms]
      rw [hround]
      rintro (⟨i, hi, hin, he⟩ | ⟨hj, -⟩ | ⟨hl, -⟩)
      · have := inj_range_map (commit rnd 0) p.n hcnd x i (hlt x (List.mem_append_left _ hx)) hin he
        subst this; exact hxr hi
      · simp [hsj] at hj
      · simp [hsl] at hl

end QSB.TS2
