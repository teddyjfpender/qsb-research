import QSB.Soundness

/-!
# M1: the emitted code has the expected shape

`CI` is a code item: a push in one of the encodings the builder uses, a number push, or an opcode.
`blocksTS2 p rnd` is the TS2-family script (one round, no chains, no signing, forced-compressed
round key, pool-first layout) written in closed form: every depth constant is an explicit formula in
`n, k, t, k_pin, k_1`. It is the object the soundness proof reasons about.

* `parse_encode`: for well-formed code items, `parse (encode cs) = some (cs.map CI.instr)`.
* `parse_build_TS2`: under `SideTS2 p rnd`, `parse (build p rnd).script = some (blocksTS2 p rnd).map instr`.
  `SideTS2` is decidable and checked per instance by `native_decide`; it includes the equality
  `(build p rnd).script = encode (blocksTS2 p rnd)` between the symbolic-stack builder (itself
  checked byte-equal to Python by `qsbcheck`) and the closed form. That equality is *not* proved for
  all parameters; it is a per-instance check.
-/

namespace QSB.Blocks
open QSB QSB.Build QSB.Soundness

def Op.byte : Op → UInt8
  | .nop => 0x61 | .twoDrop => 0x6d | .drop => 0x75 | .dup => 0x76 | .pick => 0x79 | .roll => 0x7a
  | .swap => 0x7c | .size => 0x82 | .equal => 0x87 | .equalVerify => 0x88 | .add => 0x93 | .sub => 0x94
  | .min => 0xa3 | .ripemd160 => 0xa6 | .sha1 => 0xa7 | .sha256 => 0xa8 | .hash160 => 0xa9
  | .checkSig => 0xac | .checkSigVerify => 0xad | .checkMultiSig => 0xae | .checkMultiSigVerify => 0xaf

theorem ofByte_byte (o : Op) : Op.ofByte? (Op.byte o) = some o := by cases o <;> rfl
theorem byte_ge (o : Op) : 0x61 ≤ (Op.byte o).toNat := by cases o <;> decide

theorem toNat_toUInt8 (n : Nat) (h : n < 256) : n.toUInt8.toNat = n := by
  simp [Nat.toUInt8, UInt8.toNat_ofNat]; omega

theorem pmin_parse (d rest : Bytes) (h : d.length ≤ 520) :
    opLen (pushMinE d ++ rest) = some (pushMinE d).length ∧
    decodeOp (pushMinE d ++ rest) (pushMinE d).length = .push d := by
  unfold pushMinE
  by_cases h0 : d.length = 0
  · have : d = [] := List.eq_nil_of_length_eq_zero h0
    subst this
    simp [opLen, decodeOp]
  · rw [if_neg h0]
    by_cases h1 : d.length < 0x4c
    · rw [if_pos h1]
      have hc := toNat_toUInt8 d.length (by omega)
      constructor
      · simp [opLen, hc, h1]; omega
      · simp [decodeOp, hc]; rw [if_pos (by omega), if_pos (by omega)]; simp
    · rw [if_neg h1]
      by_cases h2 : d.length ≤ 0xff
      · rw [if_pos h2]
        have hc := toNat_toUInt8 d.length (by omega)
        constructor
        · simp [opLen, hc]; omega
        · simp [decodeOp, hc]
      · rw [if_neg h2]
        have e : leBytes d.length 2 = [(d.length % 256).toUInt8, (d.length / 256 % 256).toUInt8] := by
          simp [leBytes]
        rw [e]
        have h3 := toNat_toUInt8 (d.length % 256) (by omega)
        have h4 := toNat_toUInt8 (d.length / 256 % 256) (by omega)
        constructor
        · simp [opLen, h3, h4]; omega
        · simp [decodeOp]

theorem pnon_parse (d rest : Bytes) (h : d.length ≤ 255) :
    opLen (pushNonmin d ++ rest) = some (pushNonmin d).length ∧
    decodeOp (pushNonmin d ++ rest) (pushNonmin d).length = .push d := by
  unfold pushNonmin
  have hc := toNat_toUInt8 d.length (by omega)
  constructor
  · simp [opLen, hc]; omega
  · simp [decodeOp]

theorem natLE_length_le' (n k : Nat) (h : n < 256 ^ k) : (natLE n).length ≤ k := by
  induction k generalizing n with
  | zero => simp at h; subst h; simp [natLE]
  | succ k ih =>
    unfold natLE
    split
    · simp
    · simp only [List.length_cons]
      have := ih (n / 256) (by rw [Nat.pow_succ] at h; omega)
      omega

theorem numEnc_len (v : Nat) (h : v < 2 ^ 31) : (numEnc (v : Int)).length ≤ 5 := by
  have h1 := natLE_length_le' v 4 (by omega)
  unfold numEnc
  simp only [Int.natAbs_natCast]
  generalize natLE v = m at h1
  rcases List.eq_nil_or_concat m with hm | ⟨init, last, hm⟩
  · subst hm; simp
  · subst hm
    rw [List.concat_eq_append]
    simp only [List.getLast?_append, List.getLast?_singleton, Option.some_or]
    simp at h1
    split
    · simp; omega
    · split <;> simp <;> omega

theorem opLen_big (c : UInt8) (hc : 0x4e < c.toNat) (rest : Bytes) : opLen (c :: rest) = some 1 := by
  have h1 : c ≠ 0x4c := by intro e; subst e; simp at hc
  have h2 : c ≠ 0x4d := by intro e; subst e; simp at hc
  have h3 : c ≠ 0x4e := by intro e; subst e; simp at hc
  simp only [opLen]
  rw [if_neg (by omega)]
  simp [h1, h2, h3]

theorem num_parse (v : Nat) (rest : Bytes) (h : v < 2 ^ 31) :
    opLen (pushNum v ++ rest) = some (pushNum v).length ∧
    decodeOp (pushNum v ++ rest) (pushNum v).length = .push (numEnc v) := by
  unfold pushNum
  by_cases h0 : (v : Int) = 0
  · have : v = 0 := by omega
    subst this
    simp [opLen, decodeOp, numEnc, natLE]
  · rw [if_neg h0]
    by_cases h1 : 1 ≤ (v : Int) ∧ (v : Int) ≤ 16
    · rw [if_pos h1]
      have hv : (0x50 + (v : Int).toNat) < 256 := by omega
      have hc := toNat_toUInt8 _ hv
      constructor
      · simp only [List.cons_append]; rw [opLen_big _ (by omega)]; simp
      · simp only [List.cons_append, decodeOp]
        rw [hc, if_neg (by omega), if_pos (by omega)]
        congr 2; omega
    · rw [if_neg h1]
      have hl := numEnc_len v h
      have := pmin_parse (numEnc v) rest (by omega)
      exact this

theorem op_parse (o : Op) (rest : Bytes) :
    opLen ([Op.byte o] ++ rest) = some [Op.byte o].length ∧ decodeOp ([Op.byte o] ++ rest) [Op.byte o].length = .op o := by
  have hb := byte_ge o
  constructor
  · simp only [List.cons_append, List.nil_append]; rw [opLen_big _ (by omega)]; simp
  · simp only [List.cons_append, List.nil_append, decodeOp]
    rw [if_neg (by omega), if_neg (by omega)]
    have h4f : Op.byte o ≠ 0x4f := by intro e; rw [e] at hb; simp at hb
    simp [h4f, ofByte_byte]

inductive CI where
  | pmin (d : Bytes)
  | pnon (d : Bytes)
  | num (v : Nat)
  | op (o : Op)

def CI.bytes : CI → Bytes
  | .pmin d => pushMinE d
  | .pnon d => pushNonmin d
  | .num v => pushNum v
  | .op o => [Op.byte o]

def CI.instr : CI → Instr
  | .pmin d => .push d
  | .pnon d => .push d
  | .num v => .push (numEnc v)
  | .op o => .op o

def CI.wf : CI → Bool
  | .pmin d => d.length ≤ 520
  | .pnon d => d.length ≤ 255
  | .num v => v < 2 ^ 31
  | .op _ => true

def encode (cs : List CI) : Bytes := cs.flatMap CI.bytes


theorem parse1 (ci : CI) (hw : ci.wf = true) (rest : Bytes) :
    opLen (ci.bytes ++ rest) = some ci.bytes.length ∧
    decodeOp (ci.bytes ++ rest) ci.bytes.length = ci.instr := by
  cases ci with
  | pmin d => simp only [CI.wf, decide_eq_true_eq] at hw; exact pmin_parse d rest hw
  | pnon d => simp only [CI.wf, decide_eq_true_eq] at hw; exact pnon_parse d rest hw
  | num v => simp only [CI.wf, decide_eq_true_eq] at hw; exact num_parse v rest hw
  | op o => exact op_parse o rest

theorem pushMinE_ne (d : Bytes) : pushMinE d ≠ [] := by
  unfold pushMinE; split <;> (try split) <;> (try split) <;> simp

theorem bytes_ne_nil (ci : CI) : ci.bytes ≠ [] := by
  cases ci with
  | pmin d => exact pushMinE_ne d
  | pnon d => simp [CI.bytes, pushNonmin]
  | num v =>
    simp only [CI.bytes]; unfold pushNum
    split
    · simp
    · split
      · simp
      · exact pushMinE_ne _
  | op o => simp [CI.bytes]

theorem parseF_encode (cs : List CI) (hw : cs.all CI.wf = true) :
    ∀ f, (encode cs).length < f → parseF f (encode cs) = some (cs.map CI.instr) := by
  induction cs with
  | nil => intro f _; cases f <;> simp [encode, parseF]
  | cons ci cs ih =>
    intro f hf
    simp only [List.all_cons, Bool.and_eq_true] at hw
    have hne := bytes_ne_nil ci
    have hpos : 0 < ci.bytes.length := List.length_pos_iff.mpr hne
    have hlen : (encode (ci :: cs)) = ci.bytes ++ encode cs := by simp [encode]
    rw [hlen] at hf ⊢
    obtain ⟨b, bs, hb⟩ := List.exists_cons_of_ne_nil hne
    obtain ⟨f', rfl⟩ : ∃ f', f = f' + 1 := ⟨f - 1, by simp at hf; omega⟩
    obtain ⟨h1, h2⟩ := parse1 ci hw.1 (encode cs)
    have hdrop : (ci.bytes ++ encode cs).drop ci.bytes.length = encode cs := by simp
    have := ih hw.2 f' (by simp at hf; omega)
    rw [hb] at h1 h2 hdrop ⊢
    simp only [List.cons_append, parseF] at h1 h2 hdrop ⊢
    rw [h1]; simp only [Option.map_some]
    rw [hdrop, this, h2]; simp

theorem parse_encode (cs : List CI) (hw : cs.all CI.wf = true) :
    parse (encode cs) = some (cs.map CI.instr) :=
  parseF_encode cs hw _ (by omega)

def encode_def (cs : List CI) : encode cs = cs.flatMap CI.bytes := rfl

/-! ## The TS2 family in closed form -/

/-- The puzzle hash opcode of a design. -/
def hashOpOf (b : UInt8) : Op :=
  if b = 0xa6 then .ripemd160 else if b = 0xa7 then .sha1 else .sha256

/-- Membership in the TS2 family: one round, no bonus keys, no chains, no signing, forced-compressed
round key, pool-first layout. -/
def isTS2 (p : Params) : Bool :=
  p.ts.length == 1 && p.bs == [0] && p.chainPin == 1 && p.chains == [1] && !p.signJ && !p.signLvl &&
  p.forceComp && p.poolDeep && p.kbound.length == 2 &&
  (p.hashOp == 0xa6 || p.hashOp == 0xa7 || p.hashOp == 0xa8) &&
  !p.spacerSelection && !p.destructiveChain

section
variable (p : Params) (rnd : Rand)

def tT := p.ts[0]!
def kP := p.kbound[0]!
def k1 := p.kbound[1]!
def N0 := 2 * p.n + p.k

def pushesB : List CI :=
  (List.range p.k).reverse.map (fun i => .pnon (poolSig (i + 1))) ++
  (List.range p.n).reverse.map (fun i => .pmin (commit rnd 0 i)) ++
  (List.range p.n).reverse.map (fun i => .pmin (dummy rnd 0 i))

def pinB : List CI :=
  [.num (N0 p), .op .roll, .num (2 * p.n + kP p - 1), .op .min, .op .pick, .num (N0 p + 1), .op .pick,
   .op .checkSigVerify, .num (N0 p), .op .roll, .op (hashOpOf p.hashOp), .num 1, .op .checkSig, .op .drop]

def proB : List CI :=
  [.num 0, .num (N0 p + 1), .op .roll, .num (2 * p.n + k1 p), .op .min, .op .pick]

/-- The HORS selection gadget for selection `i` (0-based). -/
def selB (i : Nat) : List CI :=
  [.num (2 * p.n + p.k + tT p + 1 - 2 * i), .op .roll, .num (p.n + 1), .op .min, .op .dup,
   .num (p.n - i + 1), .op .add, .op .roll, .num (2 * (p.n - i) + p.k + 2 * tT p + 1 - i), .op .roll,
   .op .hash160, .op .equalVerify, .op .roll]

def epiB : List CI :=
  [.num (2 * p.n + p.k + 2 - tT p), .op .roll, .op .size, .num 33, .op .equalVerify, .op .dup,
   .op (hashOpOf p.hashOp), .num 1, .op .checkSig, .op .drop, .num (tT p + 1), .op .swap] ++
  (List.range (tT p)).flatMap (fun _ => [.num (2 * p.n + p.k + 3), .op .roll]) ++
  [.num (tT p + 1), .op .checkMultiSig]

def blocksTS2 : List CI :=
  pushesB p rnd ++ pinB p ++ proB p ++ (List.range (tT p)).flatMap (selB p) ++ epiB p

/-- the symbolic-stack builder emits exactly the closed form -/
def sideScript : Bool := (build p rnd).script == encode (blocksTS2 p rnd)
/-- every push is well formed (sizes, numbers < 2^31) -/
def sideWF : Bool := (blocksTS2 p rnd).all CI.wf
/-- shape of the parameters -/
def sideArith : Bool :=
  decide (1 ≤ tT p) && decide (2 * tT p ≤ p.n) && decide (k1 p ≤ p.k) && decide (1 ≤ kP p) &&
  decide (4 * p.n + 2 * p.k + 4 * tT p + 16 < 2 ^ 31)
/-- dummies are neither empty nor 20 bytes; commitments are pairwise distinct -/
def sideData : Bool :=
  ((List.range p.n).all fun i => (dummy rnd 0 i).length != 20 && (dummy rnd 0 i).length != 0) &&
  ((List.range p.n).map (commit rnd 0)).Nodup

/-- Side conditions of the TS2-family theorem, all decidable (checked per instance). -/
def SideTS2 : Bool := isTS2 p && sideScript p rnd && sideWF p rnd && sideArith p && sideData p rnd

theorem parse_build_TS2 (h : SideTS2 p rnd = true) :
    parse (build p rnd).script = some ((blocksTS2 p rnd).map CI.instr) := by
  simp only [SideTS2, Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨-, he⟩, hw⟩, -⟩, -⟩ := h
  simp only [sideScript, beq_iff_eq] at he
  rw [he]; exact parse_encode _ hw

end

end QSB.Blocks
