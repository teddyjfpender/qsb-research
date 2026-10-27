import QSB.Bytes

/-!
# A model of Bitcoin legacy (base sigversion) script, for the opcode subset QSB emits

Mirrors Bitcoin Core `EvalScript` / `VerifyScript` under libbitcoinconsensus'
`VERIFY_ALL_PRE_TAPROOT` flags (P2SH, DERSIG, NULLDUMMY, CLTV, CSV, WITNESS). In particular
MINIMALDATA, STRICTENC, LOW_S, NULLFAIL and CONST_SCRIPTCODE are *off* (policy only).

Rules modelled:
* op count: every opcode `> OP_16` counts 1, CHECKMULTISIG additionally counts nKeys; max 201;
* script size <= 10000 bytes, pushed element <= 520 bytes, stack size <= 1000 after every op;
* CScriptNum operands are at most 4 bytes (non-minimal encodings accepted), results are minimal;
* ROLL/PICK error on a negative or too-deep index;
* FindAndDelete exactly as Core (raw-byte matches starting at opcode boundaries);
* BIP66 `IsValidSignatureEncoding`;
* CHECKMULTISIG key/sig loop order, early termination, the extra (NULLDUMMY) item.

Cryptography is abstract: hash functions and the ECDSA check are fields of `Crypto`.
Stacks are lists with the head as the top of the stack.
-/

namespace QSB

/-! ## Script numbers (CScriptNum) -/

/-- Little-endian magnitude bytes, minimal (no trailing zero byte). -/
def natLE (n : Nat) : Bytes :=
  if h : n = 0 then [] else (n % 256).toUInt8 :: natLE (n / 256)
termination_by n
decreasing_by omega

/-- CScriptNum::serialize. -/
def numEnc (i : Int) : Bytes :=
  let m := natLE i.natAbs
  match m.getLast? with
  | none => []
  | some last =>
    if last.toNat ≥ 128 then m ++ [if i < 0 then 0x80 else 0x00]
    else if i < 0 then m.dropLast ++ [last ||| 0x80] else m

/-- CScriptNum::set_vch (value of a byte string of any length). -/
def numDec (b : Bytes) : Int :=
  match b.getLast? with
  | none => 0
  | some last =>
    if last.toNat ≥ 128 then -((leVal (b.dropLast ++ [last &&& 0x7f]) : Nat) : Int)
    else (leVal b : Int)

/-! ## Errors, crypto interface, state -/

inductive Err where
  | scriptSize | pushSize | opCount | stackSize | badOpcode | invalidStackOp | numOverflow
  | equalVerify | sigDer | checkSigVerify | checkMultiSigVerify | pubkeyCount | sigCount
  | nullDummy | evalFalse
  | unsupported (code : UInt8)       -- outside the modelled subset: NOT a Core verdict
  deriving Repr, DecidableEq, Inhabited

def num4 (b : Bytes) : Except Err Int :=
  if b.length > 4 then .error .numOverflow else .ok (numDec b)

structure Crypto where
  sha256 : Bytes → Bytes
  ripemd160 : Bytes → Bytes
  sha1 : Bytes → Bytes
  /-- `CheckECDSASignature(sig incl. hashtype byte, pubkey, scriptCode)`; `sig` is non-empty and strict DER. -/
  checkSig : Bytes → Bytes → Bytes → Bool

def Crypto.hash160 (c : Crypto) (b : Bytes) : Bytes := c.ripemd160 (c.sha256 b)

/-! ## Parsing (CScript::GetOp) -/

inductive Op where
  | nop | twoDrop | drop | dup | pick | roll | swap | size | equal | equalVerify | add | sub | min
  | ripemd160 | sha1 | sha256 | hash160 | checkSig | checkSigVerify | checkMultiSig | checkMultiSigVerify
  deriving Repr, DecidableEq, Inhabited

def Op.ofByte? : UInt8 → Option Op
  | 0x61 => some .nop | 0x6d => some .twoDrop | 0x75 => some .drop | 0x76 => some .dup
  | 0x79 => some .pick | 0x7a => some .roll | 0x7c => some .swap | 0x82 => some .size
  | 0x87 => some .equal | 0x88 => some .equalVerify | 0x93 => some .add | 0x94 => some .sub | 0xa3 => some .min
  | 0xa6 => some .ripemd160 | 0xa7 => some .sha1 | 0xa8 => some .sha256 | 0xa9 => some .hash160
  | 0xac => some .checkSig | 0xad => some .checkSigVerify | 0xae => some .checkMultiSig
  | 0xaf => some .checkMultiSigVerify
  | _ => none

inductive Instr where
  | push (data : Bytes)
  | op (o : Op)
  | other (code : UInt8)       -- any opcode outside the subset
  deriving Repr, DecidableEq, Inhabited

/-- Length in bytes of the operation starting the script (`GetOp`), or `none` if truncated. -/
def opLen : Bytes → Option Nat
  | [] => none
  | c :: rest =>
    if c.toNat < 0x4c then (if rest.length ≥ c.toNat then some (1 + c.toNat) else none)
    else if c == 0x4c then
      match rest with
      | l :: r => if r.length ≥ l.toNat then some (2 + l.toNat) else none
      | [] => none
    else if c == 0x4d then
      match rest with
      | a :: b :: r => let l := a.toNat + 256 * b.toNat; if r.length ≥ l then some (3 + l) else none
      | _ => none
    else if c == 0x4e then
      match rest with
      | a :: b :: c' :: d :: r =>
        let l := leVal [a, b, c', d]; if r.length ≥ l then some (5 + l) else none
      | _ => none
    else some 1

/-- Decode one operation of known length `n` (from `opLen`). -/
def decodeOp (s : Bytes) (n : Nat) : Instr :=
  match s with
  | [] => .other 0xff
  | c :: _ =>
    if c.toNat ≤ 0x4e then
      let hdr := if c.toNat < 0x4c then 1 else if c == 0x4c then 2 else if c == 0x4d then 3 else 5
      .push ((s.drop hdr).take (n - hdr))
    else if c.toNat ≥ 0x51 ∧ c.toNat ≤ 0x60 then .push (numEnc (c.toNat - 0x50))
    else if c == 0x4f then .push (numEnc (-1))
    else match Op.ofByte? c with
      | some o => .op o
      | none => .other c

/-- Parse with fuel (each step consumes >= 1 byte, so `s.length + 1` fuel always suffices). -/
def parseF : Nat → Bytes → Option (List Instr)
  | _, [] => some []
  | 0, _ => none
  | f + 1, s =>
    match opLen s with
    | none => none
    | some n => (parseF f (s.drop n)).map (decodeOp s n :: ·)

/-- Parse a script into instructions; `none` if some push is truncated (Core: BAD_OPCODE). -/
def parse (s : Bytes) : Option (List Instr) := parseF (s.length + 1) s

/-! ## FindAndDelete (Core, script.cpp) -/

/-- `CScript() << b`: the push used as FindAndDelete's pattern. -/
def pushMin (b : Bytes) : Bytes :=
  if b.length < 0x4c then (b.length.toUInt8) :: b
  else if b.length ≤ 0xff then 0x4c :: b.length.toUInt8 :: b
  else if b.length ≤ 0xffff then 0x4d :: (b.length % 256).toUInt8 :: (b.length / 256).toUInt8 :: b
  else 0x4e :: leBytes b.length 4 ++ b

/-- Strip leading copies of `pat` (Core's inner `while` loop). -/
def stripMatches (pat : Bytes) (s : Bytes) : Bytes :=
  if h : pat ≠ [] ∧ pat.isPrefixOf s = true then stripMatches pat (s.drop pat.length) else s
termination_by s.length
decreasing_by
  have hp : pat.length ≤ s.length := (List.isPrefixOf_iff_prefix.mp h.2).length_le
  have : 0 < pat.length := List.length_pos_iff.mpr h.1
  simp; omega

theorem stripMatches_le (pat : Bytes) : ∀ s : Bytes, (stripMatches pat s).length ≤ s.length := by
  intro s
  induction h : s.length using Nat.strongRecOn generalizing s with
  | _ n ih =>
    unfold stripMatches
    split
    · have hp : pat.length ≤ s.length := (List.isPrefixOf_iff_prefix.mp (by simp_all)).length_le
      have : 0 < pat.length := List.length_pos_iff.mpr (by simp_all)
      have := ih (s.drop pat.length).length (by simp; omega) (s.drop pat.length) rfl
      simp at this ⊢; omega
    · omega

/-- Core's `FindAndDelete(script, pat)` on the remaining script `s` (starting at an op boundary or
right after a match): strip matches, then copy one GetOp-sized chunk, and repeat; a truncated tail
is copied verbatim. Fuel `s.length + 1` always suffices (every round consumes >= 1 byte). -/
def findAndDeleteF (pat : Bytes) : Nat → Bytes → Bytes
  | 0, s => s
  | f + 1, s =>
    let s' := stripMatches pat s
    match opLen s' with
    | none => s'
    | some n => s'.take n ++ findAndDeleteF pat f (s'.drop n)

def findAndDelete (pat : Bytes) (s : Bytes) : Bytes := findAndDeleteF pat (s.length + 1) s

/-! ## BIP66 strict DER (interpreter.cpp IsValidSignatureEncoding) -/

def isValidSigEncoding (sig : Bytes) : Bool :=
  let n := sig.length
  let g := fun i => (sig.getD i 0).toNat
  if n < 9 || n > 73 then false
  else if g 0 != 0x30 then false
  else if g 1 != n - 3 then false
  else
    let lenR := g 3
    if 5 + lenR ≥ n then false
    else
      let lenS := g (5 + lenR)
      if lenR + lenS + 7 != n then false
      else if g 2 != 0x02 then false
      else if lenR == 0 then false
      else if g 4 &&& 0x80 != 0 then false
      else if lenR > 1 && g 4 == 0 && g 5 &&& 0x80 == 0 then false
      else if g (lenR + 4) != 0x02 then false
      else if lenS == 0 then false
      else if g (lenR + 6) &&& 0x80 != 0 then false
      else if lenS > 1 && g (lenR + 6) == 0 && g (lenR + 7) &&& 0x80 == 0 then false
      else true

/-! ## Interpreter -/

def vTrue : Bytes := [1]
def vFalse : Bytes := []

def castToBool (b : Bytes) : Bool :=
  match b.getLast? with
  | none => false
  | some last => b.dropLast.any (· != 0) || (last != 0 && last != 0x80)

structure Ctx where
  crypto : Crypto
  /-- the executing script (scriptCode source; no OP_CODESEPARATOR in QSB scripts) -/
  script : Bytes

structure St where
  stack : List Bytes
  ops : Nat
  deriving Repr, Inhabited

def MAX_OPS : Nat := 201

/-- CHECKMULTISIG signature loop: returns success, or a DER error. `sigs`/`keys` are in check order. -/
def cmsLoop (c : Ctx) (sc : Bytes) : List Bytes → List Bytes → Except Err Bool
  | [], _ => .ok true
  | sig :: sigs, keys =>
    if sigs.length + 1 > keys.length then .ok false else
    match keys with
    | [] => .ok false
    | key :: keys' =>
      if sig ≠ [] ∧ isValidSigEncoding sig = false then .error .sigDer else
      let ok := sig ≠ [] && c.crypto.checkSig sig key sc
      if ok then cmsLoop c sc sigs keys'
      else if sigs.length + 1 > keys'.length then .ok false
      else cmsLoop c sc (sig :: sigs) keys'
termination_by sigs keys => sigs.length + keys.length
decreasing_by all_goals simp_wf <;> simp_all <;> omega

def cmsExec (c : Ctx) (verify : Bool) (s : St) : Except Err St := do
  let st := s.stack
  match st with
  | [] => .error .invalidStackOp
  | nkb :: r => do
    let nk ← num4 nkb
    if nk < 0 ∨ nk > 20 then .error .pubkeyCount else
    let ops := s.ops + nk.toNat
    if ops > MAX_OPS then .error .opCount else
    let nk := nk.toNat
    if r.length < nk + 1 then .error .invalidStackOp else
    let keys := r.take nk
    let r2 := r.drop nk
    match r2 with
    | [] => .error .invalidStackOp
    | nsb :: r3 => do
      let ns ← num4 nsb
      if ns < 0 ∨ ns > nk then .error .sigCount else
      let ns := ns.toNat
      if r3.length < ns + 1 then .error .invalidStackOp else
      let sigs := r3.take ns
      let sc := sigs.foldl (fun acc sg => findAndDelete (pushMin sg) acc) c.script
      let ok ← cmsLoop c sc sigs keys
      match r3.drop ns with
      | [] => .error .invalidStackOp
      | dummy :: rest =>
        if dummy ≠ [] then .error .nullDummy else
        if verify then (if ok then .ok ⟨rest, ops⟩ else .error .checkMultiSigVerify)
        else .ok ⟨(if ok then vTrue else vFalse) :: rest, ops⟩


def stepOp (c : Ctx) (o : Op) (s : St) : Except Err St :=
  let st := s.stack
  match o, st with
  | .nop, _ => .ok s
  | .drop, _ :: r => .ok { s with stack := r }
  | .twoDrop, _ :: _ :: r => .ok { s with stack := r }
  | .dup, a :: r => .ok { s with stack := a :: a :: r }
  | .swap, a :: b :: r => .ok { s with stack := b :: a :: r }
  | .size, a :: r => .ok { s with stack := numEnc a.length :: a :: r }
  | .equal, a :: b :: r => .ok { s with stack := (if a = b then vTrue else vFalse) :: r }
  | .equalVerify, a :: b :: r => if a = b then .ok { s with stack := r } else .error .equalVerify
  | .add, b :: a :: r => do let x ← num4 a; let y ← num4 b; .ok { s with stack := numEnc (x + y) :: r }
  | .sub, b :: a :: r => do let x ← num4 a; let y ← num4 b; .ok { s with stack := numEnc (x - y) :: r }
  | .min, b :: a :: r => do let x ← num4 a; let y ← num4 b; .ok { s with stack := numEnc (if x < y then x else y) :: r }
  | .pick, nb :: r@(_ :: _) => do
      let n ← num4 nb
      if h : 0 ≤ n ∧ n.toNat < r.length then .ok { s with stack := r[n.toNat]'h.2 :: r } else .error .invalidStackOp
  | .roll, nb :: r@(_ :: _) => do
      let n ← num4 nb
      if h : 0 ≤ n ∧ n.toNat < r.length then .ok { s with stack := r[n.toNat]'h.2 :: r.eraseIdx n.toNat }
      else .error .invalidStackOp
  | .ripemd160, a :: r => .ok { s with stack := c.crypto.ripemd160 a :: r }
  | .sha1, a :: r => .ok { s with stack := c.crypto.sha1 a :: r }
  | .sha256, a :: r => .ok { s with stack := c.crypto.sha256 a :: r }
  | .hash160, a :: r => .ok { s with stack := c.crypto.hash160 a :: r }
  | .checkSig, pk :: sig :: r =>
      let sc := findAndDelete (pushMin sig) c.script
      if sig ≠ [] ∧ isValidSigEncoding sig = false then .error .sigDer else
      let ok := sig ≠ [] && c.crypto.checkSig sig pk sc
      .ok { s with stack := (if ok then vTrue else vFalse) :: r }
  | .checkSigVerify, pk :: sig :: r =>
      let sc := findAndDelete (pushMin sig) c.script
      if sig ≠ [] ∧ isValidSigEncoding sig = false then .error .sigDer else
      if sig ≠ [] && c.crypto.checkSig sig pk sc then .ok { s with stack := r } else .error .checkSigVerify
  | .checkMultiSig, _ => cmsExec c false s
  | .checkMultiSigVerify, _ => cmsExec c true s
  | _, _ => .error .invalidStackOp
def stepCore (c : Ctx) : Instr → St → Except Err St
  | .push d, s => if d.length > 520 then .error .pushSize else .ok { s with stack := d :: s.stack }
  | .op o, s => if s.ops + 1 > MAX_OPS then .error .opCount else stepOp c o { s with ops := s.ops + 1 }
  | .other code, _ => .error (.unsupported code)

def step (c : Ctx) (i : Instr) (s : St) : Except Err St := do
  let s' ← stepCore c i s
  if s'.stack.length > 1000 then .error .stackSize else .ok s'

def run (c : Ctx) : List Instr → St → Except Err St
  | [], s => .ok s
  | i :: is, s => do let s' ← step c i s; run c is s'

/-- EvalScript: size check, parse, execute with a fresh op counter. -/
def evalScript (cr : Crypto) (script : Bytes) (stack : List Bytes) : Except Err (List Bytes) := do
  if script.length > 10000 then .error .scriptSize
  match parse script with
  | none => .error .badOpcode
  | some is => do
    let s ← run ⟨cr, script⟩ is ⟨stack, 0⟩
    .ok s.stack

/-- `scriptPubKey.IsPayToScriptHash()`: `OP_HASH160 <20 bytes> OP_EQUAL`. -/
def isP2SH (spk : Bytes) : Bool :=
  spk.length == 23 && spk.getD 0 0 == 0xa9 && spk.getD 1 0 == 0x14 && spk.getD 22 0 == 0x87

/-- `IsWitnessProgram`: `OP_0..OP_16 <2..40 bytes>` (not modelled; reported as outside the model). -/
def isWitnessProgram (spk : Bytes) : Bool :=
  let v := (spk.getD 0 0).toNat
  4 ≤ spk.length && spk.length ≤ 42 && (v == 0 || (0x51 ≤ v && v ≤ 0x60)) && (spk.getD 1 0).toNat + 2 == spk.length

def isPushOnly (s : Bytes) : Bool :=
  match parse s with
  | some is => is.all fun i => match i with | .push _ => true | _ => false
  | none => false

/-- VerifyScript under P2SH | DERSIG | NULLDUMMY | WITNESS (no witness data). -/
def verifyScript (crSig crPk : Crypto) (scriptSig spk : Bytes) : Except Err Unit := do
  if isWitnessProgram spk then .error (.unsupported 0)
  let st ← evalScript crSig scriptSig []
  let copy := st
  let st ← evalScript crPk spk st
  match st with
  | top :: _ => if castToBool top then pure () else .error .evalFalse
  | [] => .error .evalFalse
  if isP2SH spk then
    if !isPushOnly scriptSig then .error .evalFalse
    match copy with
    | [] => .error .evalFalse
    | redeem :: rest =>
      let st2 ← evalScript crPk redeem rest
      match st2 with
      | top :: _ => if castToBool top then pure () else .error .evalFalse
      | [] => .error .evalFalse

/-! ## Static op count (what the 201 limit sees on any successful run of a straight-line script) -/

/-- Opcodes > OP_16 plus, for each CHECKMULTISIG(VERIFY), the small constant pushed just before it. -/
def staticOps : List Instr → Nat
  | [] => 0
  | .push d :: .op .checkMultiSig :: rest => 1 + (numDec d).toNat + staticOps rest
  | .push d :: .op .checkMultiSigVerify :: rest => 1 + (numDec d).toNat + staticOps rest
  | .push _ :: rest => staticOps rest
  | .op _ :: rest => 1 + staticOps rest
  | .other _ :: rest => 1 + staticOps rest

end QSB
