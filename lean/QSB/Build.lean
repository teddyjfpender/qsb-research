import QSB.Script
import QSB.Hash

/-!
# Lean port of `qsb_pool.build`

Mirrors the Python `Builder` line by line: a symbolic stack of labels (bottom -> top) from which
every depth constant is derived, the emitted script bytes, the op counter and the max stack.
Randomness (dummy signatures, HORS preimages) is an input, so the checker can feed Python's.
-/

namespace QSB.Build

/-- Build parameters with every `cfg.get(..)` default already resolved. -/
structure Params where
  n : Nat
  k : Nat
  ts : List Nat
  bs : List Nat
  kbound : List Nat          -- [k_pin, k_1, .., k_R]
  chainPin : Nat
  chains : List Nat
  hashOp : UInt8             -- 0xa8 SHA256, 0xa6 RIPEMD160, 0xa7 SHA1
  poolDeep : Bool
  forceComp : Bool
  signJ : Bool
  signLvl : Bool
  deriving Repr, Inhabited

structure Rand where
  dummies : List (List Bytes)
  pre : List (List Bytes)
  preJ : List (List Bytes)
  preL : List (List Bytes)
  deriving Inhabited

structure Opts where
  testMode : Bool := false
  realRoundPuzzle : Bool := false
  padOps : Nat := 0
  padBytes : Nat := 0

/-! ## push encodings (qsbcore.py) -/

def pushMinE (b : Bytes) : Bytes :=
  if b.length = 0 then [0x00]
  else if b.length < 0x4c then b.length.toUInt8 :: b
  else if b.length ≤ 0xff then 0x4c :: b.length.toUInt8 :: b
  else 0x4d :: leBytes b.length 2 ++ b

def pushNonmin (b : Bytes) : Bytes := 0x4c :: b.length.toUInt8 :: b

def pushNum (v : Int) : Bytes :=
  if v = 0 then [0x00]
  else if 1 ≤ v ∧ v ≤ 16 then [(0x50 + v.toNat).toUInt8]
  else pushMinE (numEnc v)

def derInt (v : Nat) : Bytes :=
  let b := beBytes v (max 1 ((Nat.log2 v + 8) / 8))
  if (b.headD 0).toNat ≥ 0x80 then 0 :: b else b

/-- qsbcore.der_sig: minimal strict-DER signature. -/
def derSig (r s : Nat) (ht : UInt8) : Bytes :=
  let rb := derInt r; let sb := derInt s
  let body := [0x02, rb.length.toUInt8] ++ rb ++ [0x02, sb.length.toUInt8] ++ sb
  [0x30, body.length.toUInt8] ++ body ++ [ht]

def TEST_DER20 : Bytes := ofHex! "3011020101020c0102030405060708090a0b7f01"

/-! ## the symbolic builder -/

structure B where
  stack : List String        -- bottom -> top
  script : Array UInt8
  ops : Nat
  maxStack : Nat
  hashOp : UInt8
  testMode : Bool
  /-- (A, m) of every selection gadget, in emission order (Python's plan["rounds"][r]["A"/"m"]) -/
  plan : Array (Nat × Nat) := #[]

abbrev BM := StateM B

def emit (b : Bytes) : BM Unit := modify fun s => { s with script := s.script ++ b.toArray }
def opc (code : UInt8) (count : Nat := 1) : BM Unit :=
  modify fun s => { s with script := s.script.push code, ops := s.ops + count }
def track : BM Unit := modify fun s => { s with maxStack := max s.maxStack s.stack.length }
def depth (l : String) : BM Nat := do
  let s ← get; return s.stack.length - 1 - s.stack.idxOf l
def append (l : String) : BM Unit := modify fun s => { s with stack := s.stack ++ [l] }
def pop : BM Unit := modify fun s => { s with stack := s.stack.dropLast }
def removeL (l : String) : BM Unit := modify fun s => { s with stack := s.stack.erase l }
def setTop (l : String) : BM Unit := modify fun s => { s with stack := s.stack.dropLast ++ [l] }
def swapTop : BM Unit := modify fun s =>
  let n := s.stack.length
  { s with stack := s.stack.take (n - 2) ++ (s.stack.drop (n - 2)).reverse }
def dropTop (k : Nat) : BM Unit := modify fun s => { s with stack := s.stack.take (s.stack.length - k) }

def push (l : String) (d : Bytes) (nonmin := false) : BM Unit := do
  emit (if nonmin then pushNonmin d else pushMinE d); append l; track
def pushN (l : String) (v : Int) : BM Unit := do emit (pushNum v); append l; track
def roll (l : String) : BM Unit := do
  let d ← depth l; emit (pushNum d); opc 0x7a; removeL l; append l
def pick (l new : String) : BM Unit := do
  let d ← depth l; emit (pushNum d); opc 0x79; append new; track
def min_ (bound : Int) : BM Unit := do emit (pushNum bound); opc 0xa3

def H : BM Unit := do
  let s ← get
  if s.testMode then do opc 0x75; emit (pushMinE TEST_DER20) else opc s.hashOp

def puzzle (m : Nat) (lvl : String) (cleanup : Bool) (signLvl : Option (String × String)) : BM Unit := do
  if m == 1 then
    H; emit (pushNum 1); opc 0xac; opc 0x75; pop
  else
    H; setTop "h1"
    for i in [2:m+1] do
      opc 0x76; append s!"h{i}"; H
    roll lvl
    min_ (m - 1 : Nat)
    if let some (cl0, preL) := signLvl then
      opc 0x76; append "v_copy"
      let off ← depth cl0
      emit (pushNum ((off : Int) - 1))
      opc 0x93; opc 0x79
      pop; append "cl_sel"
      roll preL
      opc 0xa9; opc 0x88
      pop; pop
    opc 0x79; pop; append "hsel"
    emit (pushNum 1); opc 0xac; opc 0x75; pop
    if cleanup then
      let mut left := m
      while left ≥ 2 do
        opc 0x6d; dropTop 2; left := left - 2
      if left > 0 then do opc 0x75; pop

def witness (p : Params) : List String := Id.run do
  let R := p.ts.length
  let mut w : List String := []
  for rd' in [0:R] do
    let rd := R - 1 - rd'
    let tb := p.ts[rd]! + p.bs[rd]!
    w := w ++ (List.range tb).map (fun i => s!"KD{rd}_{i}") ++ [s!"key{rd}"]
    w := w ++ (List.range p.ts[rd]!).map (fun i => s!"pre{rd}_{i}")
    w := w ++ (List.range tb).map (fun i => s!"x{rd}_{i}") ++ [s!"j{rd}"]
    if p.chains[rd]! > 1 then w := w ++ [s!"l{rd}"]
    if p.signJ then w := w ++ [s!"prej{rd}"]
    if p.signLvl && p.chains[rd]! > 1 then w := w ++ [s!"prel{rd}"]
  w := w ++ ["keyp", "jp"] ++ (if p.chainPin > 1 then ["lp"] else [])
  return w

def body (p : Params) (rnd : Rand) (o : Opts) : BM Unit := do
  let R := p.ts.length
  let n := p.n; let k := p.k
  let pool := (List.range k).map fun i => derSig 1 (i + 1) 0x01
  let comm := rnd.pre.map (·.map Hash.hash160)
  if o.padBytes > 0 then do push "pad" (List.replicate o.padBytes 0); opc 0x75; pop
  if p.poolDeep then
    for s' in [0:k] do
      let s := k - s'
      push s!"P{s}" pool[s - 1]! true
    for rd in [0:R] do
      if p.signJ then
        let kb := p.kbound[rd + 1]!
        for q in [0:kb] do
          let s := kb - q
          push s!"CJ{rd}_{s}" (Hash.hash160 rnd.preJ[rd]![s - 1]!)
      if p.signLvl && p.chains[rd]! > 1 then
        for q in [0:p.chains[rd]!] do
          let v := p.chains[rd]! - 1 - q
          push s!"CL{rd}_{v}" (Hash.hash160 rnd.preL[rd]![v]!)
  for rd' in [0:R] do
    let rd := R - 1 - rd'
    for q in [0:n] do
      let i := n - 1 - q
      push s!"C{rd}_{i}" comm[rd]![i]!
    for q in [0:n] do
      let i := n - 1 - q
      push s!"D{rd}_{i}" rnd.dummies[rd]![i]!
  if !p.poolDeep then
    for s' in [0:k] do
      let s := k - s'
      push s!"P{s}" pool[s - 1]! true
  -- pinning
  roll "jp"
  let d1 := (← depth "P1") - 1
  min_ (d1 + p.kbound[0]! - 1 : Nat)
  opc 0x79; pop; append "psig"
  pick "keyp" "keyp_copy"
  opc 0xad; pop; pop
  roll "keyp"
  puzzle p.chainPin "lp" false none
  -- rounds
  if o.realRoundPuzzle then modify fun s => { s with testMode := false }
  for rd in [0:R] do
    let t := p.ts[rd]!
    pushN s!"NULL{rd}" 0
    roll s!"j{rd}"
    let d1 := (← depth "P1") - 1
    min_ (d1 + p.kbound[rd + 1]! - 1 : Nat)
    if p.signJ then
      opc 0x76; append "j_copy"
      let off : Int := ((← depth "P1") : Int) - ((← depth s!"CJ{rd}_1") : Int) - 1
      emit (pushNum off)
      opc 0x94; opc 0x79
      pop; append "cj_sel"
      roll s!"prej{rd}"
      opc 0xa9; opc 0x88
      pop; pop
    opc 0x79; pop; append s!"nsig{rd}"
    let mut remaining := (List.range n).map fun i => s!"D{rd}_{i}"
    for i in [0:t] do
      roll s!"x{rd}_{i}"
      let top := remaining.headD ""
      let A := (← depth top) - 1
      let m := remaining.length
      modify fun s => { s with plan := s.plan.push (A, m) }
      min_ (A + m - 1 : Nat)
      opc 0x76
      emit (pushNum (1 + m : Nat))
      opc 0x93; opc 0x7a
      let st := (← get).stack
      let cref := (st.reverse.find? (fun l => l.startsWith s!"C{rd}_")).getD ""
      removeL cref; append "csel"
      roll s!"pre{rd}_{i}"
      opc 0xa9; opc 0x88
      pop; pop
      opc 0x7a
      pop; removeL top; remaining := remaining.drop 1
      append s!"dsel{rd}_{i}"
    for i in [t:t + p.bs[rd]!] do
      roll s!"x{rd}_{i}"
      let top := remaining.headD ""
      let A := (← depth top) - 1
      let m := remaining.length
      modify fun s => { s with plan := s.plan.push (A, m) }
      min_ (A + m - 1 : Nat)
      opc 0x7a
      pop; removeL top; remaining := remaining.drop 1
      append s!"dsel{rd}_{i}"
    let t := t + p.bs[rd]!
    roll s!"key{rd}"
    if p.forceComp then do opc 0x82; emit (pushNum 33); opc 0x88
    opc 0x76; append s!"key{rd}_copy"
    puzzle p.chains[rd]! s!"l{rd}" true
      (if p.signLvl && p.chains[rd]! > 1 then some (s!"CL{rd}_0", s!"prel{rd}") else none)
    pushN "m" (t + 1 : Nat)
    opc 0x7c; swapTop
    for i in [0:t] do roll s!"KD{rd}_{i}"
    pushN "n" (t + 1 : Nat)
    opc (if rd < R - 1 then 0xaf else 0xae) (1 + (t + 1))
    dropTop (2 * t + 5)
    if rd == R - 1 then append "TRUE"
  for _ in [0:o.padOps] do opc 0x61

structure Built where
  script : Bytes
  ops : Nat
  maxStack : Nat
  finalStack : List String
  plan : List (Nat × Nat)

def build (p : Params) (rnd : Rand) (o : Opts := {}) : Built :=
  let w := witness p
  let init : B := { stack := w, script := #[], ops := 0, maxStack := w.length, hashOp := p.hashOp, testMode := o.testMode }
  let ((), s) := (body p rnd o).run init
  ⟨s.script.toList, s.ops, s.maxStack, s.stack, s.plan.toList⟩

end QSB.Build
