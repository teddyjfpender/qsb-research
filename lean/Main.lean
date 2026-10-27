import QSB.Tx
import QSB.Build
import Lean.Data.Json
open QSB Lean

def replay (path : System.FilePath) : IO (Nat × Nat × Nat) := do
  let lines ← IO.FS.lines path
  let mut total := 0; let mut bad := 0; let mut gap := 0
  for l in lines do
    let f := (l.splitOn " ").filter (· ≠ "")
    if f.length != 5 then continue
    let spk := ofHex! f[1]!; let tx := ofHex! f[2]!
    let idx := f[3]!.toNat!; let expect := f[4]! == "1"
    total := total + 1
    match Tx.verifyInput spk tx idx with
    | .error (.unsupported c) =>
      gap := gap + 1; IO.println s!"GAP  {f[0]!} unsupported opcode {c}"
    | r =>
      let ok := match r with | .ok _ => true | .error _ => false
      if ok != expect then
        bad := bad + 1
        IO.println s!"FAIL {f[0]!} lean={ok} core={expect} {match r with | .error e => repr e | .ok _ => "ok".toFormat}"
  return (total, bad, gap)

def getE {α} [FromJson α] (j : Json) (k : String) : IO α :=
  match j.getObjValAs? α k with
  | .ok v => pure v
  | .error e => throw (IO.userError s!"json field {k}: {e}")

def hexLists (j : Json) (k : String) : IO (List (List Bytes)) := do
  let v : List (List String) ← getE j k
  return v.map (·.map ofHex!)

def checkScripts (path : System.FilePath) : IO (Nat × Nat) := do
  let txt ← IO.FS.readFile path
  let j ← match Json.parse txt with | .ok j => pure j | .error e => throw (IO.userError e)
  let arr ← match j.getArr? with | .ok a => pure a | .error e => throw (IO.userError e)
  let mut bad := 0
  for e in arr do
    let name : String ← getE e "name"
    let pj ← match e.getObjVal? "params" with | .ok v => pure v | .error er => throw (IO.userError er)
    let p : Build.Params := {
      n := ← getE pj "n", k := ← getE pj "k", ts := ← getE pj "ts", bs := ← getE pj "bs",
      kbound := ← getE pj "kbound", chainPin := ← getE pj "chain_pin", chains := ← getE pj "chains",
      hashOp := ((← getE pj "hash_op" : Nat)).toUInt8, poolDeep := ← getE pj "pool_deep",
      forceComp := ← getE pj "force_comp", signJ := ← getE pj "sign_j", signLvl := ← getE pj "sign_lvl" }
    let rnd : Build.Rand := { dummies := ← hexLists e "dummies", pre := ← hexLists e "pre",
                              preJ := ← hexLists e "pre_j", preL := ← hexLists e "pre_l" }
    let o : Build.Opts := { testMode := ← getE e "test_mode", realRoundPuzzle := ← getE e "real_round_puzzle",
                            padOps := ← getE e "pad_ops", padBytes := ← getE e "pad_bytes" }
    let b := Build.build p rnd o
    let pyScript := ofHex! (← getE e "script")
    let pyOps : Nat ← getE e "ops"
    let pyMax : Nat ← getE e "max_stack"
    let pyPlan : List (List Nat) ← getE e "plan"
    let mut errs : List String := []
    if b.script != pyScript then
      let i := ((b.script.zip pyScript).takeWhile (fun (a, c) => a == c)).length
      errs := errs ++ [s!"script bytes differ (lean {b.script.length} B, python {pyScript.length} B, first diff at {i})"]
    if b.ops != pyOps then errs := errs ++ [s!"ops lean {b.ops} python {pyOps}"]
    if b.maxStack != pyMax then errs := errs ++ [s!"max_stack lean {b.maxStack} python {pyMax}"]
    if b.plan.map (fun (a, m) => [a, m]) != pyPlan then errs := errs ++ ["selection plan (A, m) differs"]
    match parse pyScript with
    | none => errs := errs ++ ["python script does not parse (truncated push)"]
    | some is =>
      if staticOps is != pyOps then errs := errs ++ [s!"Core op-count rule gives {staticOps is}, python counted {pyOps}"]
      if is.any (fun i => match i with | .other _ => true | _ => false) then
        errs := errs ++ ["script uses an opcode outside the model"]
    if b.finalStack.getLast? != some "TRUE" then errs := errs ++ ["symbolic stack does not end with TRUE"]
    let leftover := b.finalStack.filter fun l => ["x", "pre", "KD", "key", "j"].any (fun (p : String) => l.startsWith p)
    if !leftover.isEmpty then errs := errs ++ [s!"witness items left unconsumed: {leftover.take 5}"]
    if errs.isEmpty then
      IO.println s!"OK   {name}: {pyScript.length} B, {pyOps} ops, max stack {pyMax}"
    else
      bad := bad + 1
      IO.println s!"FAIL {name}: {errs}"
  return (arr.size, bad)

def main (args : List String) : IO UInt32 := do
  let mut rc : UInt32 := 0
  let mut mode := "replay"
  for a in args do
    if a == "--scripts" then mode := "scripts"; continue
    if a == "--replay" then mode := "replay"; continue
    if mode == "scripts" then
      let (t, b) ← checkScripts a
      IO.println s!"scripts {a}: {t} builds, {b} differ between Lean and Python"
      if b > 0 then rc := 1
    else
      let (t, b, g) ← replay a
      IO.println s!"replay {a}: {t} vectors, {b} disagree with Core, {g} outside the model"
      if b > 0 || g > 0 then rc := 1
  return rc
