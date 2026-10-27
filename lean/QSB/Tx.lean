import QSB.Script
import QSB.Hash
import QSB.Secp

/-! Legacy transactions, Core's legacy `SignatureHash`, and the concrete `Crypto` instance used by
the differential checker (executable, trusted). -/

namespace QSB.Tx

structure TxIn where
  prevout : Bytes        -- 36 bytes
  scriptSig : Bytes
  sequence : Bytes       -- 4 bytes
  deriving Inhabited
structure TxOut where
  value : Bytes          -- 8 bytes
  spk : Bytes
  deriving Inhabited
structure Tx where
  version : Bytes
  ins : List TxIn
  outs : List TxOut
  locktime : Bytes

abbrev P := StateT Bytes Option

def take (n : Nat) : P Bytes := do
  let s ← get
  if s.length < n then failure
  set (s.drop n); pure (s.take n)

def varint : P Nat := do
  let b ← take 1
  let v := (b.getD 0 0).toNat
  if v < 0xfd then pure v
  else if v == 0xfd then do pure (leVal (← take 2))
  else if v == 0xfe then do pure (leVal (← take 4))
  else do pure (leVal (← take 8))

def listOf {α} (n : Nat) (p : P α) : P (List α) :=
  match n with
  | 0 => pure []
  | k + 1 => do let a ← p; let r ← listOf k p; pure (a :: r)

def parseTx (b : Bytes) : Option Tx := do
  let (tx, rest) ← (do
    let version ← take 4
    let nin ← varint
    if nin == 0 then failure           -- segwit marker: not modelled
    let ins ← listOf nin (do
      let po ← take 36; let l ← varint; let ss ← take l; let sq ← take 4; pure (TxIn.mk po ss sq))
    let nout ← varint
    let outs ← listOf nout (do let v ← take 8; let l ← varint; let spk ← take l; pure (TxOut.mk v spk))
    let lt ← take 4
    pure (Tx.mk version ins outs lt) : P Tx).run b
  if rest.isEmpty then some tx else none

def serVarint (n : Nat) : Bytes :=
  if n < 0xfd then [n.toUInt8]
  else if n ≤ 0xffff then 0xfd :: leBytes n 2
  else if n ≤ 0xffffffff then 0xfe :: leBytes n 4
  else 0xff :: leBytes n 8

/-- Core `SignatureHash` (SigVersion::BASE) as the message scalar z (32 bytes read big-endian).
`scriptCode` contains no OP_CODESEPARATOR (checked by the caller). -/
def sighash (tx : Tx) (nIn : Nat) (scriptCode : Bytes) (hashType : Nat) : Nat :=
  let base := hashType % 32
  let none_ := base == 2
  let single := base == 3
  let acp := hashType &&& 0x80 != 0
  if nIn ≥ tx.ins.length then 2^248
  else if single && nIn ≥ tx.outs.length then 2^248       -- the SIGHASH_SINGLE bug: uint256 ONE
  else
    let idxs := if acp then [nIn] else List.range tx.ins.length
    let insSer := idxs.flatMap fun i =>
      let t := tx.ins[i]!
      let sc := if i == nIn then serVarint scriptCode.length ++ scriptCode else [0]
      let sq := if i != nIn && (none_ || single) then [0, 0, 0, 0] else t.sequence
      t.prevout ++ sc ++ sq
    let outIdx := if none_ then [] else if single then List.range (nIn + 1) else List.range tx.outs.length
    let outsSer := outIdx.flatMap fun i =>
      if single && i != nIn then List.replicate 8 0xff ++ [0]
      else let o := tx.outs[i]!; o.value ++ serVarint o.spk.length ++ o.spk
    let pre := tx.version ++ serVarint idxs.length ++ insSer ++ serVarint outIdx.length ++ outsSer ++
      tx.locktime ++ leBytes hashType 4
    beVal (Hash.hash256 pre)

def concrete (tx : Tx) (nIn : Nat) : Crypto where
  sha256 := Hash.sha256
  ripemd160 := Hash.ripemd160
  sha1 := Hash.sha1
  checkSig sig pk sc :=
    match sig.getLast? with
    | none => false
    | some ht => Secp.verify (sighash tx nIn sc ht.toNat) sig.dropLast pk

/-- libbitcoinconsensus-style verification of input `nIn` against a bare scriptPubKey. -/
def verifyInput (spk txBytes : Bytes) (nIn : Nat) : Except Err Unit :=
  match parseTx txBytes with
  | none => .error (.unsupported 0)
  | some tx =>
    if h : nIn < tx.ins.length then
      let cr := concrete tx nIn
      verifyScript cr cr (tx.ins[nIn]).scriptSig spk
    else .error (.unsupported 0)

end QSB.Tx
