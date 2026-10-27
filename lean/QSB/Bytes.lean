/-! Byte strings as `List UInt8` (proof-friendly), plus hex and little/big-endian helpers. -/

namespace QSB

abbrev Bytes := List UInt8

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

partial def ofHex? (s : String) : Option Bytes :=
  let rec go (cs : List Char) (acc : Array UInt8) : Option (Array UInt8) :=
    match cs with
    | [] => some acc
    | a :: b :: rest => do
      let hi ← hexDigit a
      let lo ← hexDigit b
      go rest (acc.push (hi * 16 + lo).toUInt8)
    | _ => none
  (go s.toList #[]).map (·.toList)

def ofHex! (s : String) : Bytes := (ofHex? s).getD []

def toHex (b : Bytes) : String :=
  let d := "0123456789abcdef".toList
  String.join (b.map fun x => String.mk [d[x.toNat / 16]!, d[x.toNat % 16]!])

/-- Little-endian value of a byte string. -/
def leVal : Bytes → Nat
  | [] => 0
  | b :: bs => b.toNat + 256 * leVal bs

/-- Big-endian value of a byte string. -/
def beVal (b : Bytes) : Nat := b.foldl (fun acc x => acc * 256 + x.toNat) 0

def leBytes (v : Nat) : Nat → Bytes
  | 0 => []
  | k + 1 => (v % 256).toUInt8 :: leBytes (v / 256) k

def beBytes (v : Nat) (k : Nat) : Bytes := (leBytes v k).reverse

end QSB
