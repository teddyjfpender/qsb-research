import QSB.Bytes

/-! Executable secp256k1 ECDSA verification with libsecp256k1's parsing rules (trusted, not verified).

Pubkeys: 33-byte 02/03 or 65-byte 04/06/07 (hybrid parity must match y), point on the curve.
Signatures: lax DER parse (strict DER was already enforced by the script layer); r or s >= n
or zero -> invalid; s is normalized to low-S before verification (as Core does). -/

namespace QSB.Secp

def P : Nat := 2^256 - 2^32 - 977
def N : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def Gx : Nat := 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
def Gy : Nat := 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def powMod (b e m : Nat) : Nat := Id.run do
  let mut r := 1 % m
  let mut b := b % m
  let mut e := e
  while e > 0 do
    if e % 2 == 1 then r := r * b % m
    b := b * b % m
    e := e / 2
  return r

def inv (a m : Nat) : Nat := powMod a (m - 2) m      -- m prime

/-- Jacobian point (X, Y, Z); Z = 0 is infinity. -/
structure JP where
  x : Nat
  y : Nat
  z : Nat

def JP.inf : JP := ⟨1, 1, 0⟩

def dbl (p : JP) : JP :=
  if p.z == 0 || p.y == 0 then JP.inf else
  let y2 := p.y * p.y % P
  let s := 4 * p.x * y2 % P
  let m := 3 * p.x * p.x % P
  let x3 := (m * m + 2 * (P - s)) % P
  let y3 := (m * ((s + P - x3) % P) + P - 8 * y2 * y2 % P) % P
  let z3 := 2 * p.y * p.z % P
  ⟨x3, y3, z3⟩

def add (p q : JP) : JP :=
  if p.z == 0 then q else if q.z == 0 then p else
  let z1z1 := p.z * p.z % P
  let z2z2 := q.z * q.z % P
  let u1 := p.x * z2z2 % P
  let u2 := q.x * z1z1 % P
  let s1 := p.y * q.z % P * z2z2 % P
  let s2 := q.y * p.z % P * z1z1 % P
  if u1 == u2 then (if s1 == s2 then dbl p else JP.inf) else
  let h := (u2 + P - u1) % P
  let r := (s2 + P - s1) % P
  let h2 := h * h % P
  let h3 := h * h2 % P
  let u1h2 := u1 * h2 % P
  let x3 := (r * r + 2 * P * 2 - h3 - 2 * u1h2) % P
  let y3 := (r * ((u1h2 + P - x3) % P) + P - s1 * h3 % P) % P
  let z3 := h * p.z % P * q.z % P
  ⟨x3, y3, z3⟩

def mul (k : Nat) (p : JP) : JP := Id.run do
  let mut acc := JP.inf
  let mut i := 256
  while i > 0 do
    i := i - 1
    acc := dbl acc
    if (k >>> i) % 2 == 1 then acc := add acc p
  return acc

def affineX (p : JP) : Option Nat :=
  if p.z == 0 then none else
  let zi := inv p.z P
  some (p.x * (zi * zi % P) % P)

def onCurve (x y : Nat) : Bool := x < P && y < P && (y * y % P) == (x * x % P * x + 7) % P

def parsePubkey (pk : Bytes) : Option JP :=
  match pk with
  | h :: rest =>
    if (h == 2 || h == 3) && rest.length == 32 then
      let x := beVal rest
      if x ≥ P then none else
      let rhs := (x * x % P * x + 7) % P
      let y := powMod rhs ((P + 1) / 4) P
      if y * y % P != rhs then none else
      let y := if y % 2 == (h.toNat - 2) then y else P - y
      some ⟨x, y, 1⟩
    else if (h == 4 || h == 6 || h == 7) && rest.length == 64 then
      let x := beVal (rest.take 32)
      let y := beVal (rest.drop 32)
      if !onCurve x y then none
      else if (h == 6 || h == 7) && y % 2 != h.toNat - 6 then none
      else some ⟨x, y, 1⟩
    else none
  | [] => none

/-- Lax DER parse of r and s (input already passed strict DER; hashtype byte removed). -/
def parseSigRS (sig : Bytes) : Option (Nat × Nat) :=
  let lr := (sig.getD 3 0).toNat
  let r := sig.drop 4 |>.take lr
  let ls := (sig.getD (5 + lr) 0).toNat
  let s := sig.drop (6 + lr) |>.take ls
  some (beVal r, beVal s)

/-- ECDSA verify on message scalar z (the sighash, read big-endian). -/
def verify (z : Nat) (sig pk : Bytes) : Bool :=
  match parsePubkey pk, parseSigRS sig with
  | some q, some (r, s) =>
    if r == 0 || s == 0 || r ≥ N || s ≥ N then false else
    let s := if s > N / 2 then N - s else s   -- Core normalizes; ECDSA is invariant under s -> n - s
    let w := inv s N
    let u1 := (z % N) * w % N
    let u2 := r * w % N
    let R := add (mul u1 ⟨Gx, Gy, 1⟩) (mul u2 q)
    match affineX R with
    | none => false
    | some x => x % N == r
  | _, _ => false

end QSB.Secp
