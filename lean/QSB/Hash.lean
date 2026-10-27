import QSB.Bytes

/-! Executable SHA-256, SHA-1 and RIPEMD-160 (FIPS 180-4 / RIPEMD-160 spec).

These are *trusted executable code*, not verified: the script model in `QSB.Script` takes hash
functions as parameters, and these instances are only used by the differential checker, where they
are cross-checked against Python's hashlib (commitments) and Core's recorded results (vectors). -/

namespace QSB.Hash

@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))
@[inline] def rotl (x : UInt32) (n : UInt32) : UInt32 := (x <<< n) ||| (x >>> (32 - n))

def pad (msg : ByteArray) (bigEndianLen : Bool) : ByteArray := Id.run do
  let bitLen := msg.size * 8
  let mut m := msg.push 0x80
  while m.size % 64 != 56 do
    m := m.push 0
  for i in [0:8] do
    let sh := if bigEndianLen then 8 * (7 - i) else 8 * i
    m := m.push (bitLen >>> sh).toUInt8
  return m

@[inline] def wordBE (m : ByteArray) (i : Nat) : UInt32 :=
  (m.get! i).toUInt32 <<< 24 ||| (m.get! (i+1)).toUInt32 <<< 16 ||| (m.get! (i+2)).toUInt32 <<< 8 ||| (m.get! (i+3)).toUInt32

@[inline] def wordLE (m : ByteArray) (i : Nat) : UInt32 :=
  (m.get! i).toUInt32 ||| (m.get! (i+1)).toUInt32 <<< 8 ||| (m.get! (i+2)).toUInt32 <<< 16 ||| (m.get! (i+3)).toUInt32 <<< 24

def outBE (ws : Array UInt32) : Bytes :=
  ws.toList.flatMap fun (w : UInt32) => [(w >>> 24).toUInt8, (w >>> 16).toUInt8, (w >>> 8).toUInt8, w.toUInt8]

def outLE (ws : Array UInt32) : Bytes :=
  ws.toList.flatMap fun (w : UInt32) => [w.toUInt8, (w >>> 8).toUInt8, (w >>> 16).toUInt8, (w >>> 24).toUInt8]

def K256 : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def sha256BA (msg : ByteArray) : Array UInt32 := Id.run do
  let m := pad msg true
  let mut h : Array UInt32 := #[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  let mut w : Array UInt32 := Array.replicate 64 0
  for blk in [0:m.size / 64] do
    for i in [0:16] do
      w := w.set! i (wordBE m (64 * blk + 4 * i))
    for i in [16:64] do
      let s0 := rotr w[i-15]! 7 ^^^ rotr w[i-15]! 18 ^^^ (w[i-15]! >>> 3)
      let s1 := rotr w[i-2]! 17 ^^^ rotr w[i-2]! 19 ^^^ (w[i-2]! >>> 10)
      w := w.set! i (w[i-16]! + s0 + w[i-7]! + s1)
    let mut a := h[0]!; let mut b := h[1]!; let mut c := h[2]!; let mut d := h[3]!
    let mut e := h[4]!; let mut f := h[5]!; let mut g := h[6]!; let mut hh := h[7]!
    for i in [0:64] do
      let S1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
      let ch := (e &&& f) ^^^ ((~~~e) &&& g)
      let t1 := hh + S1 + ch + K256[i]! + w[i]!
      let S0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
      let mj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
      let t2 := S0 + mj
      hh := g; g := f; f := e; e := d + t1; d := c; c := b; b := a; a := t1 + t2
    h := #[h[0]! + a, h[1]! + b, h[2]! + c, h[3]! + d, h[4]! + e, h[5]! + f, h[6]! + g, h[7]! + hh]
  return h

def sha256 (b : Bytes) : Bytes := outBE (sha256BA ⟨b.toArray⟩)

def sha1 (b : Bytes) : Bytes := Id.run do
  let m := pad ⟨b.toArray⟩ true
  let mut h : Array UInt32 := #[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
  let mut w : Array UInt32 := Array.replicate 80 0
  for blk in [0:m.size / 64] do
    for i in [0:16] do
      w := w.set! i (wordBE m (64 * blk + 4 * i))
    for i in [16:80] do
      w := w.set! i (rotl (w[i-3]! ^^^ w[i-8]! ^^^ w[i-14]! ^^^ w[i-16]!) 1)
    let mut a := h[0]!; let mut bb := h[1]!; let mut c := h[2]!; let mut d := h[3]!; let mut e := h[4]!
    for i in [0:80] do
      let (f, k) :=
        if i < 20 then ((bb &&& c) ||| ((~~~bb) &&& d), (0x5A827999 : UInt32))
        else if i < 40 then (bb ^^^ c ^^^ d, 0x6ED9EBA1)
        else if i < 60 then ((bb &&& c) ||| (bb &&& d) ||| (c &&& d), 0x8F1BBCDC)
        else (bb ^^^ c ^^^ d, 0xCA62C1D6)
      let t := rotl a 5 + f + e + k + w[i]!
      e := d; d := c; c := rotl bb 30; bb := a; a := t
    h := #[h[0]! + a, h[1]! + bb, h[2]! + c, h[3]! + d, h[4]! + e]
  return outBE h

def rmdR1 : Array Nat := #[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
  3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
def rmdR2 : Array Nat := #[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
  15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
def rmdS1 : Array UInt32 := #[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
  11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
def rmdS2 : Array UInt32 := #[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
  9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

@[inline] def rmdF (j : Nat) (x y z : UInt32) : UInt32 :=
  if j < 16 then x ^^^ y ^^^ z
  else if j < 32 then (x &&& y) ||| ((~~~x) &&& z)
  else if j < 48 then (x ||| ~~~y) ^^^ z
  else if j < 64 then (x &&& z) ||| (y &&& ~~~z)
  else x ^^^ (y ||| ~~~z)

def rmdK1 (j : Nat) : UInt32 :=
  if j < 16 then 0 else if j < 32 then 0x5A827999 else if j < 48 then 0x6ED9EBA1 else if j < 64 then 0x8F1BBCDC else 0xA953FD4E
def rmdK2 (j : Nat) : UInt32 :=
  if j < 16 then 0x50A28BE6 else if j < 32 then 0x5C4DD124 else if j < 48 then 0x6D703EF3 else if j < 64 then 0x7A6D76E9 else 0

def ripemd160 (b : Bytes) : Bytes := Id.run do
  let m := pad ⟨b.toArray⟩ false
  let mut h : Array UInt32 := #[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
  for blk in [0:m.size / 64] do
    let x : Array UInt32 := (List.range 16).toArray.map fun i => wordLE m (64 * blk + 4 * i)
    let mut al := h[0]!; let mut bl := h[1]!; let mut cl := h[2]!; let mut dl := h[3]!; let mut el := h[4]!
    let mut ar := h[0]!; let mut br := h[1]!; let mut cr := h[2]!; let mut dr := h[3]!; let mut er := h[4]!
    for j in [0:80] do
      let t := rotl (al + rmdF j bl cl dl + x[rmdR1[j]!]! + rmdK1 j) rmdS1[j]! + el
      al := el; el := dl; dl := rotl cl 10; cl := bl; bl := t
      let t2 := rotl (ar + rmdF (79 - j) br cr dr + x[rmdR2[j]!]! + rmdK2 j) rmdS2[j]! + er
      ar := er; er := dr; dr := rotl cr 10; cr := br; br := t2
    let t := h[1]! + cl + dr
    h := #[t, h[2]! + dl + er, h[3]! + el + ar, h[4]! + al + br, h[0]! + bl + cr]
  return outLE h

def hash160 (b : Bytes) : Bytes := ripemd160 (sha256 b)
def hash256 (b : Bytes) : Bytes := sha256 (sha256 b)

end QSB.Hash
