# Alternative-predicate investigation: no qualifying replacement found

This report records rejected shortcut families and a concrete forgery. It does
not propose an accepted faster puzzle. The tests are finite, and the Lean
lemmas are local interpreter facts. They do **not** prove that no better Bitcoin
construction exists.

## Tested routes

The input under investigation is a transaction-bound hash output of fixed
length 20 or 32 bytes. Synthetic DER, zero and negative-zero examples test
predicate behavior; they do not claim found hash preimages.

| Route | Result |
|---|---|
| Arithmetic, numeric comparisons, MIN/MAX, numeric boolean operations | Inputs longer than four bytes fail before the operation can expose bits. |
| PICK/ROLL using the hash as an index | The same numeric length restriction applies. |
| CLTV/CSV | Five-byte numeric operands are permitted; 20/32-byte values still fail. |
| SIZE or fixed stack depth | Reveals a constant, not a transaction-dependent digest. |
| IF / Boolean conversion | False only for all-zero or negative-zero strings: probability `2 / 256^L` for uniform length L. The common true outcome supplies negligible constraint. |
| Equality against one fixed L-byte value | Probability `1 / 256^L`, far harder than DER. |
| Equality against itself or an unconstrained witness value | Trivial to satisfy; does not bind a spending transaction. |
| Hash in the ECDSA pubkey slot | A 20/32-byte value is not a usable legacy ECDSA public key; negating failure adds no useful predicate. |
| Hash in a checked signature slot | Non-DER is a script error, not a Boolean false that NOT can catch. |
| Lazy CHECKMULTISIG | Can skip the hash entirely, but then it imposes no condition on the hash. |
| CAT, slicing and bitwise shortcuts | The tested disabled opcodes fail even inside an unexecuted branch. |

These observations agree with the relevant branches of
[Core 26's interpreter](https://raw.githubusercontent.com/bitcoin/bitcoin/v26.0/src/script/interpreter.cpp)
and its [script definitions](https://raw.githubusercontent.com/bitcoin/bitcoin/v26.0/src/script/script.h).
The executable probes, rather than an assertion of exhaustive opcode synthesis,
are the evidence for this catalogue.

## Concrete failure of a free comparison target

The deliberately weak candidate checks a hashlock, verifies a fixed nonce
signature under a supplied key, then compares SHA256(key) with a witness-supplied
digest. It appears to eliminate the DER grind.

For either transaction, an attacker can recover a suitable key from the fixed
signature and that transaction's sighash, compute its hash, and supply that
hash as the comparison value. The test constructs two spends of the same
synthetic outpoint, paying different P2PKH recipients, with the **same revealed
hashlock preimage**. Core accepts both scripts, and the Lean interpreter agrees.
No GPU search or discrete-log computation is required for this counterexample.

The fixed signature is pushed nonminimally, so FindAndDelete does not remove it.
The counterexample therefore preserves the intended fixed-signature/sighash
binding; the failure is the unconstrained hash comparison target. These are
script-validation test transactions, not funded or broadcast transactions.

The lazy-CHECKMULTISIG probes provide a separate control. With two required
signatures and two keys, failure of the first checked signature can stop the
loop before the second signature's DER check. Reversing which signature is
checked first restores the DER error. Skipping validation is not an easier
transaction-binding predicate.

## Evidence and limits

Run from the repository root:

```
python3 challenge/mechanisms/predicate_catalog/check.py
cd lean
lake env lean ../challenge/mechanisms/predicate_catalog/Proof.lean
```

- **2,146 Core vectors**, all with expected outcomes.
- **695 vectors** in the frozen Lean opcode subset agree with Core, with no
  unsupported cases in that subset. The other **1,451 are Core-only** tests;
  no Lean coverage is claimed for them.
- Seven local Lean lemmas cover numeric overflow, constant size information,
  Boolean false conditions, non-DER failure and the skipped-signature case.
  Their axioms are only `propext` and `Quot.sound`; no `sorry` or `native_decide`.
- The frozen builder, analyser, judge, Lean interpreter and Core harness are
  unchanged. No new GPU measurement or ranked submission was made.

The original alternatives reviewed were
[Heilman's signature-size construction](https://mirror.b10c.me/lists/bitcoindev/ZjzFtus_aBchwKz2@camus/t/),
[Binohash](https://robinlinus.com/binohash.pdf), and
[QSB](https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/main/paper/QSB.pdf).
QSB explicitly replaces the nonce-dependent size puzzle to address the Shor
threat. This limited literature review found no qualifying substitute; it is
not evidence that the global research frontier is exhausted.

The remaining gap is a different transaction-binding construction, or a faster
implementation outside the frozen rate model. The tests above do not cover all
multi-input algebraic constructions, all witness relationships, or novel
cryptanalytic algorithms. The sub-two-hour upper-tier target remains unresolved.
