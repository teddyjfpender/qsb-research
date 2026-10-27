# Destructive selection of a hash-chain level

Status: promoted into qsb-design-v3 and used by the deep-accepted `spacer_d`
and `spacer_e` submissions. See the [judge-3 release](../../judge/releases/qsb-judge-3.md).
The original prototype evidence below includes a local Lean lemma and 1,032
vectors agreeing with Bitcoin Core and Lean. This is a small opcode improvement;
the under-two-hour target remains unmet.

## Fragment and stack effect

The existing round puzzle leaves all m chain outputs on the stack, uses
`OP_PICK` to copy the witness-selected output, checks DER, and drops all m
outputs. Change that final `OP_PICK` to `OP_ROLL`. Checking DER consumes the
selected output, so only m-1 outputs need cleanup.

The selector remains MIN-clamped to m-1. Negative indices still fail. The
optional authentication of the level is unchanged. Pinning is unchanged,
because its remaining chain values are visible to later round selectors and
changing them would require separate freedom accounting.

Before: `... h_1 ... h_m index PICK OP_1 CHECKSIG DROP cleanup(m)`.
After: `... h_1 ... h_m index ROLL OP_1 CHECKSIG DROP cleanup(m-1)`.

Both versions submit the same selected bytes to the same DER check. Both leave
exactly the same suffix after cleanup. With `OP_2DROP` cleanup, this saves one
opcode and one byte whenever m>1 is odd. It also reduces the transient stack
size by one at the selector. It never adds an attacker choice.

## Proof and its limits

`Proof.lean` proves `same_selected_value_and_suffix` for arbitrary hash values,
arbitrary suffixes, every in-range index, and an arbitrary acceptance predicate.
It uses the frozen model's byte/list representation. Its axioms are only
`propext` and `Quot.sound`; there is no `sorry`, `native_decide`, or new axiom.

This is a local stack-transformation theorem. It is not the missing full
two-round `SelectionSound` theorem. It also does not prove Core's C++ interpreter
equivalent to Lean. Core/Lean replay supplies independent executable evidence.
Changing script bytes changes sighashes, so existing real puzzle solutions must
be recomputed; identical stack behavior does not imply identical transactions.

For the same parameters, the intended S_i and E_i are unchanged: all levels,
nonce signatures, recovered-key parities, encodings, and authorized dummy sets
are the same. The prototype uses the existing analyser on that basis. Its
standalone example numbers below remain historical proposal estimates. The
promoted spacer combinations have exact-layout measured rates and fresh deep
audits. No claim of full-family proof is made.

## Implementation and reproduction

`build.py` subclasses the builder only inside the standalone proposal process;
it never changes a trusted file or runs within the frozen judge. It verifies
the exact terminal opcode pattern before replacing it, adjusts the symbolic
stack, and emits the shortened cleanup.

From the repository root:

```sh
python3 challenge/mechanisms/destructive_chain/build.py --test
cd lean
lake env lean ../challenge/mechanisms/destructive_chain/Proof.lean
```

Tests cover every selectable level for lengths 2 through 16, with and without
signed levels and pool indices. They also include wrong preimages, wrong keys,
negative and oversized indices, repeated selections, production non-hits,
opcode limits, and two full upper-tier shapes. All 1,032 Core verdicts match
expectations and the Lean replay has zero disagreements and zero unsupported
cases. Production and test-mode twins pass the unchanged parser; the two
upper-tier examples pass `design_check()` and static limits.

## Historical standalone cost estimates

| Candidate | Classical bits | Quantum bits | Collision bits | Ops | Production bytes | Model GPU-h |
|---|---:|---:|---:|---:|---:|---:|
| D, n134, k96, round chains 3/3 | 114.591 | 51.211 | 82.611 | 201 | 9806 | 5.283 |
| E, n139, k64, bounds 48/64, chains 3/3 | 116.176 | 52.296 | 83.060 | 201 | 9764 | 5.689 |

Both have seven signed selections per round, no bonus selections, SHA-256,
pool-first layout, one pinning hash, and allow all key encodings. GPU times use
the existing measured rate table plus its rehash/retry model, not a new GPU run.
The E example is slower than the independently ranked 5.574-hour E candidate;
the opcode optimization alone does not justify replacing that candidate.

The useful result is an independently checked local saving that future layouts
can compose. It does not remove the three-hit DER work requirement and does not
meet the user's under-two-hour target.
