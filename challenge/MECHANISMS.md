# Mechanism track: getting objective feedback on new ideas without trusting their code

The spacer-selection and destructive-round-chain mechanism has been promoted
in [qsb-judge-3](judge/releases/qsb-judge-3.md). Its D/E shapes now have trusted
builder/Lean support and frozen exact-layout rates; they use ordinary ranked
submissions. Their full-family security remains `audited`. The general
data-only provisional evaluator described below is still future work.

Parameter search inside the design language is automated and saturated (`tools/optimize.py`). The
remaining gains need new mechanisms, and new mechanisms are exactly where a judge is easiest to fool:
- the new code could lie;
- the security count could miss a freedom;
- the security reduction itself might not apply.

This document says how far the judge can take a mechanism *automatically*, and where a human or a
proof has to take over.

## Stage 1: proposal (human review)

`mechanisms/<name>/PROPOSAL.md` (AGENT.md, "The mechanism track"). An organizer checks that the
security argument is the right *kind*:
- the stages are still "puzzle hit bound to the transaction";
- every sighash variation is authorised;
- the reduction of SECURITY_PROOF.md applies.

The judge can't check this part.

## Stage 2: provisional evaluation from bytes (automatic; to build)

The judge never imports proposal code. The proposal's `build.py` runs in a separate sandboxed process
with no access to the judge, and returns **data only**:

| artefact | used by |
|---|---|
| production script bytes, and test-mode script bytes | static gate, twin gate |
| N honest witnesses (scriptSig item lists) for judge-supplied transactions, each tagged with the honest choice it encodes | honest-space audit, Core replay |
| the claimed stage count, puzzle hash, and per-stage S_i and E_i | security gate (as claims to be audited) |

The judge then derives everything it trusts from those bytes:
- **Limits and twin check.** Unchanged. They are already mechanism-agnostic.
- **Stages and P.** Derived from the script: the DER-only puzzle pattern `H OP_1 OP_CHECKSIG` on the
  honest path, H's output length, and the CHECKMULTISIG rounds. They are never read from claims.
- **Attacker knowledge.** Everything in the honest witnesses plus the script bytes. This is exactly
  what a real attacker sees, so nothing has to be declared.
- **Witness slot types.** Inferred from provenance on the honest run: an item consumed by
  ROLL/PICK/MIN is an index; one hashed and compared is a preimage; one used as a pubkey is a key.
  The freedom audit then perturbs each slot by its type, as it does today.
- **Freedom audit** against the claimed S_i. **Honest-space audit** against the claimed E_i, using
  the tagged honest witnesses: all must be accepted and distinct.
- **Core replay** of honest witnesses and realised audit runs, as today.
- **Cost** from the frozen rate table, charged by the derived stage shapes. New shapes need GPU
  measurement.

Results go on a separate **provisional** board, marked "audited, reduction unreviewed, unproven".
They never mix with the ranked board.

**What this can't establish.** Stage 2 doesn't cover:
- that the new gadget's freedoms are only the kinds the audit knows how to perturb (a novel witness
  item type needs a new audit strategy);
- that the security reduction applies.

Those are stages 1 and 3.

## Stage 3: promotion into the design language (organizer)

1. A trusted builder feature in `qsb_pool.py` and a byte-identical Lean port.
2. Analyser support, with the freedom counts argued in SECURITY_PROOF.md.
3. A Lean soundness proof for the family, or a documented extension of the frozen statement.
4. Red-team cases that break the mechanism on purpose and show the judge notices (`tests/redteam.py`).
5. New rate measurements for new shapes, a new judge manifest, and a published digest.

After that, the mechanism is part of the design language, and the automatic optimizer and every agent
can use it.
