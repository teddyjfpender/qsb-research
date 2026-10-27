# Program for a QSB research agent

You are optimizing the cost of a quantum-safe Bitcoin spend (QSB) at fixed security. A fixed judge
scores your work; you can't change it, and you don't need to: read it if you like, and it's built
to stay robust when fully known.

## Objective

**Push the Pareto frontier of (cost in sats ↓, 2nd-preimage bits ↑).** The judge's result for a
design is a vector (`score`: sats, preimage / quantum / collision bits, and whether the bits are
`proven` or `audited`), never a single number.

**Your result counts** if no deep-verified design dominates it, meaning none is both at least as
cheap and at least as secure. `run_ranked.sh` tells you, for every accepted run, whether it joins
the frontier or which design dominates it.

**Ways to contribute, most valuable first:**
1. **Move the frontier with a new mechanism.** Cheaper at every security level, or more bits for
   the same cost.
2. **Fill a gap in the frontier.** Look for a security level where the cheapest design is much more
   expensive than its neighbours: `leaderboard.py`, "cheapest ... with at least b bits".
3. **Turn `audited` into `proven`.** Prove a frozen soundness statement for a new family in Lean
   (FORMAL_VERIFICATION.md, M4/M5).

## Where things stand

Check this before you start: `python3 leaderboard.py`, `python3 leaderboard.py --frontier`.

- **The design language is already searched.** `tools/optimize.py` maps the design language's whole
  frontier with the judge's own gates, and its points are on the board.
- **So guessing parameters won't win.** Improvements have to come from new mechanisms (below), or
  from design-language regions the optimizer's grid skips. Read `tools/optimize.py` for the grid.
- **Fees are about 90% of the score.** Every byte costs 5 sats, and a GPU-hour costs 690.
  - A dummy+commitment pair (31 B) costs 155 sats.
  - One HORS selection costs 11 opcodes, and the 201-op limit is what caps 3-stage designs.
- **Hard floors, so you don't chase the impossible** (QSB_IMPROVEMENTS.md §10, §14):
  - Every stage costs at least 2^P hash compressions, because P is fixed by strict DER.
  - Two stages give at most about 2P bits, and 3 stages are needed above about 92.
  - The honest spender needs at least about P − log2(candidates per sighash) bits of *authorised*
    sighash variation per round.
- **Already tried and ruled out** (QSB_IMPROVEMENTS.md §11, §14, §15; don't resubmit these):
  - sighash-type pools;
  - CODESEPARATOR choice;
  - deletable pool signatures;
  - two nonce signatures in one multisig;
  - a shared dummy region;
  - spreading stages across inputs (attackers drop inputs);
  - SegWit/tapscript;
  - binary IF-chains (they only help for m ≥ 16).

## The loop

1. **Hypothesis.** Write one line in `research_log.md`: what you change and why it should help.
2. **Screen (about 1 s, unranked):**
   `python3 -m judge <dir> --mode screen --dev`
   - Runs the judge's real schema, build, static, security and cost gates.
   - Check `leaderboard.py --history` first. Never re-run a design that's already there.
   - Read `diagnostics`:
     - `headroom` shows which constraint binds: ops, bytes, bits, or E.
     - `cost_split` shows fees vs GPU.
     - `sats_at_other_fee_rates` shows how robust the design is.
3. **Rank (about 40 s):** `./run_ranked.sh submissions/<name>` (or `./run_batch.sh standard <dirs>`)
   - Adds the freedom audit, the honest-space audit, Core and Lean replay, and the Lean builder
     check.
   - A rejection names the gate and carries the evidence. A freedom-audit counterexample includes
     the witness.
4. **Promote:** `./run_ranked.sh submissions/<name> --deep`
   - Needed only if the ranked run would join the frontier.
   - Only deep-verified runs are on the board. The organizer also re-measures frontier designs'
     stage shapes on a GPU (`tools/measure_design.py`).
5. **Log the outcome.** Numbers, and whether the hypothesis held. Never repeat a logged experiment
   without a new reason.

A judge verdict of `judge-error` means you found a bug in the judge, not in your design. Report it:
it's a result.

## Rules

- **Where you write:** only `submissions/<name>/design.json`, `research_log.md`, and proposals under
  `mechanisms/<name>/`. Your sandbox can't write the judge, the builder, the analyser, the Lean
  model, or the Core harness.
- **Don't try to make the judge accept something that isn't secure.** It is built to catch that;
  when it doesn't, the report is still evidence against you. If you think you've found such a hole,
  write it up in `research_log.md` as a finding; that is worth more than a score.

## The mechanism track (where the real gains are)

A mechanism is anything the design language can't express. Examples:
- a new selection gadget with fewer opcodes or bytes per authorised bit;
- a new way to vary the sighash that only the owner can authorise;
- a different layout that frees opcodes.

Propose one as `mechanisms/<name>/PROPOSAL.md` with:

1. **The trick.** The script fragment, its stack effect, and what each witness item is.
2. **Why it's sound.** Which attacker choices it adds, as S_i factors, and why the security reduction
   (SECURITY_PROOF.md) still applies.
3. **A cost estimate** in the judge's terms: opcodes and bytes per authorised bit, and the score of
   the best design you expect.
4. **Optional:** a prototype builder, `mechanisms/<name>/build.py`, that emits a production script,
   a test-mode script and honest witnesses as **data** (see MECHANISMS.md, "provisional evaluation").
   The judge can then evaluate it from bytes alone, without running your code in its process.

Organizers promote a mechanism into the design language once it has a trusted builder, a Lean port
and proof, analyser support, and red-team cases (CHALLENGE.md, "What the loop can change").
