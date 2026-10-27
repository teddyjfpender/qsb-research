# qsb-judge-3: spacer mechanism promotion

This is an organizer release requested by the repository owner. It integrates
the previously measured spacer proposal into the trusted, data-only ranked
workflow. The solver sandbox rules still apply to ordinary challenge runs.

## Registered design language

`qsb-design-v2` remains accepted with its original layout. `qsb-design-v3`
adds two required fields:

```
"selection_layout": "split" | "spacer"
"destructive_chain": true | false
```

Spacer designs require pool-first layout, zero bonus selections and unsigned
indices/levels. Existing opcode, byte, stack, admissibility, audit and consensus
gates remain in force. Unmeasured new layouts are rejected at the cost gate.
Only the exact D/E shapes below have frozen measured rates in this release.

| Submission | Measured-rate projection | Conservative scored hours | Security confidence |
|---|---:|---:|---|
| `spacer_d` | 4.413 h | 4.657 h | audited |
| `spacer_e` | 4.498 h | 4.739 h | audited |

Both figures appear on the leaderboard row and in the cost-gate JSON. The
scored figure uses each stage's slowest real-DER repeat times a 0.95 rate
allowance. The measured projection uses stage medians. Neither is a full-solve
observation or a deadline guarantee. Bytes, fees and all three security axes
are still computed by the judge from its own build and analyser.

## Evidence and proof boundary

- Trusted `qsb_pool.py` and `lean/QSB/Build.lean` implement the same layout and
  destructive round-chain selection. The old published D/E production and
  stand-in scripts are reproduced byte for byte. No proposal code is imported
  by the judge.
- Local pairing and cleanup lemmas are part of the Lean library. The extended
  full-family target includes residual pin-chain nonce choices and is pinned
  in `QSB/SpacerSoundness.lean`. It remains unproved; the ranked confidence is
  explicitly `audited`. Existing TS2 statements are not weakened.
- The analyser's S counts retain the pin-chain extras. Exact DER probabilities
  exclude empty integers. Bonus honest-space counting now uses distinct
  FindAndDelete unions. Both counting corrections have independent anchors.
- `tests/spacer_promotion.py` exercises golden bytes, different build seeds,
  schema rejection, unmeasured-shape rejection, odd/even cleanup lengths,
  endpoint/reversed selections, fake-pair boundary attacks, and whole-builder
  mutations. Removing either MIN or the HORS check must be detected.
- Core and Lean subprocess failures or incomplete outputs fail the consensus
  gate. A failed or incomplete Lean builder invocation cannot count as a pass.
- `judge/exact_rates.json` is regenerated from the 18 real-DER measurements by
  `tools/build_exact_rates.py`. Raw rates and independently checked GPU hits
  remain in `mechanisms/spacer_selection/gpu_validation/`. The old RND1
  measurement tool refuses to benchmark spacer layouts with the wrong input.

## Reproduce

From the repository root:

```
python3 challenge/tests/spacer_promotion.py
python3 challenge/tests/redteam.py
bash lean/check.sh
```

Then, from `challenge/`:

```
./run_ranked.sh submissions/spacer_d --deep
./run_ranked.sh submissions/spacer_e --deep
python3 leaderboard.py --dims split
```

`gpu_hours_rtx4090` is the conservative scored value;
`gpu_hours_measured_projection` is the projection from exact-layout medians.
The new release deliberately retains the conservative pricing policy.

## Accepted runs

The final manifest digest is `ffb31e8bd64490dd`. All four runs passed every
gate in deep mode:

- [spacer_d](../../leaderboard/runs/20261027T134022Z_spacer_d_deep.json):
  101,352 freedom-audit runs, 1,000 honest samples and 264 Core/Lean vectors.
- [spacer_e](../../leaderboard/runs/20261027T134022Z_spacer_e_deep.json):
  101,592 freedom-audit runs, 1,000 honest samples and 264 Core/Lean vectors.
- Previous [gpu_d_0](../../leaderboard/runs/20261027T134022Z_gpu_d_0_deep.json)
  and [gpu_e_0](../../leaderboard/runs/20261027T134022Z_gpu_e_0_deep.json)
  revalidated at 5.567 and 5.846 hours respectively.

Both spacers meet their original tier's classical, quantum and collision
thresholds after both counting corrections. D does not preserve every excess
security bit of `gpu_d_0`; the release JSON records the exact tier comparison.
The current revalidated frontier contains both spacers.

Integration validation passed 36 red-team cases, 160 additional Core/Lean
vectors, seven failed-verifier controls and the full Lean check (75 identical
builds and 658 replay vectors). See [the machine-readable release record](qsb-judge-3.json)
and [full Lean log](qsb-judge-3-lean-check.log).

## Versioning

The judge-2 manifest is archived at `releases/qsb-judge-2/MANIFEST.sha256`.
Its run files remain immutable in `leaderboard/runs/`; they are not relabeled
as judge-3 acceptances. The leaderboard includes only freshly accepted runs
under the current published manifest. Thus its current frontier is over the
designs revalidated in this release, not a claim that the old entire parameter
search has been rerun. `leaderboard.py --history` retains the earlier results.

The release manifest pins the exact rate table and all Lean sources, in
addition to the Python judge/builder and consensus harness. Its published
digest and validation summary are recorded in `qsb-judge-3.json` beside this
document, together with the accepted run paths and their content hashes.
