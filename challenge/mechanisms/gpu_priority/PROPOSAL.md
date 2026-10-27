# GPU-first upper-tier submissions and bonus-space correction

The user prioritizes GPU-hours over bytes in this repository, at security-menu
tiers D and E. The later explicit target is under two GPU-hours, preferably
under thirty minutes, at both tiers. The results here are intermediate gains;
they do not satisfy that time target.

## Accepted local submissions

| Design | Classical bits | Quantum bits | Collision bits | Frozen-model GPU-h | Total vB |
|---|---:|---:|---:|---:|---:|
| Original D | 111.799 | 49.815 | 78.421 | 5.846* |  — |
| `gpu_d_0` | 115.176 | 51.503 | 82.692 | 5.330 | 10934 |
| Original E | 116.176 | 52.003 | 82.627 | 6.041 | — |
| `gpu_e_0` | 116.842 | 52.129 | 83.101 | 5.574 | 10893 |

Both new designs pass the unmodified judge in deep mode. D has 85,038 audit
runs over three seeds and 264 Core/Lean consensus vectors; E has 84,354 audit
runs and 259 consensus vectors. Each has 1,000 honest-space samples and a
byte-identical rebuild by the frozen Lean builder. They are `audited`, not
fully formally proven design families. Their archived reports are in
`challenge/leaderboard/runs/20261027T103420Z_gpu_d_0_deep.json` and
`challenge/leaderboard/runs/20261027T102843Z_gpu_e_0_deep.json`.

These designs join the split (bytes, GPU-hours, security) frontier. They are
dominated on the default fee-weighted frontier, as expected when spending more
bytes to save compute. GPU-hours are estimates from frozen measured stage
rates, including rehashing and retries; no full GPU search was performed here.

The nominal reductions against the same frozen cost model are 8.83% for D and
7.73% for E. The older SECURITY_MENU times use a different accounting basis and
must not be compared directly to these estimates.

## Verified bug: signed/bonus partitions are not independent puzzle inputs

For t signed and b bonus selections from n distinct dummies, a union U of size
t+b has `C(t+b,t)` different choices of which openings to call signed. All have
the same FindAndDelete result. With the same nonce signature, recovered-key
parity, encoding, and chain level, they query the same puzzle input.

The number of distinct subset inputs is therefore `C(n,t+b)`, not
`C(n,t)*C(n-t,b) = C(n,t+b)*C(t+b,t)`. The latter counts distinct authorizations,
but counting those as independent search chances overstates E. The current
honest-space audit deliberately sorts the entire subset and does not identify
this issue with random sampling.

`check_bonus_space.py` constructs all seven partitions of one union in tier D.
For both production and test-mode scripts it checks seven distinct witnesses,
one sighash, and one recovered puzzle key. All seven test-mode witnesses are
VALID in Bitcoin Core. No real puzzle hit is claimed for the production script.

The distinct-input E1 for D is 0.759919 rather than 5.319436. Under the same
Poisson model, the per-pin probability of round-1 success is approximately
0.532296 rather than 0.995104. Replacing E1 in the existing cost formula gives
approximately 7.429 GPU-hours, not 5.846. This correction concerns the ordinary
honest search over legitimate distinct bonus dummies. It does not assert an
exhaustive optimal search over all off-region witness freedoms.

No trusted file has been changed to conceal or exploit this finding. The new
submitted candidates have zero bonus selections. The search filters candidates
with this error; it retains the original D estimate only for transparent
baseline comparison. The exact security/collision implications of repairing all
bonus accounting merit a separate review.

## Search and reproducibility

Base commit: `2263cd305ab31c9e8e538ab3d1ec617d232f42e3`.
Dependencies: Python standard library, the repository's Rust/Core runner, and
Lean 4.28.0. Both verifiers were built locally without altering trusted sources.

```sh
python3 challenge/mechanisms/gpu_priority/check_bonus_space.py
python3 challenge/mechanisms/gpu_priority/search.py --steps 500000 --finalists 1200 --screen
cd challenge
./run_ranked.sh submissions/gpu_d_0 --deep
./run_ranked.sh submissions/gpu_e_0 --deep
python3 leaderboard.py --dims split
```

The deterministic search seed is 20261027. It ranks by the repository's fast
GPU model, then rebuilds finalists and recomputes exact security, script limits,
and frozen-table costs. Every baseline security axis must be maintained. The
proxy does not establish validity. An early n141 E candidate was correctly
rejected because its test-mode twin exceeded 10,000 bytes; the accepted n140
candidate and final search check both sizes. A t=2 gadget-only test also exposed
that the existing vector generator expects at least four selections; those
gadget tests were changed to t=4 without changing any trusted code.

## Scope of the remaining target

Parameter changes and the destructive chain selector do not achieve under two
hours. Three DER-bound stages need, in the idealized independent-trial model,
at least three successful rare events. At the measured compression rates in
this repository this is already around two hours before EC work and retries.
This is a statement about the existing predicates and measurements, not a
universal impossibility theorem about every Bitcoin construction or GPU kernel.

The next work must reduce per-shot work substantially, use a different
transaction-binding predicate/construction, or present an explicitly accounted
amortization with equivalent security. Extra GPUs reducing elapsed time do not
reduce GPU-hours. Setup work, unsuccessful searches, and batching denominators
must be counted explicitly; none are silently excluded here.
