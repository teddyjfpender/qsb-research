# Measured spacer proposal and research closure

The requested timing validation is complete. Retain the spacer mechanism as a
local mechanism-track submission and close this research pass. Its timing is
supported by exact-layout GPU measurements, but its security status remains
**audited, with a local pairing lemma; full-family soundness unproved**. It has
not been promoted into the frozen ranked judge.

## Decision on the two estimates

| Tier | Original model | Projection from measured rates | Change | Slowest repeats with 5% rate allowance |
|---|---:|---:|---:|---:|
| D | 4.253431 h | **4.412697 h** | +3.74% | 4.656597 h |
| E | 4.759079 h | **4.498099 h** | −5.48% | 4.739034 h |

The original estimates were broadly supported. D was slightly optimistic; E
was conservative on the measured card. Use the new projections in place of the
old figures. They estimate a mean using measured stage throughput, corrected
DER probabilities, and the existing random-oracle/Poisson retry model. They
are not observed full-spend completion times. The allowance is a planning
margin, not a statistical confidence interval or a deadline guarantee.

Neither candidate meets two GPU-hours or thirty minutes. No new qualifying
construction was identified, and no claim that the global frontier is optimal
is made. Further construction search is closed under the user's instruction.

## Hardware and measurement

One Runpod RTX 4090, CUDA 12.8, driver 595.91.07, 450 W power cap. No GPU unlock,
driver modification, overclock, or tensor rewrite was applied. Three real-DER
runs of at least 20 seconds per stage sampled low, middle and high portions of
the subset space. The stages ran sequentially on the GPU.

| Tier / stage | Median G attempts/s | Observed repeat range |
|---|---:|---:|
| D pin | 8.3138 | 8.2996–8.3260 |
| D round 1 | 9.2656 | 9.2357–9.2744 |
| D round 2 | 9.3952 | 9.3701–9.4262 |
| E pin | 16.2810 | 16.2670–16.2840 |
| E round 1 | 20.7630 | 20.7360–20.8090 |
| E round 2 | 21.2440 | 21.2340–21.2620 |

Timed real-DER work: 362.88 seconds. Reduced-difficulty runs: 62.87 seconds.
The benchmark driver took 445.89 seconds including per-process setup; rental
also included compilation and artifact transfer. The pod was deleted and the
account's pod list was empty when cleanup was checked. Credentials and SSH
keys were not copied into the repository.

The exact renderer hashes the actual production scripts, with seven minimal
dummy pushes removed from each independent round. Midstates stop before the
first possible deletion. D rehashes 71/136 blocks and E 75/143 blocks, plus the
second SHA-256 pass. Interleaved commitments are included. The unchanged
pinning kernel varies an eight-byte transaction output nonce, using each
candidate's full production script. A shot counts one key encoding at one
hash-chain level; all six parity/encoding combinations and every configured
level are charged. No stand-in hash is used in these GPU rates.

Given rates r0/r1/r2, DER probability q and round success probabilities p1/p2:

```
expected GPU seconds = (1/(r0*p1*p2) + 1/(r1*p2) + 1/r2) / q
```

q is 780555/2^65 for D and 390405/2^65 for E. This calculation includes retries
when a finite round has no solution. It assumes complete production search of
the authorized space; the delivered kernel is a measurement/search component,
not a completed retry-and-spend application. Provisioning, compilation and CPU
verification are excluded from the projected grinding cost. One card and short
repeats cannot establish the performance of every card or a multi-hour run.

## Correctness and security evidence

- 412 CPU stream cases match independent legacy `sighash_all`, including first,
  last and random subsets across all four round layouts.
- Twelve 28-bit zero-gate runs produced 3,464 hits. No within-run duplicates.
  Uniform reproducible samples independently re-derived 2,954 hits on the CPU;
  all passed, and all 2,954 altered-sign controls failed. Every encoding and
  chain level was represented. Maximum absolute hit-count Poisson z: 1.982.
- Source/input SHA-256 digests on the GPU host matched the retrieved artifacts.
- The existing 3,658 Core/Lean vectors and D/E freedom audits remain applicable:
  the candidate scripts are byte-identical to the previously audited artifacts.
- No real DER hit was found in the short timing runs, and no full production
  spend was solved. Reduced-difficulty checks establish pipeline correctness,
  not production puzzle completion or a security proof.
- The original corrected D/E tier thresholds remain met by the unchanged
  security model. Classical / quantum / collision bits are D:
  113.556305 / 50.193190 / 82.226848; E:
  117.695523 / 52.555280 / 84.033726. The frozen manifest remains unchanged.

## Assessment of GPU unlock projects

Reviewed on 2026-10-27:

- [Zagitta/gpu-unlock](https://github.com/Zagitta/gpu-unlock), HEAD
  `6081407b312aa3139a2bed62bdda354f4ffddc1d`: unlocks selected floating-point
  tensor instruction issue rates.
- [JustAResearcher/gpu-unlock-ada](https://github.com/JustAResearcher/gpu-unlock-ada),
  HEAD `d28c485418c3d9d034cd4bac19200bc33dd3453b`: reports about 2× FP16/BF16 tensor
  throughput with FP32 accumulation on RTX 4090, while INT8, dp4a and scalar
  FP32 stay near baseline. Its reported application gains are workload-specific.

The compiled `pool2_round` binary contains **zero tensor instructions**. Its
static instruction mix is dominated by integer adds, multiply/adds, bitwise
logic and shifts (`IADD3`, `IMAD`, `LOP3`, `SHF`). See
`gpu_validation/results/instruction_mix.json`, extracted with CUDA
`cuobjdump --dump-sass` across the binary's kernel variants. This is static
code inspection, not a dynamic bottleneck profile.

Inference: these particular tensor unlocks should yield little or no direct
gain for the existing QSB kernels. A future tensor-based arithmetic rewrite
would need its own correctness and performance evidence, and would not
automatically accelerate the SHA bitwise operations. No unlocked A/B test was
performed, so no numerical unlocked speedup is claimed. The projects' tensor
speedups cannot be applied as a multiplier to our GPU-hour estimates.

## Reproduction and submission artifacts

From the repository root:

```
python3 challenge/mechanisms/spacer_selection/gpu_validation.py setup
```

In a scratch directory on an RTX 4090 CUDA host, place the generated `.bin`
files and `pool2_exact.cu`, alongside `round_renderer.cuh`,
`run_gpu_validation.py`, and the repository's unchanged `gpu/GPUMath.h`,
`GPUHash.h`, `field2.cuh`, and `fasthash.cuh`. Compile and measure:

```
nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -o pool2_pin pool2_exact.cu -lcrypto -lgomp
nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -DROUND_MODE -o pool2_round pool2_exact.cu -lcrypto -lgomp
python3 run_gpu_validation.py
```

Retrieve `results/` into `challenge/mechanisms/spacer_selection/gpu_validation/`,
then run locally:

```
python3 challenge/mechanisms/spacer_selection/summarize_gpu_validation.py
```

`gpu_validation/report.json` is the machine-readable timing and correctness
report. Raw per-run measurements, hits, build logs, hardware snapshots and
input/source hashes accompany it. `D_candidate.json` and `E_candidate.json`
retain their original modeled estimates for provenance and link to the new
timing validation. `PROPOSAL.md`, `Proof.lean`, `validation.json`, the byte
vectors and these GPU artifacts comprise the completed local mechanism-track
submission. No external publication or ranked promotion is claimed.
