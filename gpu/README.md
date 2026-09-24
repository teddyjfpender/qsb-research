# GPU validation of the nonce-signature pool (RTX 4090, 2026-09-24)

## Round 3: bigger pools, the 2-stage TS2 design, and Blackwell (RTX 4090 + RTX 5090)

**Changes:**
- **Pool size.** `pool2.cu` now supports pools up to 512 signatures; above 127, s takes two bytes
  and signatures are 10 bytes.
- **Ablation builds.** `-DABL_NOHASH` and `-DABL_NOEC` separate EC, hash and overhead costs.
- **Script side** (`../qsb_pool.py`):
  - `force_comp`: `OP_SIZE 33 OP_EQUALVERIFY` in rounds, so only compressed keys are accepted;
  - `pool_deep`: the pool is pushed first, so round sighashes never rehash pool bytes; safety relies
    on `design_check()`;
  - the 2-stage **TS2** config: n150, t16, pinning pool 300, round bound 32–64.

  Consensus: 81 end-to-end vectors, including 22 for TS2 (uncompressed round key rejected, j
  reaching a commitment or a SINGLE-bug dummy rejected), plus 114 mechanism vectors. 0 unexpected.

**Where the time goes** (k=512, ns per shot, whole GPU):

| | total | EC only (no-hash build) | hash only (no-EC build) | EC | SHA-256 | overhead |
|---|---|---|---|---|---|---|
| RTX 4090 | 0.143 | 0.080 | 0.095 | ≈0.048 | ≈0.063 | ≈0.032 |
| RTX 5090 | 0.102 | 0.060 | 0.067 | ≈0.035 | ≈0.042 | ≈0.025 |

EC work is at its ~4.5 multiplies-per-point floor and SHA-256 is at the microbenchmark rate. Only
the ~22% overhead remains, so the kernel is within ~1.3x of its floor on either card.

**RTX 5090 vs 4090:** field multiply 1.41x, SHA-256 1.49x, RIPEMD-160 1.56x; pool kernel
1.40–1.53x. Layr's promoted **pinning** kernel fails its own G-table self-check on sm_120 and
produces no candidates (`results3/rtx5090/layr_pinning_5090_direct.txt`). Their subset kernel scores
950.1M cand/s. The 5090 "today" figure therefore scales their 4090 pinning score by the measured
subset ratio (1.39x): ≈73 h.

**Full spend** ("×" is against today's 101 h on an RTX 4090):

| design | 2nd-pre bits | honest shots | RTX 4090 | RTX 5090 |
|---|---|---|---|---|
| Paper Config A on Layr's tuned kernels | 116.3 | 2^48.89 | 101.3 h | ≈72.7 h (est.) |
| 3-stage RIPEMD n140 k24 enc3 | 117.2 | 2^47.90 | 9.2 h (11x) | 6.2 h (16x) |
| 3-stage SHA-256 n140 k24 enc3 | 114.4 | 2^46.95 | 6.6 h (15x) | **4.3 h (23x)** |
| 2-stage TS2 SHA-256, kpin300, round k32 compressed | 84.7 | 2^46.37 | 4.7 h (22x) | 3.3 h (31x) |
| 2-stage TS2 SHA-256, kpin300, round k64 compressed | 83.7 | 2^46.37 | 4.1 h (25x) | **2.9 h (34x)** |

Raw matrices: `results3/rtx4090/matrix.txt`, `results3/rtx5090/matrix.txt`.


## Update: `pool2.cu`, the tuned kernel (second RTX 4090 session)

These are the current numbers; the `pool.cu` prototype results follow further down. The Layr baseline
was re-measured on the same host through Layr's harness: pinning 794.3M cand/s (1.59G shots/s),
subset 681.7M cand/s (1.36G shots/s).

**What changed from pool.cu:**
1. **All three key encodings are hashed per point.** Compressed takes 1 block; uncompressed and
   hybrid take 2 blocks each. The security model already counts them for the attacker, so for the
   honest spender they are extra shots with no EC work.
2. **Carry-safe field arithmetic** (`field2.cuh`: 64-bit limbs, `unsigned __int128`). This fixes the
   k=64 miscompile; the pool.cu k=64 RIPEMD build is now exact.
3. **Jacobian mixed additions in the setup**, plus nested loops instead of per-element division.
4. **Inlined, register-resident SHA-256 / RIPEMD-160** (`fasthash.cuh`).

**Correctness:**
- Exact CPU dumps match for every k, both hashes and both sighash shapes; that covers 3,500+
  compared values.
- 20 hit-verified runs: 0 failures, Poisson |z| ≤ 1.9. Hits split evenly across the three
  encodings (`results2/`).

**Primitive costs** (`microbench.cu`, whole-GPU ns per operation):

| primitive | ns/op |
|---|---|
| field multiply | 0.0115 |
| field square | 0.0096 |
| SHA-256 compression | 0.060 |
| RIPEMD-160 compression | 0.032 |
| `_ModInv` | 0.81 |

**Throughput, pinning shape** (shots/s):

| k | SHA-256 enc1 | SHA-256 enc3 | RIPEMD enc3 |
|---|---|---|---|
| 12 | 3.65G | 5.27G | 6.85G |
| 24 | 4.74G | 6.03G | **8.67G** |
| 64 | 5.88G | | **9.73G** |
| 127 | 6.40G | | |

Round shape (27 compressions/z): SHA-256 enc3 4.49G (k=12) / 5.59G (k=24); RIPEMD enc3
5.44G (k=12) / 7.59G (k=24). The real strict-DER gate runs at the same speed as the zero-bit gate.

**Full spend on one RTX 4090** (honest shots from `qsb_pool.py --report`; stage rates as measured):

| design | 2nd-preimage bits | honest shots | pin / round rate | RTX 4090-hours | vs today | source |
|---|---|---|---|---|---|---|
| Paper Config A (recounted) on Layr's tuned kernels | 116.3 | 2^48.89 | 1.59G / 1.36G | **101.3** | **1.0x** | measured (Layr harness) |
| 3-stage, RIPEMD (paper hash), n148 k12 | 119.3 | 2^47.91 | 6.85G / 5.44G | **12.6** | **8.1x** | measured, enc3 |
| 3-stage, RIPEMD, n140 k24 | 117.2 | 2^47.90 | 8.67G / 7.59G | **9.2** | **11.0x** | measured, enc3 |
| 3-stage, SHA-256 puzzle, n148 k12 | 116.4 | 2^46.95 | 5.27G / 4.49G | **8.0** | **12.7x** | measured, enc3 |
| 3-stage, SHA-256 puzzle, n140 k24 | 114.4 | 2^46.95 | 6.03G / 5.59G | **6.6** | **15.4x** | measured, enc3 |
| 2-stage, SHA-256, n250, pinning k127 / round k24 | 83.6 | 2^46.37 | 6.40G / 5.59G | **≈4.2** | **≈24x** | round rate from the 27-block shape; n=250 rehashes more, so optimistic |

**Where the time goes now.** At k=24 with three encodings, about 75% of the time is SHA-256
compressions. On a 4090 a full-block SHA-256 runs at about 17G/s (hashcat's 22G/s relies on
password-specific zero words). The 3-stage SHA-256 design needs 1.34×10^14 shots, so hashing alone
sets a floor of about **2–2.5 h**, and 2 stages about 1.5 h. **Under one RTX 4090-hour isn't
reachable with any DER-based design.** It needs about 3–5x more hash throughput per GPU-hour, or
parallel GPUs for wall-clock time: 8 GPUs finish the 6.6 GPU-hour design in about 50 minutes, for
about $5.

Reproduce:
```
nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -o pool2 pool2.cu -lcrypto -lgomp   # ~25 s
POOL_DUMP=1 ./pool2 <pinning.bin> 24 sha zeros 22 1 0 /dev/null 3 > d.txt
python3 dump_compare2.py <pinning.json> d.txt sha 0
./sweep2.sh          # matrix + hit verification
./microbench         # primitive costs
```

---

# First session: `pool.cu` prototype


`pool.cu` is a CUDA prototype of the pool loop from `../QSB_IMPROVEMENTS.md` §2. It grinds Layr's exact
pinning problem (`layr/problems/pinning.bin`, seed 0), so its numbers compare directly with Layr's
kernels on the same card.

For each candidate (seq, lt), the kernel:
1. computes z = SHA256d(preimage);
2. computes B = z·G with the 16-bit-window G-table, reused from Avihu's/VanitySearch's code;
3. forms the 2k keys Q = ±j·A − B with one Montgomery-batched inversion per thread;
4. hashes each compressed key once and applies the gate.

k=1 is the control: today's per-candidate structure (one scalar mult, 2 shots), built from the same
code. Every configuration used here was checked two ways:
- **Hit re-derivation:** `verify_pool_hits.py` rebuilds each hit on the CPU (preimage → z →
  `recover(r=1, s=j)` → hash → gate). It checks hit counts against Poisson expectation and runs a
  negative control that perturbs j and the sign.
- **Exact dump (`POOL_DUMP=1` + `dump_compare.py`):** x, parity and the first hash word for every
  (j, sign) of one candidate, compared with the CPU.

## Results (one RTX 4090, CUDA 12.4, driver 570, RunPod secure cloud)

Baseline: Layr's promoted kernels, scored by Layr's own harness in `fixed_time` mode, 90 s at N=24:
- pinning: **800.3M candidates/s = 1.601G shots/s** (8,614 verified hits);
- subset: **678.4M candidates/s = 1.357G shots/s** (7,305 verified hits).

Pool kernel, 30 s per point, SHA-256 gate at N=26 (same hash as the Layr benchmark). The last two
columns compare against Layr's tuned kernels:

| k | pinning shape | round shape (27 compressions/z) | vs k=1 (same code) | vs Layr tuned |
|---|---|---|---|---|
| 1 (control) | 0.587G | 0.391G | 1.0x / 1.0x | 0.37x / 0.29x |
| 4 | 1.617G | | 2.8x | 1.01x |
| 8 | 2.484G | | 4.2x | 1.55x |
| **12** | **3.266G** | **2.640G** | **5.6x / 6.8x** | **2.0x / 1.9x** |
| 16 | 3.648G | | 6.2x | 2.3x |
| **24** | **4.186G** | **3.736G** | **7.1x / 9.6x** | **2.6x / 2.8x** |
| 32 | 4.401G | | 7.5x | 2.7x |
| 64 | 5.203G | 4.937G | 8.9x / 12.6x | 3.3x / 3.6x |
| 127 | 5.331G | | 9.1x | 3.3x |

**RIPEMD-160 with the real strict-DER predicate** (the actual QSB puzzle; throughput only, since hits
are 2^-46):

| k | pinning shape | round shape |
|---|---|---|
| 1 | 0.586G | |
| 12 | 3.549G | 2.795G |
| 24 | 4.567G | 4.070G |

The DER check costs nothing measurable, and RIPEMD runs slightly faster than SHA-256.

**Correctness:**
- 17 hit-verified runs: 0 failed hits and 0 duplicates, Poisson |z| ≤ 2.2, 0 control false passes
  (`results/verify.jsonl`).
- Exact dumps for 18 kernel builds: all 1,152 points match the CPU, except k=64 RIPEMD
  (`results/dump_all.txt`).

**Known defect: k=64 + RIPEMD.** That one template instantiation computes wrong points (x is already
wrong, before hashing). It's deterministic, independent of loop unrolling, and absent in k=64 SHA and
k=127 RIPEMD. The likely cause is VanitySearch `GPUMath.h` chaining carries across separate
`asm volatile` statements (`add.cc` … `addc`), which the compiler is free to break. Avihu's v16
README describes a similar carry-propagation fix. Those numbers are excluded. A production kernel
should use single-asm-block carry chains, as the Layr kernels do.

## What it means for a full spend

Honest shots come from `../qsb_pool.py --report`; stage rates are the measured numbers above.

| | shots | pinning / round rate | RTX 4090-hours |
|---|---|---|---|
| Paper Config A (recounted) on Layr's tuned kernels | 2^48.89 | 1.60G / 1.36G | **101** |
| n148, 7+1b/8, k=12, RIPEMD + DER-only check, untuned pool kernel | 2^47.91 | 3.55G / 2.79G | **24 (4.2x)** |
| n140, 7+1b/8, k=24, same | 2^47.90 | 4.57G / 4.07G | **17 (5.9x)** |

**How this compares with the earlier estimate.** The ≈10–18x estimate assumed equal kernel quality.
At equal quality it holds: 5.6–9.6x from the pool × 2x fewer shots ≈ 11–19x. The measured 4–6x end to
end is against a kernel with months of tuning that this prototype doesn't have: Layr's kernel is 2.7x
faster than the k=1 control built from the same code as the pool. How much of that tuning carries
over to the pool loop is open (the loop is partly hash-bound). That is the next engineering step, not
a demonstrated result.

## Reproduce

Cost: about $0.82 of RTX 4090 time.

```bash
# on a CUDA 12.x box with libssl-dev; layr/ and research/ side by side
cd layr && python3 harness/gen_problem.py --seed 0 && cd ../research/gpu
nvcc -O3 -arch=sm_89 -Xcompiler -fopenmp -o pool pool.cu -lcrypto -lgomp   # ~3 min; or -DONLY_K=12
./pool ../../layr/problems/pinning.bin 12 sha zeros 26 30 0 runs/k12.hits > runs/k12.json
python3 verify_pool_hits.py ../../layr/problems/pinning.json runs/k12.hits --summary runs/k12.json
POOL_DUMP=1 ./pool ../../layr/problems/pinning.bin 12 rmd zeros 22 1 0 /dev/null > d.txt
python3 dump_compare.py ../../layr/problems/pinning.json d.txt rmd
./sweep.sh            # full matrix;  ./layr_baseline.sh  # Layr kernels via Layr's harness
```

`pool.cu` uses VanitySearch's GPLv3 `GPUMath.h`/`GPUHash.h` (see `COPYING`), so it is GPLv3 as a
derived work. The Python files are standalone.
