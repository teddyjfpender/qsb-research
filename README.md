# QSB research: cheaper quantum-safe Bitcoin spends

Start with **[QSB_IMPROVEMENTS.md](QSB_IMPROVEMENTS.md)**. It covers:
- the nonce-signature pool and the DER-only puzzle check, which keep security equal or higher;
- measured results against Layr's tuned kernels (101 RTX 4090-hours today):
  - 3-stage at 114 bits: **6.6 h** on an RTX 4090 and **4.3 h** on an RTX 5090;
  - 2-stage TS2 at 84 bits: **4.1 h** on an RTX 4090 and **2.9 h (34x)** on an RTX 5090;
- why under one 4090-hour is below the hash floor for any DER-based design (§10);
- corrections to the paper's accounting, exact configurations, validation results and next steps.

Quick check (all vectors run through Bitcoin Core's libbitcoinconsensus):

    (cd consensus_check && cargo build --release)
    python3 gen_vectors.py        | consensus_check/target/release/cchk   # 114 mechanism vectors
    python3 qsb_pool.py --vectors | consensus_check/target/release/cchk   # 81 end-to-end vectors
    python3 qsb_pool.py --report                                          # configuration table

See §12 of the write-up for the benchmark build and a file index, and [gpu/README.md](gpu/README.md) for the GPU results.
