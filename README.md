# QSB research: cheaper quantum-safe Bitcoin spends

Start with **[QSB_IMPROVEMENTS.md](QSB_IMPROVEMENTS.md)**. It covers:
- the nonce-signature pool and the DER-only puzzle check, which keep security equal or higher;
- measured results against Layr's tuned kernels (101 RTX 4090-hours today):
  - 3-stage at 114 bits: **6.6 h** on an RTX 4090 and **4.3 h** on an RTX 5090;
  - 2-stage TS2 at 84 bits: **4.1 h** on an RTX 4090 and **2.9 h (34x)** on an RTX 5090;
  - 2-stage **TS4** (hash chains plus signed pool index/level) at **89.7 bits**: **1.76 h** on an
    RTX 4090 and **1.21 h** on an RTX 5090 (58x / 84x vs today);
- **Round 7 (QSB_IMPROVEMENTS §15):** fee-lean tier L, a 3.0 kB script (vs 9.2 kB) at 89.7 bits for 2.3 GPU-hours,
  is 2.0–2.5x cheaper in total cost once on-chain fees are counted;
- **Round 6 (QSB_IMPROVEMENTS §14):** an `OP_SHA1` TS4 (tier A1) gives 91.6 bits at 1.62 h on an RTX 4090 and
  1.14 h on an RTX 5090 (both measured), plus a proof sketch that no DER-based stage can cost less than 2^P hash compressions;
- **[challenge/CHALLENGE.md](challenge/CHALLENGE.md)**: an autoresearch challenge with a fixed, cheat-resistant judge.
  Submissions are data only. The judge builds the script, computes security, audits the attacker's real choices, checks
  every verdict against Bitcoin Core and Lean, and costs the spend from 360 measured GPU shapes. Red-team: 35/35. Its automatic optimizer found designs 8.6% (90-bit) and
  2.9% (116-bit) cheaper than the hand-built ones; LLM agents work on new mechanisms (challenge/AGENT.md, MECHANISMS.md);
- **[FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md)**: Lean 4 regression gate (`lean/check.sh`) with proven
  gadget and limit theorems, a byte-exact Lean port of the builder, and a replay of 658 test vectors that agrees with Core;
- **[SECURITY_MENU.md](SECURITY_MENU.md)**: five exact, consensus-tested designs covering every
  target up to **116 bits**: 89.7 / 91.6 / 108 / 111.8 / 116 bits at 1.76 / 1.91 / 3.94 / 4.81 / 5.22
  RTX 4090-hours. Tier E matches Config A's security at 19x less compute;
- why under one 4090-hour is below the hash floor for any DER-based design (§10);
- corrections to the paper's accounting, exact configurations, validation results and next steps;
- **a real spend**: the production TS2 script with GPU-found strict-DER SHA-256 hits, verified VALID
  by Bitcoin Core ([gpu/README.md](gpu/README.md), "Real spend"; artifacts in `real/`);
- **[SECURITY_PROOF.md](SECURITY_PROOF.md)**: ROM/QROM security theorems and proofs;
- **`design_search.py`** / `design_search.txt` / `design_frontier.md`: the design optimizer and its
  measured-cost frontier.

Quick check (all vectors run through Bitcoin Core's libbitcoinconsensus):

    (cd consensus_check && cargo build --release)
    python3 gen_vectors.py        | consensus_check/target/release/cchk   # 114 mechanism vectors
    python3 qsb_pool.py --vectors | consensus_check/target/release/cchk   # 131 end-to-end vectors
    python3 qsb_pool.py --report                                          # configuration table

See §12 of the write-up for the benchmark build and a file index, and [gpu/README.md](gpu/README.md) for the GPU results.
