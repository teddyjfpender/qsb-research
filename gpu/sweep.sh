#!/bin/bash
# Throughput + correctness sweep for pool.cu on one GPU. Every run's hits are re-derived on CPU.
set -u
cd "$(dirname "$0")"
BIN=../../layr/problems/pinning.bin; JS=../../layr/problems/pinning.json
SEC=${SEC:-30}; N=${N:-26}
mkdir -p runs; : > runs/sweep.jsonl; : > runs/verify.jsonl
run() {  # K hash gate extra
  tag="K$1_$2_$3_x$4"
  ./pool $BIN $1 $2 $3 $N $SEC $4 runs/$tag.hits > runs/$tag.json 2>/dev/null
  cat runs/$tag.json | tee -a runs/sweep.jsonl
}
for K in 1 4 8 12 16 24 32 64 127; do run $K sha zeros 0; done
for K in 1 12 24 64;               do run $K rmd zeros 0; done
for K in 1 12 24 64;               do run $K sha zeros 24; done
for K in 1 12 24;                  do run $K rmd der 0; done
for K in 12 24;                    do run $K rmd der 24; done
for f in runs/K*_zeros_*.json; do
  python3 verify_pool_hits.py $JS ${f%.json}.hits --summary $f --max 800 | tee -a runs/verify.jsonl
done
