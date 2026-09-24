#!/bin/bash
# pool2 matrix: every zeros-gate run is re-derived on CPU; der-gate runs are throughput with the real predicate.
set -u
cd "$(dirname "$0")"
BIN=../../layr/problems/pinning.bin; JS=../../layr/problems/pinning.json
SEC=${SEC:-20}; N=${N:-27}
mkdir -p runs2; : > runs2/sweep.jsonl; : > runs2/verify.jsonl
run() {  # K hash gate extra enc
  tag="K$1_$2_$3_x$4_e$5"
  ./pool2 $BIN $1 $2 $3 $N $SEC $4 runs2/$tag.hits $5 > runs2/$tag.json 2>/dev/null
  cat runs2/$tag.json >> runs2/sweep.jsonl
}
for x in 0 24; do
  for K in 1 12 24 64 127; do run $K sha zeros $x 1; done
  for K in 12 24 64;       do run $K rmd zeros $x 3; done
  for K in 12 24 127;      do run $K sha der $x 1; done
  for K in 12 24;          do run $K rmd der $x 3; done
done
for f in runs2/K*_zeros_*.json; do
  python3 verify_pool_hits.py $JS ${f%.json}.hits --summary $f --max 600 >> runs2/verify.jsonl
done
echo DONE >> runs2/verify.jsonl
