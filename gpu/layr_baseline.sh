#!/bin/bash
# Layr's promoted kernels, scored by Layr's own harness (every hit re-derived by harness/verify.py).
set -u
cd "$(dirname "$0")/../../layr"
SEC=${SEC:-90}
for bench in pinning subset; do
  python3 harness/run_benchmark.py --bench $bench --mode fixed_time --seconds $SEC --N 24 \
    --grinder "cmd:python3 harness/gpu_wrap.py --src candidates/$bench/$bench.cu" \
    --out /workspace/layr_${bench}_artifact.json --score-out /workspace/layr_${bench}_score.json \
    > /workspace/layr_${bench}.log 2>&1
  echo "== $bench"; tail -5 /workspace/layr_${bench}.log; cat /workspace/layr_${bench}_score.json 2>/dev/null; echo
done
