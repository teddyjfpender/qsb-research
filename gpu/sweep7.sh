#!/bin/bash
# Frozen cost table for the autoresearch judge: pool2 attempts/s over the full stage-shape grid (RTX 4090).
cd "$(dirname "$0")"
R=runs9; mkdir -p $R; : > $R/rates.jsonl
run() { POOL_CHAIN=$7 $2 $3 $4 $5 zeros 30 ${SEC:-6} 0 /dev/null $6 0 2>/dev/null | sed "s/^{/{\"tag\":\"$1\",/" >> $R/rates.jsonl; }
for H in sha rmd sha1; do
  for E in 1 3; do for M in 1 2 4 8 16; do
    for K in 8 16 32 64 96 128 300; do run pin_${H}_k${K}_m${M}_e${E} ./pool2 ../real/pin.bin $K $H $E $M; done
    for K in 8 16 32 64 96; do run rnd_${H}_k${K}_m${M}_e${E} ./pool2_round ../real/round.bin $K $H $E $M; done
  done; done
done
echo DONE > $R/DONE
