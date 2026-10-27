#!/bin/bash
# Hash-chain OR sweep on the REAL TS2 problem shapes (real/pin.bin, real/round.bin); zeros-gate runs verified.
cd "$(dirname "$0")"
R=runs5; mkdir -p $R; : > $R/sweep.jsonl
pin() { POOL_CHAIN=$2 ./pool2 ../real/pin.bin $1 sha zeros ${N:-28} ${SEC:-12} 0 $R/pin_k$1_m$2.hits 1 0 > $R/pin_k$1_m$2.json 2>/dev/null; cat $R/pin_k$1_m$2.json >> $R/sweep.jsonl; }
rnd() { POOL_CHAIN=$2 ./pool2_round ../real/round.bin $1 sha zeros ${N:-28} ${SEC:-12} 0 $R/rnd_k$1_m$2.hits 1 0 > $R/rnd_k$1_m$2.json 2>/dev/null; cat $R/rnd_k$1_m$2.json >> $R/sweep.jsonl; }
for m in 1 2 4 8 12 16; do pin 300 $m; pin 400 $m; done
for k in 4 16 32 64; do for m in 1 4 8 12 16; do rnd $k $m; done; done
echo DONE >> $R/sweep.jsonl
