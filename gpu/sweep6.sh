#!/bin/bash
# Round 6 extra shapes: SHA-1 pinning with all encodings, and 3-stage round shapes (SHA-1).
cd "$(dirname "$0")"
R=runs8; mkdir -p $R
run() { POOL_CHAIN=$7 $2 $3 $4 $5 zeros 30 ${SEC:-12} 0 /dev/null $6 0 2>/dev/null | sed "s/^{/{\"tag\":\"$1\",/" >> $R/rates.jsonl; }
for K in 32 96; do for M in 1 2 3; do run pin_sha1_k${K}_m${M}_e3 ./pool2 ../real/pin.bin $K sha1 3 $M; done; done
for K in 16 32 48 64 96; do for M in 1 2 3; do run rnd_sha1_k${K}_m${M}_e3 ./pool2_round ../real/round.bin $K sha1 3 $M; done; done
for K in 16 32 48 64 96; do for M in 2 3 4; do run rnd_sha1_k${K}_m${M}_e1 ./pool2_round ../real/round.bin $K sha1 1 $M; done; done
for K in 32 96 300; do for M in 2 3 4 8; do run pin_sha1_k${K}_m${M}_e1 ./pool2 ../real/pin.bin $K sha1 1 $M; done; done
echo DONE6 > $R/DONE6
