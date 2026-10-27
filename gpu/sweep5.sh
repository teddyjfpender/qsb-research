#!/bin/bash
# Round 6: OP_SHA1 puzzles. TS4 shapes with SHA-1 vs SHA-256 in the same session, plus CPU-verified SHA-1 chain hits.
cd "$(dirname "$0")"
R=runs8; mkdir -p $R; : > $R/rates.jsonl
run() { # tag binary problem K hash enc chain
  POOL_CHAIN=$7 $2 $3 $4 $5 zeros 30 ${SEC:-12} 0 /dev/null $6 0 2>/dev/null | sed "s/^{/{\"tag\":\"$1\",/" >> $R/rates.jsonl
}
run pin_sha_k300_m16  ./pool2 ../real/pin.bin 300 sha 1 16
run pin_sha1_k300_m16 ./pool2 ../real/pin.bin 300 sha1 1 16
run rnd_sha_k64_m16   ./pool2_round ../real/round.bin 64 sha 1 16
run rnd_sha1_k64_m16  ./pool2_round ../real/round.bin 64 sha1 1 16
run pin_sha1_k96_m3   ./pool2 ../real/pin.bin 96 sha1 1 3
run pin_sha1_k96_m1   ./pool2 ../real/pin.bin 96 sha1 1 1
run rnd_sha1_k96_m3_e3 ./pool2_round ../real/round.bin 96 sha1 3 3
run rnd_sha1_k48_m3_e3 ./pool2_round ../real/round.bin 48 sha1 3 3
run rnd_sha1_k96_m2_e3 ./pool2_round ../real/round.bin 96 sha1 3 2
L=../../layr/problems
POOL_CHAIN=8 ./pool2 $L/pinning.bin 24 sha1 zeros 24 10 0 $R/v_sha1.hits 1 > $R/v_sha1.json 2>/dev/null
POOL_CHAIN=3 ./pool2 $L/pinning.bin 24 sha1 zeros 24 10 0 $R/v_sha1e3.hits 3 > $R/v_sha1e3.json 2>/dev/null
python3 verify_pool_hits.py $L/pinning.json $R/v_sha1.hits --summary $R/v_sha1.json --max 300 > $R/v_sha1.verify
python3 verify_pool_hits.py $L/pinning.json $R/v_sha1e3.hits --summary $R/v_sha1e3.json --max 300 > $R/v_sha1e3.verify
echo DONE > $R/DONE
