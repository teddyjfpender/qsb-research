#!/bin/bash
# Rates for the security menu (real TS2 shapes) + correctness of RIPEMD chains and enc3+chains (Layr problem).
cd "$(dirname "$0")"
R=runs7; mkdir -p $R; : > $R/rates.jsonl
run() { # tag binary problem K hash enc chain
  POOL_CHAIN=$7 $2 $3 $4 $5 zeros 30 ${SEC:-12} 0 /dev/null $6 0 2>/dev/null | sed "s/^{/{\"tag\":\"$1\",/" >> $R/rates.jsonl
}
# 2-stage RIPEMD (menu >=90)
run pin_rmd_k300_m16 ./pool2 ../real/pin.bin 300 rmd 1 16
run rnd_rmd_k64_m16  ./pool2_round ../real/round.bin 64 rmd 1 16
# 3-stage menu entries (SHA-256): pinning and round shapes
run pin_sha_k96_m3   ./pool2 ../real/pin.bin 96 sha 1 3
run pin_sha_k96_m1   ./pool2 ../real/pin.bin 96 sha 1 1
run pin_sha_k32_m3   ./pool2 ../real/pin.bin 32 sha 1 3
run rnd_sha_k96_m2_e3 ./pool2_round ../real/round.bin 96 sha 3 2
run rnd_sha_k96_m3_e3 ./pool2_round ../real/round.bin 96 sha 3 3
run rnd_sha_k48_m3_e3 ./pool2_round ../real/round.bin 48 sha 3 3
run rnd_sha_k16_m2_e3 ./pool2_round ../real/round.bin 16 sha 3 2
run rnd_sha_k32_m3_e3 ./pool2_round ../real/round.bin 32 sha 3 3
# correctness: RIPEMD chains and enc3+chains on the Layr problem, verified on CPU
L=../../layr/problems
POOL_CHAIN=8 ./pool2 $L/pinning.bin 24 rmd zeros 24 10 0 $R/v_rmd.hits 1 > $R/v_rmd.json 2>/dev/null
POOL_CHAIN=3 ./pool2 $L/pinning.bin 24 sha zeros 24 10 0 $R/v_e3.hits 3 > $R/v_e3.json 2>/dev/null
python3 verify_pool_hits.py $L/pinning.json $R/v_rmd.hits --summary $R/v_rmd.json --max 300 > $R/v_rmd.verify
python3 verify_pool_hits.py $L/pinning.json $R/v_e3.hits --summary $R/v_e3.json --max 300 > $R/v_e3.verify
echo DONE > $R/DONE
