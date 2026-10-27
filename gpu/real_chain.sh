#!/bin/bash
# Real TS2 spend: grind pinning (strict DER, SHA-256) until a hit, then the round for that exact tx.
cd "$(dirname "$0")"
R=../real/runs; mkdir -p $R
date -u +%FT%TZ > $R/start_time
POOL_STOP_ON_HIT=1 ./pool2 ../real/pin.bin 300 sha der 0 36000 0 $R/pin_real.hits 1 0 > $R/pin_real.json 2> $R/pin_real.log
date -u +%FT%TZ > $R/pin_done_time
set -- $(head -1 $R/pin_real.hits)
( cd .. && python3 real_spend.py round-problem $1 $2 ) > $R/round_problem.txt
POOL_STOP_ON_HIT=1 ./pool2_round ../real/round.bin 64 sha der 0 36000 0 $R/round_real.hits 1 0 > $R/round_real.json 2> $R/round_real.log
date -u +%FT%TZ > $R/round_done_time
echo DONE > $R/DONE
