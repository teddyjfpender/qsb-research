#!/bin/bash
cd "$(dirname "$0")"; : > runs10.jsonl
POOL_CHAIN=8 ./pool2 ../real/pin.bin 16 sha1 zeros 30 30 0 /dev/null 1 0 2>/dev/null | sed 's/^{/{"tag":"pin_k16_m8_e1",/' >> runs10.jsonl
POOL_CHAIN=8 ./pool2 ../real/pin.bin 16 sha1 zeros 30 30 0 /dev/null 3 0 2>/dev/null | sed 's/^{/{"tag":"pin_k16_m8_e3",/' >> runs10.jsonl
POOL_CHAIN=8 ./pool2_round ../real/round.bin 16 sha1 zeros 30 30 0 /dev/null 1 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k16_m8_e1",/' >> runs10.jsonl
POOL_CHAIN=8 ./pool2_round ../real/round.bin 16 sha1 zeros 30 30 0 /dev/null 3 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k16_m8_e3",/' >> runs10.jsonl
POOL_CHAIN=1 ./pool2 ../real/pin.bin 96 sha zeros 30 30 0 /dev/null 1 0 2>/dev/null | sed 's/^{/{"tag":"pin_k96_m1_e1",/' >> runs10.jsonl
POOL_CHAIN=1 ./pool2 ../real/pin.bin 96 sha zeros 30 30 0 /dev/null 3 0 2>/dev/null | sed 's/^{/{"tag":"pin_k96_m1_e3",/' >> runs10.jsonl
POOL_CHAIN=2 ./pool2_round ../real/round.bin 64 sha zeros 30 30 0 /dev/null 1 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k64_m2_e1",/' >> runs10.jsonl
POOL_CHAIN=2 ./pool2_round ../real/round.bin 64 sha zeros 30 30 0 /dev/null 3 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k64_m2_e3",/' >> runs10.jsonl
POOL_CHAIN=2 ./pool2_round ../real/round.bin 96 sha zeros 30 30 0 /dev/null 1 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k96_m2_e1",/' >> runs10.jsonl
POOL_CHAIN=2 ./pool2_round ../real/round.bin 96 sha zeros 30 30 0 /dev/null 3 0 2>/dev/null | sed 's/^{/{"tag":"rnd_k96_m2_e3",/' >> runs10.jsonl
