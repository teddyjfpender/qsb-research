| design (2-stage, SHA-256 puzzle, pool-first, compressed rounds) | ops | bytes | E (round) | 2nd-pre bits | collision bits | quantum-query bits | pinning / round rate (4090, measured) | RTX 4090 | vs today (101 h) | RTX 5090 (est. ×0.68) |
|---|---|---|---|---|---|---|---|---|---|---|
| pinning pool 400 chain 16; round bound 32 chain 16; n140 t8 | 184 | 9344 | 6.7e+01 | 80.7 | 63.6 | 31.3 | 14.23G / 13.80G | **1.80 h** | 56x | 1.22 h |
| pinning pool 400 chain 16; round bound 16 chain 16; n140 t8 | 184 | 9344 | 3.4e+01 | 81.7 | 64.1 | 31.8 | 14.23G / 12.74G | **1.88 h** | 54x | 1.28 h |
| pinning pool 400 chain 16; round bound 16 chain 4; n120 t10 | 176 | 8734 | 3.3e+02 | 83.7 | 65.1 | 32.8 | 14.23G / 7.72G | **2.52 h** | 40x | 1.71 h |
| pinning pool 400 chain 16; round bound 4 chain 12; n120 t10 | 196 | 8754 | 2.5e+02 | 84.1 | 65.3 | 33.0 | 14.23G / 6.94G | **2.70 h** | 37x | 1.84 h |
| pinning pool 400 chain 16; round bound 4 chain 8; n120 t10 | 186 | 8744 | 1.6e+02 | 84.7 | 65.6 | 33.3 | 14.23G / 5.77G | **3.07 h** | 33x | 2.09 h |
