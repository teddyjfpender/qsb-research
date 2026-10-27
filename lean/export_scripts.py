#!/usr/bin/env python3
"""Dump qsb_pool.build() outputs for the Lean differential checker (lean/qsbcheck --scripts).

For every design: the resolved build parameters, the build's random material (dummy sigs, HORS
preimages), and the script bytes / op count / max symbolic stack that Python produced. The Lean
port rebuilds each script from the same parameters and randomness and must match byte for byte.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import qsb_pool as q  # noqa: E402
import final_menu  # noqa: E402

HASH_OP = {"sha256": 0xA8, "rmd": 0xA6, "sha1": 0xA7}

DESIGNS = [(f"TIER{tag}", cfg) for tag, _desc, cfg, _e in final_menu.TIERS] + [
    ("TIER-A-SHA1", dict(final_menu.TIERS[0][2], hash="sha1")),
    ("NB", dict(n=140, t1=8, t2=7, k=64, seed=5)),
    ("BK", dict(n=148, t1=7, b1=1, t2=8, k=12, seed=6)),
    ("TS", dict(n=250, t1=16, k=127, k1=8, seed=7)),
    ("TS2", dict(n=150, t1=16, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256", seed=8)),
    ("TS3", dict(n=150, t1=12, k=300, k1=16, force_comp=True, pool_deep=True, hash="sha256",
                 chain_pin=8, chain_r=8, seed=9)),
    ("TS4", dict(n=120, t1=8, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256",
                 chain_pin=16, chain_r=16, sign_j=True, sign_lvl=True, seed=10)),
    ("REAL_TS2", dict(n=150, t1=16, k=300, k1=64, force_comp=True, pool_deep=True, hash="sha256", seed=2026)),
    ("SPACER_D", dict(n=129, k=96, t1=7, t2=7, k1=96, k2=96, chain_pin=2, chain1=4, chain2=5,
                      pool_deep=True, force_comp=False, hash="sha256", spacer_selection=True, destructive_chain=True)),
    ("SPACER_E", dict(n=135, k=64, t1=7, t2=7, k1=64, k2=64, chain_pin=2, chain1=4, chain2=5,
                      pool_deep=True, force_comp=False, hash="sha1", spacer_selection=True, destructive_chain=True)),
]
VARIANTS = [dict(), dict(test_mode=True), dict(test_mode=True, real_round_puzzle=True),
            dict(test_mode=True, pad_ops=3), dict(test_mode=True, pad_bytes=77)]


def params(cfg, b):
    R = len(b["ts"])
    k = cfg["k"]
    return dict(
        n=cfg["n"], k=k, ts=b["ts"], bs=b["bs"],
        kbound=[cfg.get("k_pin", k)] + [cfg.get(f"k{i + 1}", k) for i in range(R)],
        chain_pin=b["chain_pin"], chains=b["chains"], hash_op=HASH_OP[cfg.get("hash", "rmd")],
        pool_deep=bool(cfg.get("pool_deep")), force_comp=bool(cfg.get("force_comp")),
        sign_j=bool(cfg.get("sign_j")), sign_lvl=bool(cfg.get("sign_lvl")),
        spacer_selection=bool(cfg.get("spacer_selection")), destructive_chain=bool(cfg.get("destructive_chain")))


def main():
    out = []
    for name, cfg in DESIGNS:
        for v in VARIANTS:
            b = q.build(cfg, **v)
            out.append(dict(
                name=name + "".join(f"/{k}={val}" for k, val in v.items()),
                params=params(cfg, b),
                test_mode=bool(v.get("test_mode")), real_round_puzzle=bool(v.get("real_round_puzzle")),
                pad_ops=v.get("pad_ops", 0), pad_bytes=v.get("pad_bytes", 0),
                dummies=[[d.hex() for d in ds] for ds in b["dummies"]],
                pre=[[p.hex() for p in ps] for ps in b["pre"]],
                pre_j=[[p.hex() for p in ps] for ps in b["pre_j"]],
                pre_l=[[p.hex() for p in ps] for ps in b["pre_l"]],
                script=b["script"].hex(), ops=b["ops"], max_stack=b["max_stack"],
                plan=[[a, m] for rp in b["plan"]["rounds"] for a, m in zip(rp["A"], rp["m"])]))
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
