"""Submission schema: a QSB design in the judge's declarative DSL (judge component, frozen).

A submission is data, never code. Unknown keys, wrong types and out-of-range values are rejected;
the judge never reads any claimed metric from a submission.
"""
import json

SCHEMA = "qsb-design-v3"
HASHES = ("sha256", "rmd", "sha1")
TOP = {"schema", "hash", "n", "k", "pool_deep", "force_comp", "chain_pin", "sign_j", "sign_lvl",
       "rounds"}
ROUND = {"t", "b", "k", "chain"}
EXTENSIONS = {"selection_layout", "destructive_chain"}


class Invalid(Exception):
    pass


def _int(d, key, lo, hi):
    v = d.get(key)
    if type(v) is not int or not lo <= v <= hi:
        raise Invalid(f"{key} must be an integer in [{lo}, {hi}], got {v!r}")
    return v


def _bool(d, key):
    v = d.get(key)
    if type(v) is not bool:
        raise Invalid(f"{key} must be true/false, got {v!r}")
    return v


def load(path):
    raw = open(path, "rb").read()
    if len(raw) > 4096:
        raise Invalid("design.json larger than 4 KiB")
    try:
        d = json.loads(raw)
    except ValueError as e:
        raise Invalid(f"not JSON: {e}")
    if not isinstance(d, dict):
        raise Invalid("top level must be an object")
    schema = d.get("schema")
    if schema not in ("qsb-design-v2", SCHEMA):
        raise Invalid(f"schema must be 'qsb-design-v2' or {SCHEMA!r}")
    fields = TOP | (EXTENSIONS if schema == SCHEMA else set())
    extra = set(d) - fields
    if extra:
        raise Invalid(f"unknown keys {sorted(extra)} (claims and metrics are not accepted)")
    missing = fields - set(d)
    if missing:
        raise Invalid(f"missing keys {sorted(missing)}")
    if d["hash"] not in HASHES:
        raise Invalid(f"hash must be one of {HASHES}")
    n, k = _int(d, "n", 4, 300), _int(d, "k", 1, 300)
    pool_deep, force_comp = _bool(d, "pool_deep"), _bool(d, "force_comp")
    sign_j, sign_lvl = _bool(d, "sign_j"), _bool(d, "sign_lvl")
    chain_pin = _int(d, "chain_pin", 1, 16)
    spacer, destructive = False, False
    if schema == SCHEMA:
        if d["selection_layout"] not in ("split", "spacer"):
            raise Invalid("selection_layout must be 'split' or 'spacer'")
        spacer = d["selection_layout"] == "spacer"
        destructive = _bool(d, "destructive_chain")
        if spacer and (not pool_deep or sign_j or sign_lvl):
            raise Invalid("promoted spacer family requires pool-first layout and unsigned indices/levels")
    if (sign_j or sign_lvl) and not pool_deep:
        raise Invalid("sign_j / sign_lvl are implemented for the pool-first layout only")
    rounds = d["rounds"]
    if not isinstance(rounds, list) or not 1 <= len(rounds) <= 2:
        raise Invalid("rounds must be a list of 1 or 2 round objects")
    cfg = dict(hash=d["hash"], n=n, k=k, pool_deep=pool_deep, force_comp=force_comp, chain_pin=chain_pin,
               sign_j=sign_j, sign_lvl=sign_lvl)
    if schema == SCHEMA:
        cfg.update(spacer_selection=spacer, destructive_chain=destructive)
    for i, r in enumerate(rounds, 1):
        if not isinstance(r, dict) or set(r) != ROUND:
            raise Invalid(f"round {i} must have exactly the keys {sorted(ROUND)}")
        t, b = _int(r, "t", 1, 40), _int(r, "b", 0, 2)
        if spacer and b:
            raise Invalid("spacer selection does not support bonus selections")
        if t + b > n // 2:
            raise Invalid(f"round {i}: t + b must be at most n/2 (layout condition of the soundness proof)")
        cfg[f"t{i}"], cfg[f"b{i}"] = t, b
        cfg[f"k{i}"] = _int(r, "k", 1, min(k, 96))          # 96 = largest measured round pool bound
        cfg[f"chain{i}"] = _int(r, "chain", 1, 16)
    cfg["chain_r"] = cfg["chain1"]
    if sign_lvl and all(cfg[f"chain{i}"] == 1 for i in range(1, len(rounds) + 1)):
        raise Invalid("sign_lvl without any round chain has nothing to sign")
    return d, cfg
