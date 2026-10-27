"""Honest cost from frozen measurements (judge component, frozen).

GPU time: every stage costs 2^P attempts at the rate the reference kernel (gpu/pool2.cu) *measured*
on an RTX 4090 for that stage shape (hash, pool bound k, chain length m, encodings e). The table is
frozen in rates.json (built by tools/build_rates.py from gpu/results7). Lookup is conservative: the
rate of an off-grid shape is the minimum over the corners of its enclosing grid cell (the rate is
nearly but not strictly monotone), times a 0.95 noise margin. Shapes outside the grid are rejected. Round stages also pay for rehashing more script than
the measured round problem did (conservatively: the whole region to the end of the script), charged
at the measured SHA-256 compression time per extra 64-byte block, amortised over the candidates per
sighash. The honest spender's retries (a round with no solution) come from the analyser's E_i.

Bytes: production script + the honest scriptSig (production witness, 65-byte keys wherever the round
accepts them) + 60 vB of fixed transaction overhead. Legacy bytes are non-witness data: 1 vB each.
"""
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent


class Unmeasured(Exception):
    pass


def load_table():
    return json.loads((HERE / "rates.json").read_text())


def measured_profile(cfg, built):
    """Exact measured design shapes only. Random script constants do not alter work size.

    No submission supplies rates. These organizer-frozen records are pinned in
    the judge manifest and require every semantic/layout parameter to match.
    """
    if not (cfg.get("spacer_selection") or cfg.get("destructive_chain")):
        return None
    key = {name: cfg.get(name, False) for name in
           ("hash", "n", "k", "pool_deep", "force_comp", "chain_pin", "sign_j", "sign_lvl",
            "spacer_selection", "destructive_chain")}
    key["rounds"] = [dict(t=cfg[f"t{i}"], b=cfg.get(f"b{i}", 0), k=cfg[f"k{i}"],
                          chain=cfg[f"chain{i}"]) for i in range(1, len(built["ts"])+1)]
    profiles = json.loads((HERE / "exact_rates.json").read_text())
    for profile in profiles["profiles"]:
        if key == profile["shape"]:
            if len(built["script"]) != profile["production_bytes"] or built["ops"] != profile["ops"]:
                raise Unmeasured("measured layout's bytes/op count changed; remeasurement required")
            return profile
    raise Unmeasured("no exact-layout RTX 4090 measurements for this construction and parameter shape")


def hours_at_rates(rates, analysed, P):
    p = [1 - math.exp(-x) for x in analysed["E"]]
    total, reach = 2 ** P / rates[0], 1.0
    for i, success in enumerate(p):
        total += reach * success * 2 ** P / rates[i+1]
        reach *= success
    return total / math.prod(p) / 3600


def lookup(tbl, stage, hsh, k, m, e):
    """Conservative rate for shape (k, m): the measured rate at a grid point, otherwise the minimum over
    the corners of the grid cell that encloses (k, m), times the noise margin. (The rate is not strictly
    monotone: measured dips between neighbours are <= 6%, which the corner minimum and margin absorb.)
    Shapes outside the measured grid are rejected."""
    pts = {(r["k"], r["m"]): r["rate"] for r in tbl["rates"] if r["stage"] == stage and r["hash"] == hsh and r["e"] == e}
    if not pts:
        raise Unmeasured(f"no measured {stage} shapes for hash={hsh}, e={e}")
    K = sorted({a for a, _ in pts})
    M = sorted({b for _, b in pts})
    if not (K[0] <= k <= K[-1] and M[0] <= m <= M[-1]):
        raise Unmeasured(f"{stage} shape (hash={hsh}, k={k}, m={m}, e={e}) is outside the measured grid "
                         f"k in [{K[0]}, {K[-1]}], m in [{M[0]}, {M[-1]}]")
    klo, khi = max(a for a in K if a <= k), min(a for a in K if a >= k)
    mlo, mhi = max(b for b in M if b <= m), min(b for b in M if b >= m)
    corners = [pts.get((a, b)) for a in {klo, khi} for b in {mlo, mhi}]
    if any(c is None for c in corners):
        raise Unmeasured(f"grid cell around {stage} (k={k}, m={m}) is not fully measured")
    return min(corners) * tbl["noise_margin"]


def round_stream_bytes(built, r):
    """Bytes rehashed per candidate sighash in round r: from round r's first dummy push to the end of
    the script (the honest search may use any dummy of the region), minus the t deleted pushes."""
    from qsbcore import push_min
    script = built["script"]
    first = min(script.index(push_min(d)) for d in built["dummies"][r])
    return len(script) - first - 10 * built["ts"][r]


def gpu_hours(cfg, built, analysed, P, tbl):
    profile = measured_profile(cfg, built)
    if profile is not None:
        stage_rates = [min(s["der_rates"]) * profile["noise_margin"] for s in profile["stages"]]
        return hours_at_rates(stage_rates, analysed, P), stage_rates
    hsh = cfg["hash"]
    R = len(built["ts"])
    pins = [lookup(tbl, "pin", hsh, cfg["k"], cfg["chain_pin"], e) for e in (1, 3)
            if _has(tbl, "pin", hsh, cfg["k"], cfg["chain_pin"], e)]
    if not pins:
        raise Unmeasured(f"pinning shape (hash={hsh}, k={cfg['k']}, m={cfg['chain_pin']}) is outside the measured grid")
    rate_pin = max(pins)
    H = tbl["sha256_block_ns"]
    stage_rates = [rate_pin]
    for i in range(1, R + 1):
        k_, m_ = cfg[f"k{i}"], cfg[f"chain{i}"]
        opts = []
        for e in ((1,) if cfg.get("force_comp") else (1, 3)):
            if not _has(tbl, "rnd", hsh, k_, m_, e):
                continue
            ns = 1e9 / lookup(tbl, "rnd", hsh, k_, m_, e)
            extra_blocks = max(0, math.ceil((round_stream_bytes(built, i - 1) + tbl["round_tx_tail"] + 9) / 64)
                               - tbl["measured_round_blocks"])
            ns += extra_blocks * H / (2 * k_ * m_ * e)
            opts.append(1e9 / ns)
        if not opts:
            raise Unmeasured(f"round shape (hash={hsh}, k={k_}, m={m_}) is outside the measured grid")
        stage_rates.append(max(opts))
    return hours_at_rates(stage_rates, analysed, P), stage_rates


def _has(tbl, stage, hsh, k, m, e):
    try:
        lookup(tbl, stage, hsh, k, m, e)
        return True
    except Unmeasured:
        return False
