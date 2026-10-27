"""Ground truth from Bitcoin Core (judge component, frozen).

Every verdict the judge relies on is replayed through libbitcoinconsensus (Core's own interpreter,
`consensus_check/cchk`) and, when built, through the Lean model (`lean/qsbcheck`):

1. the builder's own honest spends and negative vectors (`qsb_pool.vectors_for`, judge seed);
2. *realised audit runs*: attacker-mode runs from the freedom audit (both accepted and rejected ones)
   are turned into real transactions by computing, for every signature the run checked, the key an
   attacker with discrete logs would supply (key recovery over the real sighash of the scriptCode the
   run actually used). Core must agree with the audit interpreter on every one. This is what makes the
   audit's attacker model trustworthy: a Core-accepted run the audit rejected would be a missed
   freedom, and is reported as a judge failure.
"""
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import qsb_pool as q  # noqa: E402
from qsbcore import Z_SINGLE_BUG, enc, push_min, push_num, recover, ser_tx, sighash_all  # noqa: E402

from . import interp  # noqa: E402

CCHK = ROOT / "consensus_check/target/release/cchk"
LEAN = ROOT / "lean/.lake/build/bin/qsbcheck"


def _key_like(template, Q):
    if len(template) == 65 and template[0] in (6, 7):
        return enc(Q, "hybrid")
    if len(template) == 65:
        return enc(Q, "uncomp")
    return enc(Q, "comp")


def realise(script, items, tx):
    """Replace every witness key a checked signature was paired with by the real recovered key."""
    ins, outs, idx, lt = tx
    items = list(items)
    for _ in range(4):                                  # keys can change the path; iterate to a fixpoint
        res = interp.run(script, items)
        changed = False
        for e in res["events"]:
            pairs = []
            if e[0] == "CHECKSIG" and len(e[3][0]) in (33, 65) and e[2][0]:
                pairs = [(e[2], e[3], e[5])]
            elif e[0] == "CMS":
                pairs = [(s, k, e[5]) for s, k in zip(e[2], e[3])]
            for (sig, sp), (key, kp), sc in pairs:
                if kp[0] != "wit" or len(sig) < 9:
                    continue
                ht = sig[-1]
                z = Z_SINGLE_BUG if (ht & 0x1F) == 3 and idx >= len(outs) else sighash_all(ins, outs, idx, sc, ht=ht, locktime=lt)
                lr, ls = sig[3], sig[5 + sig[3]]
                r = int.from_bytes(sig[4:4 + lr], "big")
                s = int.from_bytes(sig[6 + lr:6 + lr + ls], "big")
                try:
                    Q = recover(r, s, z, 0)
                except Exception:
                    continue
                if Q is None:
                    continue
                new = _key_like(key, Q)
                if items[kp[1]] != new:
                    items[kp[1]] = new
                    changed = True
        if not changed:
            break
    return items


def to_line(tag, script, items, tx, expect):
    ins, outs, idx, lt = tx
    ss = b"".join(push_min(w) if w else push_num(0) for w in items)
    ins2 = [(t_, v, (ss if i == idx else b""), s_) for i, (t_, v, _, s_) in enumerate(ins)]
    return f"{tag} {script.hex()} {ser_tx(ins2, outs, lt).hex()} {idx} {1 if expect else 0}"


def run_cchk(lines):
    if not CCHK.exists():
        return None, "consensus_check not built"
    result = subprocess.run([str(CCHK)], input="\n".join(lines) + "\n", capture_output=True, text=True)
    out = result.stdout
    bad = [l for l in out.splitlines() if "unexpected" in l and "<--" in l]
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    count = sum(l.startswith(("PASS", "FAIL")) for l in out.splitlines())
    if result.returncode or count != len(lines) or not tail.startswith("unexpected results: "):
        return None, "Core replay failed or incomplete: " + (out + result.stderr)[-1000:]
    return bad, tail


def run_lean(lines, tmpdir):
    if not LEAN.exists():
        return None, "lean/qsbcheck not built"
    f = Path(tmpdir) / "judge_vectors.txt"
    f.write_text("\n".join(lines) + "\n")
    result = subprocess.run([str(LEAN), str(f)], capture_output=True, text=True)
    out = result.stdout
    bad = [l for l in out.splitlines() if l.startswith(("FAIL", "GAP"))]
    expected = f"{len(lines)} vectors, 0 disagree with Core, 0 outside the model"
    if (result.returncode or expected not in out) and not bad:
        bad = ["Lean replay failed or incomplete: " + (out + result.stderr)[-1000:]]
    return bad, (out.strip().splitlines() or [""])[-1]


def realised_audit_lines(tag, tb, audit_samples, rng, n_acc=40, n_rej=40):
    """audit_samples: list of (items, ok_in_attacker_mode)."""
    tx = q.make_tx()
    acc = [s for s in audit_samples if s[1]]
    rej = [s for s in audit_samples if not s[1]]
    # half of the rejected runs are the ones that got furthest (a wrongly rejected valid run fails
    # late), half are random
    deep = sorted(rej, key=lambda s: -s[2])[:n_rej // 2]
    rest = [s for s in rej if s not in deep]
    pick = rng.sample(acc, min(n_acc, len(acc))) + deep + rng.sample(rest, min(n_rej - len(deep), len(rest)))
    lines = []
    for i, (items, ok, _prog) in enumerate(pick):
        real = realise(tb["script"], items, tx)
        # the expected verdict is the audit interpreter's verdict on the realised witness itself
        # (realising can repair a run that only failed because of a deliberately bad key)
        exp = interp.run(tb["script"], real)["ok"]
        lines.append(to_line(f"{tag}_audit{'ACC' if exp else 'REJ'}{i}", tb["script"], real, tx, exp))
    return lines
