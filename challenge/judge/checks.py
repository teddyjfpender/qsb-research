"""Static checks on the judge-built scripts (judge component, frozen).

* limits: Core's legacy limits recomputed from the bytes with the judge's own parser, never from the
  builder's counters: size <= 10,000, every push <= 520 bytes, static op count <= 201 (each opcode
  above OP_16 counts 1; CHECKMULTISIG also counts the key count pushed right before it; a script whose
  CHECKMULTISIG key count is not a literal push is rejected), only modelled opcodes, no truncated push.
* twin: the test-mode script (used for every spendability and audit run) must equal the production
  script except that each puzzle hash opcode H is replaced by `OP_DROP <fixed 20-byte DER>`. So
  everything the judge proves about the test-mode script holds for the deployed bytes, except the
  puzzle predicates themselves (which is exactly the 2^-P work the security model counts).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from qsb_pool import TEST_DER20  # noqa: E402

from .interp import OPS, ops_of  # noqa: E402

HASH_OPS = {0xA6, 0xA7, 0xA8}


def tokens(script):
    out = []
    for pos in ops_of(script):
        op = script[pos]
        if op == 0:
            out.append(("push", b""))
        elif op < 0x4C:
            out.append(("push", script[pos + 1:pos + 1 + op]))
        elif op == 0x4C:
            out.append(("push1", script[pos + 2:pos + 2 + script[pos + 1]]))
        elif op == 0x4D:
            out.append(("push2", script[pos + 3:pos + 3 + int.from_bytes(script[pos + 1:pos + 3], "little")]))
        elif op == 0x4E:
            out.append(("push4", b""))
        elif 0x51 <= op <= 0x60:
            out.append(("num", op - 0x50))
        else:
            out.append(("op", op))
    return out


def limits(script):
    errs = []
    if len(script) > 10000:
        errs.append(f"script is {len(script)} bytes (> 10,000)")
    for p_ in ops_of(script):                    # every push must fit inside the script
        op = script[p_]
        if 1 <= op < 0x4C:
            hdr, n_ = 1, op
        elif op == 0x4C:
            hdr, n_ = 2, script[p_ + 1] if p_ + 1 < len(script) else 10 ** 6
        elif op == 0x4D:
            hdr, n_ = 3, int.from_bytes(script[p_ + 1:p_ + 3], "little") if p_ + 2 < len(script) else 10 ** 6
        else:
            continue
        if p_ + hdr + n_ > len(script):
            errs.append("truncated push")
    toks = tokens(script)
    ops = 0
    for i, (kind, v) in enumerate(toks):
        if kind.startswith("push") and len(v) > 520:
            errs.append("push larger than 520 bytes")
        if kind == "push4":
            errs.append("PUSHDATA4 not allowed")
        if kind == "op":
            if v not in OPS:
                errs.append(f"opcode {v:#x} outside the judge's model")
            ops += 1
            if v in (0xAE, 0xAF):
                prev = toks[i - 1] if i else None
                if prev is None or prev[0] != "num":
                    if prev and prev[0] == "push" and len(prev[1]) == 1 and prev[1][0] <= 20:
                        ops += prev[1][0]
                    else:
                        errs.append("CHECKMULTISIG key count is not a literal")
                else:
                    ops += prev[1]
    if ops > 201:
        errs.append(f"static op count {ops} (> 201)")
    return ops, errs


def twin(prod, test):
    a, b = tokens(prod), tokens(test)
    i = j = subs = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1; j += 1
            continue
        if a[i][0] == "op" and a[i][1] in HASH_OPS and b[j] == ("op", 0x75) and j + 1 < len(b) \
                and b[j + 1] == ("push", TEST_DER20):
            i += 1; j += 2; subs += 1
            continue
        return None, f"production and test-mode scripts differ at token {i}/{j}"
    if i != len(a) or j != len(b):
        return None, "production and test-mode scripts have different lengths"
    return subs, None
