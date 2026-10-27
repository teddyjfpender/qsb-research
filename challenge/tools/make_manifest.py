#!/usr/bin/env python3
"""Organizer tool: pin every file the judge trusts (judge/MANIFEST.sha256). Run only when deliberately
releasing a new judge version; ranked runs refuse to score if any pinned file differs."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted({*(p.relative_to(ROOT) for p in (ROOT / "challenge/judge").glob("*.py")),
                *(p.relative_to(ROOT) for p in (ROOT / "challenge/judge").glob("*.json")),
                Path("qsb_pool.py"), Path("qsbcore.py"), Path("ripemd160.py"), Path("trace.py"),
                Path("lean/export_scripts.py"), Path("lean/FROZEN.sha256"), Path("final_menu.py"),
                *(p.relative_to(ROOT) for p in (ROOT / "lean").glob("*.lean")),
                *(p.relative_to(ROOT) for p in (ROOT / "lean/QSB").glob("*.lean")),
                Path("lean/lean-toolchain"), Path("lean/lake-manifest.json"),
                *(p.relative_to(ROOT) for p in (ROOT / "consensus_check/src").glob("*.rs")),
                Path("consensus_check/Cargo.toml"), Path("consensus_check/Cargo.lock")})
lines = [f"{hashlib.sha256((ROOT / f).read_bytes()).hexdigest()}  {f}" for f in FILES if (ROOT / f).exists()]
(ROOT / "challenge/judge/MANIFEST.sha256").write_text("\n".join(lines) + "\n")
print(f"pinned {len(lines)} files")
