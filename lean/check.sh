#!/bin/bash
# Regression gate for QSB: Lean proofs + Lean-vs-Python builds + Lean-vs-Core consensus replay.
# Exit status is non-zero on any failure. Run from anywhere: research/lean/check.sh
set -euo pipefail
cd "$(dirname "$0")"
R=..
CCHK=$R/consensus_check/target/release/cchk

echo "== 1. export Python builds and regenerate the Lean tier data"
python3 export_scripts.py > vectors/scripts.json
python3 gen_tiers.py
python3 - <<'PY'
import json
d = {e["name"]: e for e in json.load(open("vectors/scripts.json"))}
assert d["REAL_TS2"]["script"] == open("../real/script.hex").read().strip(), "REAL_TS2 export != real/script.hex"
print("   REAL_TS2 build == real/script.hex (the spend Core accepted)")
PY

echo "== 2. regenerate consensus vectors from the Python generators"
python3 $R/gen_vectors.py > vectors/mechanism.txt 2>/dev/null
python3 $R/qsb_pool.py --vectors > vectors/end_to_end.txt 2>/dev/null
if [ -x "$CCHK" ]; then
  for f in vectors/mechanism.txt vectors/end_to_end.txt; do
    out=$("$CCHK" < "$f" | tail -1)
    echo "   Core on $f: $out"
    [ "$out" = "unexpected results: 0" ] || { echo "Core disagrees with the generator's expectations"; exit 1; }
  done
  python3 edge_vectors.py
else
  echo "   (consensus_check not built: using the committed Core-labelled vectors as they are)"
fi

echo "== 3. frozen statements, build and check every proof"
shasum -a 256 -c FROZEN.sha256 > /dev/null || { shasum -a 256 -c FROZEN.sha256 | grep -v OK; echo "a frozen statement/definition file changed (update FROZEN.sha256 only deliberately)"; exit 1; }
echo "   frozen statement files unchanged"
lake build 2>&1 | grep -E "error|warning: declaration uses 'sorry'" && { echo "lake build failed"; exit 1; } || true
lake build > /dev/null
AX=$(lake env lean scripts_axioms.lean 2>&1)
if echo "$AX" | grep -q sorryAx; then echo "a proof depends on sorryAx"; exit 1; fi
BADAX=$(echo "$AX" | tr ',[]' '\n\n\n' | sed 's/.*depends on axioms://' | tr -d ' ' | grep -v '^$' | grep -v "^'" \
  | grep -vx -e propext -e Classical.choice -e Quot.sound -e Lean.ofReduceBool -e Lean.trustCompiler || true)
[ -z "$BADAX" ] || { echo "unexpected axioms: $BADAX"; exit 1; }
# the generic soundness theorems must not rely on compiled evaluation
for t in QSB.TS2.ts2_family_sound QSB.Gadget.gadget_spec QSB.Blocks.parse_build_TS2; do
  echo "$AX" | tr '\n' ' ' | grep -o "'$t' depends on axioms: \[[^]]*\]" | grep -q ofReduceBool && { echo "$t uses native_decide"; exit 1; }
done
echo "   proofs OK (axioms: $(lake env lean scripts_axioms.lean 2>&1 | grep -o 'Lean.ofReduceBool' | sort -u | tr '\n' ' ')+ propext/Classical/Quot.sound)"

echo "== 4. Lean builder == Python builder (bytes, op count, max stack)"
lake build qsbcheck > /dev/null
./.lake/build/bin/qsbcheck --scripts vectors/scripts.json | tail -1

echo "== 5. Lean interpreter + Lean crypto vs Bitcoin Core verdicts"
./.lake/build/bin/qsbcheck vectors/edge.txt vectors/mechanism.txt vectors/end_to_end.txt \
  $R/final_menu_vectors.txt $R/security_menu_vectors.txt $R/real/production_vector.txt | grep -E "^(replay|FAIL|GAP)"
echo "ALL CHECKS PASSED"
