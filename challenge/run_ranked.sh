#!/bin/bash
# Ranked evaluation of one submission. Usage: challenge/run_ranked.sh <submission_dir> [--deep]
#   --deep: promotion-grade verification (3 audit seeds, 10x perturbations, 1000 honest samples,
#           3x realised Core vectors). Only deep-verified runs can lead the board.
# - the judge must match its manifest (no --dev): a modified judge refuses to score
# - only design.json is copied out of the submission, into a fresh directory
# - the seed is drawn here, after the submission is fixed, and recorded with the manifest digest
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUB="$1"; MODE=standard; [ "${2:-}" = "--deep" ] && MODE=deep
[ -f "$SUB/design.json" ] || { echo "no design.json in $SUB"; exit 2; }
TMP="$(mktemp -d)"; trap 'chmod -R u+w "$TMP"; rm -rf "$TMP"' EXIT
cp "$SUB/design.json" "$TMP/design.json"
chmod -R a-w "$TMP"
SEED=$(python3 -c "import secrets; print(secrets.randbelow(2**32))")
DIGEST=$(shasum -a 256 "$HERE/judge/MANIFEST.sha256" | cut -c1-16)
if [ -n "${QSB_JUDGE_DIGEST:-}" ] && [ "$DIGEST" != "$QSB_JUDGE_DIGEST" ]; then
  echo "judge manifest digest $DIGEST != published $QSB_JUDGE_DIGEST: refusing to score"; exit 3
fi
mkdir -p "$HERE/leaderboard/runs"
OUT="$HERE/leaderboard/runs/$(date -u +%Y%m%dT%H%M%SZ)_$(basename "$SUB")_$MODE.json"
cd "$HERE"
set +e
python3 -m judge "$TMP" --seed "$SEED" --mode "$MODE" --out "$OUT.tmp" > /dev/null 2> "$OUT.log"
RC=$?
set -e
python3 - "$OUT.tmp" "$OUT" "$DIGEST" "$(basename "$SUB")" "$(shasum -a 256 "$TMP/design.json" | cut -c1-64)" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r["manifest_digest"] = sys.argv[3]; r["submission"] = sys.argv[4]
r["design_sha256"] = sys.argv[5]
json.dump(r, open(sys.argv[2], "w"), indent=1)
print(f"{r['submission']}: {r['verdict']}" + (f" at {r.get('rejected_at')}" if r['verdict'] != 'accepted' else
      f", score ({r['score']['sats']} sats, {r['score']['preimage_bits']} bits) ({r['gates']['cost']['gpu_hours_rtx4090']} GPU-h, "
      f"{r['gates']['cost']['total_vbytes']} vB, bits {r['score']['bits_confidence']})"))
if r["verdict"] == "accepted":
    sys.path.insert(0, ".")
    import leaderboard
    print("   frontier:", leaderboard.status(r))
PY
rm -f "$OUT.tmp"
exit $RC
