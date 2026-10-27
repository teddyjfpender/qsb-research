#!/bin/bash
# Evaluate many submissions in parallel. Usage:
#   challenge/run_batch.sh standard <dir>...      rank every given submission dir
#   challenge/run_batch.sh deep-pending           deep-verify every run that would join the frontier
# Parallelism: QSB_JOBS (default: half the CPU cores). Each job is an independent run_ranked.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
J=${QSB_JOBS:-$(( $(sysctl -n hw.ncpu 2>/dev/null || nproc) / 2 ))}
case "$1" in
  standard) shift; printf '%s\n' "$@" | xargs -P "$J" -I{} "$HERE/run_ranked.sh" {} ;;
  deep-pending)
    cd "$HERE"
    python3 leaderboard.py --pending | while read -r s; do
      for d in submissions baselines; do [ -d "$d/$s" ] && echo "$d/$s"; done
    done | xargs -P "$J" -I{} "$HERE/run_ranked.sh" {} --deep ;;
  *) echo "usage: $0 standard <dir>... | deep-pending"; exit 2 ;;
esac
