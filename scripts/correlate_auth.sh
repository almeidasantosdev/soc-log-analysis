#!/usr/bin/env bash
# Simple auth correlation for SOC N1 practice (grep/awk).
# Usage: bash scripts/correlate_auth.sh samples/auth.log

set -euo pipefail

LOG="${1:-samples/auth.log}"

if [[ ! -f "$LOG" ]]; then
  echo "File not found: $LOG" >&2
  exit 1
fi

echo "== Failures by source IP =="
grep -E "Failed password|Invalid user" "$LOG" \
  | grep -oE "from [^ ]+" \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -nr

echo
echo "== Successes by source IP =="
grep -E "Accepted " "$LOG" \
  | grep -oE "from [^ ]+" \
  | awk '{print $2}' \
  | sort \
  | uniq -c \
  | sort -nr

echo
echo "== IPs present in BOTH failures and successes (incident candidates) =="
comm -12 \
  <(grep -E "Failed password|Invalid user" "$LOG" | grep -oE "from [^ ]+" | awk '{print $2}' | sort -u) \
  <(grep -E "Accepted " "$LOG" | grep -oE "from [^ ]+" | awk '{print $2}' | sort -u)
