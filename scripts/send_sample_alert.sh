#!/usr/bin/env bash
# POST a synthetic alert to soc-homelab alert-sink (default localhost:8088).
set -euo pipefail

SINK="${ALERT_SINK:-http://localhost:8088/alert}"

curl -sS -X POST "$SINK" \
  -H "Content-Type: application/json" \
  -d '{
    "rule": "ssh_bruteforce",
    "severity": "medium",
    "host": "lab-web-01",
    "src_ip": "203.0.113.10",
    "detail": "synthetic alert from soc-log-analysis"
  }' | python -m json.tool
