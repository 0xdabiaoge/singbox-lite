#!/usr/bin/env bash
set -euo pipefail
LOG_DIR=${LOG_DIR:-/var/log}
UNIT=${UNIT:-cloudflared-argo}
if [ -f "$LOG_DIR/${UNIT}.log" ]; then
  grep -oE "https?://[a-z0-9.-]+\.[a-z]{2,}" "$LOG_DIR/${UNIT}.log" | tail -n1 | sed 's#https\?://##' && exit 0
fi
journalctl -u "$UNIT" --no-pager -n 300 2>/dev/null | grep -oE "https?://[a-z0-9.-]+\.[a-z]{2,}" | tail -n1 | sed 's#https\?://##' || true
