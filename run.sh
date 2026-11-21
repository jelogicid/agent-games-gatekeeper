#!/bin/bash
# Supervisor loop — keeps the gatekeeper agent alive. Secrets live in .env (600).
cd "$(dirname "$0")"
export TMPDIR="$HOME/tmp"
while true; do
  set -a; [ -f .env ] && . ./.env; set +a
  node server.js >> agent.log 2>&1
  echo "[supervisor] agent exited rc=$? at $(date -u +%FT%TZ), restart in 2s" >> agent.log
  sleep 2
done
