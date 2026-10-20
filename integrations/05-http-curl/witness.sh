#!/usr/bin/env sh
# Minimal Deus Witness calls with curl. env: DW_URL (e.g. http://localhost:8810), DW_KEY (agent key dwk_...)
# usage: witness.sh act TOOL 'ARGS_JSON' | get RID [WAIT_S] | present RID | report RID true|false | info
set -eu
H="Authorization: Bearer ${DW_KEY:-}"
case "${1:-}" in
  act)     curl -sS -X POST "$DW_URL/v1/actions" -H "$H" -H 'Content-Type: application/json' -d "{\"tool\":\"$2\",\"args\":$3}" ;;
  get)     curl -sS "$DW_URL/v1/actions/$2?wait=${3:-0}" -H "$H" ;;
  present) curl -sS -X POST "$DW_URL/v1/actions/$2/present" -H "$H" -H 'Content-Type: application/json' -d '{}' ;;
  report)  curl -sS -X POST "$DW_URL/v1/actions/$2/report" -H "$H" -H 'Content-Type: application/json' -d "{\"executed\":$3}" ;;
  info)    curl -sS "$DW_URL/v1/witness" ;;
  *) echo "usage: $0 act|get|present|report|info ..." >&2; exit 2 ;;
esac
echo
