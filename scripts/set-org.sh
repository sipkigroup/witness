#!/usr/bin/env bash
# scripts/set-org.sh <github-org-lowercase>  -> replaces the placeholders <ORG> / ORGNAME everywhere (run once after the repo exists)
set -euo pipefail
cd "$(dirname "$0")/.."
O="${1:?usage: set-org.sh <github-org>}"
[[ "$O" =~ ^[a-z0-9-]+$ ]] || { echo "lowercase letters, digits, dash only (MCP Registry names are case-sensitive)" >&2; exit 2; }
grep -rlE "<ORG>|ORGNAME" . --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=scripts | while read -r f; do
  sed -i.bak -e "s/<ORG>/$O/g" -e "s/ORGNAME/$O/g" "$f" && rm -f "$f.bak"
done
bash scripts/check-version.sh
