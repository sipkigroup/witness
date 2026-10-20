#!/usr/bin/env bash
# The version in sdk-ts/package.json (equal to the tag vX.Y.Z when one is given). Also: no placeholder org left.
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(python3 -c "import json;print(json.load(open('sdk-ts/package.json'))['version'])")
echo "sdk-ts/package.json $v"
if [ $# -ge 1 ]; then [ "v$v" = "$1" ] || { echo "tag $1 != tree v$v" >&2; exit 1; }; fi
if [ -n "${GITHUB_ACTIONS:-}" ] && grep -rq '<ORG>' .github; then echo "placeholder org still present (scripts/set-org.sh)" >&2; exit 1; fi
echo "versions OK: $v"
