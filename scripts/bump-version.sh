#!/usr/bin/env bash
# scripts/bump-version.sh 0.3.0  -> sets the version in sdk-ts/package.json, then check-version.sh
set -euo pipefail
cd "$(dirname "$0")/.."
V="${1:?usage: bump-version.sh X.Y.Z}"
[[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "need X.Y.Z" >&2; exit 2; }
V="$V" python3 - <<'PY'
import json, os
V = os.environ["V"]
d = json.load(open("sdk-ts/package.json")); d["version"] = V
open("sdk-ts/package.json", "w").write(json.dumps(d, indent=2) + "\n")
PY
bash scripts/check-version.sh
