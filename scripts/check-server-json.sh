#!/usr/bin/env bash
# server.json (MCP Registry): valid JSON, limits of the registry schema, same version as python/pyproject.toml,
# same name as the `mcp-name:` line of python/README.md (PyPI ownership check of the registry), PyPI package pinned to that version.
# Offline. The registry's own check (`mcp-publisher validate`) runs in release.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, re, sys
s = json.load(open("server.json", encoding="utf-8"))
py = open("python/pyproject.toml", encoding="utf-8").read()
pv = re.search(r'^version\s*=\s*"([^"]+)"', py, re.M).group(1)
readme = open("python/README.md", encoding="utf-8").read()
m = re.search(r"mcp-name:\s*(\S+?)(?:\s|-->|$)", readme)
errs = []
if not re.fullmatch(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+", s.get("name", "")): errs.append("name pattern")
if not 1 <= len(s.get("description", "")) <= 100: errs.append("description length %d (registry limit 100)" % len(s.get("description", "")))
if len(s.get("title", "")) > 100: errs.append("title > 100")
if s.get("version") != pv: errs.append("version %s != python/pyproject.toml %s" % (s.get("version"), pv))
if re.search(r"[\^~<>*]|\.x|latest", str(s.get("version"))): errs.append("version must be exact")
if not m or m.group(1) != s.get("name"): errs.append("python/README.md mcp-name %r != name %r" % (m and m.group(1), s.get("name")))
pk = s.get("packages") or []
if not pk: errs.append("no packages")
for p in pk:
    if p.get("registryType") == "pypi" and (p.get("identifier") != "deus-witness" or p.get("version") != pv): errs.append("pypi package must be deus-witness==%s" % pv)
if "<ORG>" in json.dumps(s) or "ORGNAME" in json.dumps(s): errs.append("placeholder org left (scripts/set-org.sh)")
if errs:
    print("server.json: " + "; ".join(errs), file=sys.stderr); sys.exit(1)
print("server.json OK: %s %s" % (s["name"], pv))
PY
