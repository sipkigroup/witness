"""0.2.58 (FABLE-NOL 03.11 p.5.4): `deus-witness-hook --setup-strict` writes the strict Claude Code sandbox into the USER settings
(~/.claude/settings.json), with a backup and a printed diff; `--undo-strict` puts the backup back. Under the standing mandate the lines
the classifier cannot read (opaque: `$(...)`, eval, functions, interpreter code with a path not shown) are asked unless this sandbox holds
the call (server: hookjudge/sandbox.evaluate + allowances.code_cover, 0.2.82): macOS Seatbelt, no network but the allow-list, secrets
unreadable, no retry outside the sandbox. What the hook cannot set from a file: CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 must be in the
environment of the shell that starts Claude Code (0.2.57, L2 b2) -- printed as the one remaining step. macOS only (sandbox.py)."""
from __future__ import annotations

import difflib
import json
import os
import sys
import time

SECRETS = [".ssh", ".aws", ".config/gh", ".netrc", ".docker", ".kube", ".gnupg", ".npmrc", ".pypirc", ".git-credentials",
           ".config/gcloud", ".azure", ".config/deus-witness", ".claude.json", ".claude/.credentials.json"]
# 11.11 (r0260) = sandbox_fact.CRED_SOURCES (server hookjudge/sandbox.CRED_SOURCES has the reason for each): the login keychain, browser
# cookie stores, editors' token stores, CLI credential files. Not ~/Library/Caches (pip, uv, Homebrew read it).
CRED_SOURCES = ["Library/Keychains", "Library/Cookies", "Library/HTTPStorages", "Library/Safari", "Library/Containers/com.apple.Safari",
                "Library/Application Support/Google/Chrome", "Library/Application Support/BraveSoftware",
                "Library/Application Support/Microsoft Edge", "Library/Application Support/Arc", "Library/Application Support/Chromium",
                "Library/Application Support/Vivaldi", "Library/Application Support/com.operasoftware.Opera",
                "Library/Application Support/Firefox", "Library/Application Support/Code/User/globalStorage",
                "Library/Application Support/Cursor/User/globalStorage", ".config/hub", ".config/glab-cli",
                "Library/Application Support/glab-cli", ".config/git/credentials", ".gcm", ".cargo/credentials", ".cargo/credentials.toml",
                ".gem/credentials", "Library/Application Support/pypoetry/auth.toml"]
BLOCK = {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False, "excludedCommands": [],
         "network": {"allowedDomains": [], "strictAllowlist": True, "allowUnixSockets": [], "allowAllUnixSockets": False, "allowLocalBinding": False},
         "filesystem": {"denyRead": ["~/" + s for s in SECRETS + CRED_SOURCES]}}
# 11.11 (r0260, class (г) of the dev hold-out, L2 10.11): in this sandbox `npm view` / `npm install` fail writing ~/.npm (cache, logs),
# `git clone` / `git init` fail copying the sample hooks into the new .git/hooks (Seatbelt denies hooks/), and `pip download` saw
# "from versions: none" with pypi.org + files.pythonhosted.org listed -- hypothesis (L1, not yet measured): pip >= 24.2 verifies TLS through
# `truststore` (the macOS trust service over Mach lookup, which this sandbox denies: allowMachLookup is a WEAKER key; Claude Code's docs
# say the same of Go CLIs), so the index is unreachable. A developer would turn the strictness off; instead these variables (Claude Code's
# settings `env`, set only when the person has not set them) keep every write inside Claude Code's per-user temp root, which the sandbox
# already writes, and open nothing: no allowWrite, no excludedCommands, no host, no Mach service.
#   npm_config_cache / UV_CACHE_DIR -> <tmp>/claude-<uid>/{npm,uv}-cache   (npm: integrity-checked content cache, logs under it)
#   PIP_USE_DEPRECATED=legacy-certs                                            (pip's bundled certifi instead of the trust service)
#   GIT_TEMPLATE_DIR=""                                                        (git init / clone copy no template: no .git/hooks/*.sample)
def tool_env(uid=None):
    u = os.getuid() if uid is None and hasattr(os, "getuid") else (uid or 0)
    root = "/private/tmp/claude-%d" % u
    return {"npm_config_cache": root + "/npm-cache", "UV_CACHE_DIR": root + "/uv-cache", "PIP_USE_DEPRECATED": "legacy-certs",
            "GIT_TEMPLATE_DIR": ""}


# ignoreViolations: Claude Code 2.1.318 expects a record (a boolean makes it skip the whole settings file, L3 04.11); any entry weakens the sandbox, so it is removed
WEAKER = ("ignoreViolations", "enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "allowAppleEvents", "allowMachLookup")


def settings_path(env=None) -> str:
    e = os.environ if env is None else env
    base = e.get("CLAUDE_CONFIG_DIR") or os.path.join(e.get("HOME") or os.path.expanduser("~"), ".claude")
    return os.path.join(base, "settings.json")


def strict_settings(cur: dict) -> dict:
    out = json.loads(json.dumps(cur)) if isinstance(cur, dict) else {}
    sb = out.get("sandbox") if isinstance(out.get("sandbox"), dict) else {}
    for k in WEAKER:
        sb.pop(k, None)
    sb.update({k: v for k, v in BLOCK.items() if k not in ("network", "filesystem")})
    net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
    net.update(BLOCK["network"])
    net.pop("allowMachLookup", None)
    sb["network"] = net
    fs = sb.get("filesystem") if isinstance(sb.get("filesystem"), dict) else {}
    fs.pop("disabled", None)
    fs.pop("allowWrite", None)
    deny = [x for x in (fs.get("denyRead") or []) if isinstance(x, str)]
    fs["denyRead"] = deny + [x for x in BLOCK["filesystem"]["denyRead"] if x not in deny]
    fs["allowRead"] = [x for x in (fs.get("allowRead") or []) if isinstance(x, str) and not any(x.rstrip("/").endswith(s) for s in SECRETS)
                       and not any(("/" + s + "/") in (x.rstrip("/") + "/") for s in CRED_SOURCES)]   # 11.11: nor one inside a source
    sb["filesystem"] = fs
    out["sandbox"] = sb
    env = out.get("env") if isinstance(out.get("env"), dict) else {}
    have = {k.lower() for k in env}
    for k, v in tool_env().items():
        if k.lower() not in have:                     # the person's own value wins (npm reads NPM_CONFIG_CACHE too)
            env[k] = v
    out["env"] = env
    return out


def setup(env=None, write=True) -> int:
    p = settings_path(env)
    try:
        cur = json.load(open(p)) if os.path.exists(p) else {}
    except ValueError as e:
        print("deus-witness-hook --setup-strict: %s is not JSON (%s); fix it first" % (p, e), file=sys.stderr)
        return 1
    if not isinstance(cur, dict):
        print("deus-witness-hook --setup-strict: %s is not an object" % p, file=sys.stderr)
        return 1
    new = strict_settings(cur)
    a, b = json.dumps(cur, indent=2, ensure_ascii=False, sort_keys=True).splitlines(), json.dumps(new, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    diff = list(difflib.unified_diff(a, b, fromfile=p, tofile=p + " (strict)", lineterm=""))
    if not diff:
        print("already strict: %s" % p)
        return 0
    print("\n".join(diff))
    if not write:
        return 0
    bak = "%s.bak-strict-%s" % (p, time.strftime("%Y%m%dT%H%M%S"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if os.path.exists(p):
        with open(p, "rb") as f, open(bak, "wb") as g:
            g.write(f.read())
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(new, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(p + ".tmp", p)
    print("written: %s (backup: %s; undo: deus-witness-hook --undo-strict)" % (p, bak if os.path.exists(bak) else "none, the file was new"))
    print("one step the file cannot do: export CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 in the shell that starts Claude Code (the hook must see it), "
          "then start a NEW Claude Code session (the witness treats a session whose settings changed as not strict).")
    return 0


def undo(env=None) -> int:
    p = settings_path(env)
    d = os.path.dirname(p)
    baks = sorted(x for x in os.listdir(d) if x.startswith(os.path.basename(p) + ".bak-strict-")) if os.path.isdir(d) else []
    if not baks:
        print("deus-witness-hook --undo-strict: no backup next to %s" % p, file=sys.stderr)
        return 1
    src = os.path.join(d, baks[-1])
    with open(src, "rb") as f, open(p + ".tmp", "wb") as g:
        g.write(f.read())
    os.replace(p + ".tmp", p)
    print("restored %s from %s" % (p, src))
    return 0
