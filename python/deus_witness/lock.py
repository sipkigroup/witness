"""deus-witness lock: pin the Witness hook with Claude Code managed settings, so the agent cannot switch it off.

  deus-witness lock --print   the managed-settings.json for this OS (merged with the one already there, never overwriting its keys)
  deus-witness lock --plan    what the installation does, step by step, and ONE command for a person to run with sudo
  deus-witness lock --check   no privileges: LOCKED / NOT LOCKED (why); exit code 0 / 1

Why a root copy (ZAKREPLENIE-HUKA-1511, trap 2): the plugin's hook lives in ~/.claude/plugins/cache/... and the client in a venv of the
user - both writable by the agent, so a managed hook that calls them calls whatever the agent wrote there. The managed hook calls
<root>/hook.sh, a script owned by root that runs the client from <root>/venv (also owned by root) with `python -I`.
This command never runs sudo and never writes to system folders: it prints; the person runs the one command.
allowManagedHooksOnly is NOT set: it would switch off every user, project and plugin hook of the owner (their own rules)."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys

from . import __version__

MATCHER = ("Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Read|Grep|Glob|LS|WebFetch|WebSearch|"
           "ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*")          # the same matcher as the plugin's hooks.json
PLACES = {
    "darwin": {"managed": "/Library/Application Support/ClaudeCode/managed-settings.json",
               "root": "/Library/Application Support/ClaudeCode/deus-witness", "group": "wheel", "sha": "shasum -a 256",
               "python": ("/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
                          "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3",
                          "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3",
                          "/Library/Frameworks/Python.framework/Versions/3.11/bin/python3",
                          "/Library/Frameworks/Python.framework/Versions/3.10/bin/python3", "/usr/bin/python3")},
    "linux": {"managed": "/etc/claude-code/managed-settings.json", "root": "/etc/claude-code/deus-witness", "group": "root",
              "sha": "sha256sum", "python": ("/usr/bin/python3", "/usr/local/bin/python3")},
}
NO_MANAGED_ONLY = ("allowManagedHooksOnly is not set: it would switch off every user, project and plugin hook of the owner "
                   "(their own rules), not only the agent's")
URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~\-/]*)?")


def os_name(platform=None) -> str:
    p = platform or sys.platform
    if p.startswith("darwin"):
        return "darwin"
    if p.startswith("linux"):
        return "linux"
    raise SystemExit("deus-witness lock: managed settings are supported here for macOS and Linux only (got %s)" % p)


def places(platform=None, managed=None, root=None) -> dict:
    d = dict(PLACES[os_name(platform)])
    d["managed"] = managed or d["managed"]
    d["root"] = (root or d["root"]).rstrip("/")
    d["hook"] = d["root"] + "/hook.sh"
    return d


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def hook_script(root: str) -> str:
    """The root copy of the hook script. Its text depends only on `root` (the witness URL is a separate root-owned file), so the hash
    `--check` expects is known without reading anything the agent can write."""
    return """#!/bin/sh
# Deus Witness, root copy (deus-witness lock). Owned by root; Claude Code managed settings call it for every matched tool call.
# The client runs from the root-owned venv next to this file, with python -I (no PYTHONPATH, no user site, no current directory).
R=%s
PATH=/usr/bin:/bin:/usr/sbin:/sbin
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE DEUS_WITNESS_VERIFY DEUS_WITNESS_EXEC_SCAN DEUS_WITNESS_HOOK_ALLOW
DEUS_WITNESS_HOOK_TIMEOUT=610
DEUS_WITNESS_HOOK_WAIT=600
DEUS_WITNESS_HOOK_ON_DEFER=deny
DEUS_WITNESS_LOCKED_ROOT="$R"
export PATH DEUS_WITNESS_HOOK_TIMEOUT DEUS_WITNESS_HOOK_WAIT DEUS_WITNESS_HOOK_ON_DEFER DEUS_WITNESS_LOCKED_ROOT
if [ -s "$R/witness-url" ]; then
  DEUS_WITNESS_URL=$(head -n 1 "$R/witness-url")
  export DEUS_WITNESS_URL
fi
exec "$R/venv/bin/python" -I -m deus_witness.hook "$@"
""" % _q(root)


def expected_sha256(root: str) -> str:
    return hashlib.sha256(hook_script(root).encode()).hexdigest()


def hook_commands(hook: str) -> dict:
    return {"session": '"%s" --session-start' % hook, "pretool": '"%s" || exit 2' % hook, "post": '"%s"' % hook}


def ours(hook: str) -> dict:
    c = hook_commands(hook)
    return {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": c["session"], "timeout": 60}]}],
                      "PreToolUse": [{"matcher": MATCHER, "hooks": [{"type": "command", "command": c["pretool"], "timeout": 620,
                                                                     "onFailure": "block"}]}],
                      # r0316: the check after the call (pin.check): a call that ran is compared with the input Witness approved
                      "PostToolUse": [{"matcher": MATCHER, "hooks": [{"type": "command", "command": c["post"], "timeout": 30}]}],
                      "PostToolUseFailure": [{"matcher": MATCHER, "hooks": [{"type": "command", "command": c["post"], "timeout": 30}]}]},
            "permissions": {"disableBypassPermissionsMode": "disable"}}


def _names_hook(entry, hook: str) -> bool:
    hs = entry.get("hooks") if isinstance(entry, dict) else None
    return isinstance(hs, list) and any(isinstance(h, dict) and isinstance(h.get("command"), str) and hook in h["command"] for h in hs)


def merge(existing, hook: str):
    """-> (settings, warnings). Keeps every key of `existing`; replaces only our own entries (idempotent) and the bypass key."""
    warn = []
    out = copy.deepcopy(existing) if isinstance(existing, dict) else {}
    mine = ours(hook)
    hooks = out.get("hooks")
    if not isinstance(hooks, dict):
        if hooks is not None:
            warn.append("the managed file's \"hooks\" is not an object: replaced")
        hooks = out["hooks"] = {}
    for ev, entries in mine["hooks"].items():
        cur = hooks.get(ev)
        if not isinstance(cur, list):
            if cur is not None:
                warn.append("the managed file's hooks.%s is not a list: replaced" % ev)
            cur = []
        hooks[ev] = [e for e in cur if not _names_hook(e, hook)] + copy.deepcopy(entries)
    perms = out.get("permissions")
    if not isinstance(perms, dict):
        if perms is not None:
            warn.append("the managed file's \"permissions\" is not an object: replaced")
        perms = out["permissions"] = {}
    if perms.get("disableBypassPermissionsMode") not in (None, "disable"):
        warn.append("permissions.disableBypassPermissionsMode was %r: set to \"disable\"" % perms.get("disableBypassPermissionsMode"))
    perms["disableBypassPermissionsMode"] = "disable"
    if out.get("disableAllHooks") is True:
        warn.append("disableAllHooks: true in the managed file switches the Witness hook off: removed")
        del out["disableAllHooks"]
    return out, warn


def read_json(path: str):
    """-> (data, error). Missing = (None, None)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(4 * 1024 * 1024)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, type(e).__name__
    try:
        d = json.loads(raw.decode("utf-8-sig"))
    except ValueError:
        return None, "NOT_JSON"
    return (d, None) if isinstance(d, dict) else (None, "NOT_OBJECT")


def settings_for(p: dict):
    """-> (text, warnings, existed)."""
    cur, err = read_json(p["managed"])
    warn = []
    if err:
        warn.append("%s exists but cannot be used (%s): it would be REPLACED - look at it first" % (p["managed"], err))
    elif cur is not None:
        warn.append("%s already exists: this is a MERGE (its other keys are kept); compare before installing" % p["managed"])
    data, w = merge(cur, p["hook"])
    return json.dumps(data, indent=2) + "\n", warn + w, cur is not None or bool(err)


def do_print(p: dict, out=None) -> int:
    out = out or sys.stdout
    text, warn, _ = settings_for(p)
    print("# %s" % p["managed"], file=out)
    for w in warn:
        print("# WARNING: " + w, file=out)
    print("# " + NO_MANAGED_ONLY, file=out)
    out.write(text)
    return 0


# ---- checks (no privileges) ----

def _mode_ok(st, allowed_uids) -> str | None:
    if st.st_uid not in allowed_uids:
        return "owned by uid %d, not root" % st.st_uid
    if stat.S_IMODE(st.st_mode) & 0o022:
        return "writable by group or others (mode %o)" % stat.S_IMODE(st.st_mode)
    return None


def path_safe(path: str, allowed_uids=(0,)) -> str | None:
    """None when `path` and every folder above it are owned by root (allowed_uids) and writable by nobody else, with no symlink on
    the way (a user-owned folder or symlink anywhere above lets the agent move the file away and put its own in place)."""
    try:
        if os.path.realpath(path) != os.path.abspath(path):
            return "%s goes through a symlink" % path
        st = os.lstat(path)
    except OSError as e:
        return "%s: %s" % (path, e.strerror or type(e).__name__)
    why = _mode_ok(st, allowed_uids)
    if why:
        return "%s is %s" % (path, why)
    d = os.path.dirname(os.path.abspath(path))
    while True:
        try:
            why = _mode_ok(os.lstat(d), allowed_uids)
        except OSError as e:
            return "%s: %s" % (d, e.strerror or type(e).__name__)
        if why:
            return "folder %s is %s" % (d, why)
        up = os.path.dirname(d)
        if up == d:
            return None
        d = up


def _first_word(cmd: str) -> str:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    return cmd.split(None, 1)[0] if cmd else ""


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(65536), b""):
                h.update(b)
        return h.hexdigest()
    except OSError:
        return None


def check(p: dict, allowed_uids=(0,), deep=True) -> dict:
    """-> {"locked": bool, "reasons": [...], "sha256": hash of the root hook script or None}. deep: also every file of the root venv."""
    reasons = []
    data, err = read_json(p["managed"])
    if data is None:
        reasons.append("no managed settings file at %s" % p["managed"] if err is None else "%s: %s" % (p["managed"], err))
        data = {}
    else:
        why = path_safe(p["managed"], allowed_uids)
        if why:
            reasons.append(why)
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if data and perms.get("disableBypassPermissionsMode") != "disable":
        reasons.append('permissions.disableBypassPermissionsMode is not "disable" (bypassPermissions mode stays available)')
    if data.get("disableAllHooks") is True:
        reasons.append("disableAllHooks: true in the managed file")
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    c = hook_commands(p["hook"])
    want = {"PreToolUse": (MATCHER, c["pretool"]), "SessionStart": (None, c["session"]),
            "PostToolUse": (MATCHER, c["post"]), "PostToolUseFailure": (MATCHER, c["post"])}
    for ev, (matcher, cmd) in want.items():
        found, other = False, []
        for e in hooks.get(ev) or []:
            if not isinstance(e, dict) or not isinstance(e.get("hooks"), list):
                continue
            for h in e["hooks"]:
                if not isinstance(h, dict) or not isinstance(h.get("command"), str):
                    continue
                w = _first_word(h["command"])
                if w == p["hook"] and h["command"] == cmd and (matcher is None or e.get("matcher") == matcher) and \
                        (ev != "PreToolUse" or h.get("onFailure") == "block"):
                    found = True
                elif "deus-witness" in h["command"]:
                    other.append(w)
        if data and not found:
            reasons.append("no %s hook on the root copy %s%s" % (ev, p["hook"],
                           (" (it calls %s - a place the agent may write)" % ", ".join(sorted(set(other)))) if other else ""))
    sha = _sha256(p["hook"])
    why = path_safe(p["hook"], allowed_uids)
    if why:
        reasons.append(why)
    elif sha != expected_sha256(p["root"]):
        reasons.append("%s has sha256 %s, expected %s" % (p["hook"], sha, expected_sha256(p["root"])))
    elif not os.access(p["hook"], os.X_OK):
        reasons.append("%s is not executable" % p["hook"])
    py = p["root"] + "/venv/bin/python"
    if not os.path.exists(py):
        reasons.append("no root venv client at %s" % py)
    else:
        why = path_safe(os.path.realpath(py), allowed_uids)
        if why:
            reasons.append("the venv interpreter: " + why)
    if deep and os.path.isdir(p["root"]):
        bad = 0
        for d, dirs, files in os.walk(p["root"]):
            for n in dirs + files:
                try:
                    st = os.lstat(os.path.join(d, n))
                except OSError:
                    continue
                if st.st_uid not in allowed_uids or (not stat.S_ISLNK(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o022):
                    if not bad:
                        reasons.append("%s is not root-only (%s)" % (os.path.join(d, n), _mode_ok(st, allowed_uids)))
                    bad += 1
        if bad > 1:
            reasons.append("... %d more files under %s are not root-only" % (bad - 1, p["root"]))
    return {"locked": not reasons, "reasons": reasons, "sha256": sha}


def fact(p=None, allowed_uids=(0,)) -> dict | None:
    """For the hook: {"locked": bool, "sha256": str|None}, cheap (no venv walk). None on Windows / any error. The places are the fixed
    system ones (never from the environment: an agent that writes settings "env" would point the check at its own files)."""
    try:
        r = check(p or places(), allowed_uids, deep=False)
        return {"locked": bool(r["locked"]), "sha256": r["sha256"]}
    except BaseException:      # noqa: BLE001  (SystemExit on an unsupported OS too): no fact
        return None


def do_check(p: dict, allowed_uids=(0,), out=None) -> int:
    out = out or sys.stdout
    r = check(p, allowed_uids)
    if r["locked"]:
        print("LOCKED: %s calls %s (sha256 %s); bypassPermissions disabled" % (p["managed"], p["hook"], r["sha256"]), file=out)
        return 0
    print("NOT LOCKED: " + r["reasons"][0], file=out)
    for x in r["reasons"][1:]:
        print("  also: " + x, file=out)
    return 1


# ---- plan ----

def pick_python(p: dict, given=None, allowed_uids=(0,)):
    """-> (path, why_not). Only a root-owned interpreter: the install runs it as root, and the hook runs it for every call."""
    import subprocess
    for c in ([given] if given else list(p["python"])):
        if not c or not os.path.exists(c):
            continue
        rc = os.path.realpath(c)
        why = path_safe(rc, allowed_uids)
        if why:
            if given:
                return None, why
            continue
        try:
            v = subprocess.run([rc, "-I", "-c", "import sys; print(sys.version_info >= (3, 10))"], capture_output=True, text=True,
                               timeout=10, cwd="/").stdout.strip()
        except (OSError, subprocess.SubprocessError):
            v = ""
        if v == "True":
            return c, None
        if given:
            return None, "%s is not Python 3.10+" % c
    return None, ("no root-owned Python 3.10+ found (looked at: %s). A Python owned by your user (Homebrew, pyenv, uv) cannot be "
                  "used: the agent could change it and get root when the install runs. Install one from python.org (macOS) or "
                  "the system package manager, then run this again" % ", ".join(p["python"]))


def witness_url(env=None) -> str:
    from . import links
    u = links.configured_url(env)
    return u if isinstance(u, str) and URL_RE.fullmatch(u) else links.DEFAULT_URL


def install_script(p: dict, python: str, settings_text: str, url: str, version=__version__) -> str:
    R, M = p["root"], p["managed"]
    grp = p["group"]
    return """set -eu
umask 022
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
cd /
R={R}
M={M}
mkdir -p "$R" "$(dirname "$M")"
cat > "$R/hook.sh.new" <<'DW_HOOK_EOF'
{hook}DW_HOOK_EOF
mv -f "$R/hook.sh.new" "$R/hook.sh"
printf '%s\\n' {url} > "$R/witness-url"
{py} -I -m venv --clear "$R/venv"
"$R/venv/bin/python" -I -m pip install --isolated --no-cache-dir --only-binary=:all: --disable-pip-version-check --quiet {spec}
chown -R root:{grp} "$R"
chmod -R go-w "$R"
chmod 755 "$R" "$R/hook.sh"
cat > "$M.new" <<'DW_SETTINGS_EOF'
{settings}DW_SETTINGS_EOF
chown root:{grp} "$M.new"
chmod 644 "$M.new"
mv -f "$M.new" "$M"
{sha} "$R/hook.sh"
echo "expected: {expected}"
""".format(R=_q(R), M=_q(M), hook=hook_script(R), url=_q(url), py=_q(python), spec=_q("deus-witness==%s" % version), grp=grp,
           settings=settings_text, sha=p["sha"], expected=expected_sha256(R))


def do_plan(p: dict, python=None, allowed_uids=(0,), env=None, out=None) -> int:
    out = out or sys.stdout
    text, warn, existed = settings_for(p)
    py, why = pick_python(p, python, allowed_uids)
    url = witness_url(env)
    print("deus-witness lock --plan: nothing is changed by this command; the person runs ONE command below with sudo.", file=out)
    print("Steps the command performs (as root):", file=out)
    print("  1. create %s and write hook.sh there (the root copy of the hook script; sha256 %s)" % (p["root"], expected_sha256(p["root"])),
          file=out)
    print("  2. write %s/witness-url = %s (the witness the hook sends to; root-owned, not from the agent's environment)" % (p["root"], url),
          file=out)
    print("  3. create the venv %s/venv from %s and install deus-witness==%s from PyPI into it (wheels only, pip --isolated)"
          % (p["root"], py or "<no usable Python>", __version__), file=out)
    print("  4. chown -R root:%s, chmod -R go-w, hook.sh 755" % p["group"], file=out)
    print("  5. %s %s (hook on %s for SessionStart + PreToolUse, onFailure block; disableBypassPermissionsMode: disable)"
          % ("merge into" if existed else "write", p["managed"], p["hook"]), file=out)
    print("  6. print the sha256 of the copied hook.sh (must equal the one in step 1)", file=out)
    print("Not set: " + NO_MANAGED_ONLY, file=out)
    for w in warn:
        print("WARNING: " + w, file=out)
    try:
        from .trial import load_key
        if not os.environ.get("DEUS_WITNESS_KEY") and load_key() is None:
            print("WARNING: no agent key is set up: once locked, EVERY matched tool call is refused until you run `deus-witness try` "
                  "(or set DEUS_WITNESS_KEY)", file=out)
    except Exception:      # noqa: BLE001
        pass
    print("After it: `deus-witness lock --check` must say LOCKED. With the Deus Witness plugin also on, every call is witnessed "
          "twice: turn the plugin off (/plugin). Undo: sudo rm -r %s, and remove our entries from %s" % (_q(p["root"]), _q(p["managed"])),
          file=out)
    if py is None:
        print("BLOCKED: " + why, file=out)
        return 2
    script = install_script(p, py, text, url)
    print("\nThe one command (read it before you run it; script sha256 %s):\n" % hashlib.sha256(script.encode()).hexdigest(), file=out)
    out.write("sudo /bin/sh -s <<'DEUS_WITNESS_LOCK_EOF'\n" + script + "DEUS_WITNESS_LOCK_EOF\n")
    return 0


def main(argv=None, allowed_uids=(0,), out=None) -> int:
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="deus-witness lock", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--print", action="store_true", dest="print_", help="print managed-settings.json for this OS (merged)")
    g.add_argument("--plan", action="store_true", help="print the install steps and ONE sudo command (changes nothing)")
    g.add_argument("--check", action="store_true", help="LOCKED / NOT LOCKED; exit code 0 / 1 (no privileges)")
    ap.add_argument("--os", choices=("darwin", "linux"), default=None, help="target OS (default: this one)")
    ap.add_argument("--python", default=None, help="the root-owned Python 3.10+ for the root venv (--plan)")
    ap.add_argument("--managed-path", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--root-dir", default=None, help=argparse.SUPPRESS)
    o = ap.parse_args(argv)
    p = places(o.os, o.managed_path, o.root_dir)
    if o.print_:
        return do_print(p, out)
    if o.plan:
        return do_plan(p, o.python, allowed_uids, out=out)
    return do_check(p, allowed_uids, out)
