"""V3 (0.2.56, 26.10.2026): the `sandbox` fact. The hook reads Claude Code's own settings layers and reports, for THIS Bash call, how
Claude Code's sandbox is configured. The hook does not decide anything: the witness decides whether the configuration is "strict"
(server/app/hookjudge/sandbox.py) and fails closed on anything unknown.

Settings layers (code.claude.com/docs/en/settings, "Settings precedence"), highest first:
  managed (managed-settings.json + managed-settings.d/*.json; failsafe.managed_files)  >  --settings (INVISIBLE to the hook)
  >  <project>/.claude/settings.local.json  >  <project>/.claude/settings.json  >  ~/.claude/settings.json ($CLAUDE_CONFIG_DIR/settings.json)
A scalar comes from the highest layer that sets it; "Lists merge instead of overriding" (union).
Keys read (code.claude.com/docs/en/sandboxing, settings-reference):
  sandbox.enabled, sandbox.failIfUnavailable, sandbox.allowUnsandboxedCommands, sandbox.excludedCommands, sandbox.ignoreViolations,
  sandbox.enableWeakerNestedSandbox, sandbox.enableWeakerNetworkIsolation, sandbox.allowAppleEvents,
  sandbox.filesystem.{denyRead, allowRead, disabled}, sandbox.credentials.files[{path, mode}],
  sandbox.network.{allowedDomains, allowUnixSockets, allowAllUnixSockets, allowMachLookup, allowLocalBinding},
  permissions.deny "Read(...)" (merged into denyRead by Claude Code), permissions.allow "WebFetch(domain:...)" (merged into allowedDomains),
  sandbox.network.strictAllowlist (0.2.57: ONLY from the managed or the user layer -- "Setting it in a repository's .claude/settings.json or
    .claude/settings.local.json has no effect"; from --settings it works for Claude Code but is invisible to the hook -> reported absent),
  sandbox.network.allowManagedDomainsOnly (0.2.57: managed layer only),
  env CLAUDE_CODE_SUBPROCESS_ENV_SCRUB (0.2.57: ONLY the hook's own process environment; a settings `env` block does not count -- L2
    OTCHET-V3-L2 b2: the variable in the project's `env` did not switch the scrub on, the hook and the command still saw the secrets),
  tool_input.dangerouslyDisableSandbox (this call asks to run outside the sandbox),
  the event's permission_mode (0.2.57; the witness accepts only the modes checked at L2).
A layer that exists but is not a JSON object is reported "bad": Claude Code skips it, the merged view is then not what Claude Code uses,
and the witness treats the fact as unknown. An MDM plist (macOS) is reported "unread"."""
from __future__ import annotations

import json
import os
import sys

from . import failsafe

MAX_LIST = 64
MAX_STR = 1024
MDM_PLISTS = ("/Library/Managed Preferences/com.anthropic.claudecode.plist",)
WEAKER = ("enableWeakerNestedSandbox", "enableWeakerNetworkIsolation", "allowAppleEvents")


def _load(path):
    """-> ("absent", None) | ("ok", dict) | ("bad", None)"""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except FileNotFoundError:
        return "absent", None
    except (OSError, ValueError):
        return "bad", None
    return ("ok", d) if isinstance(d, dict) else ("bad", None)


def _get(d, *path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def _strs(v):
    return [x for x in v if isinstance(x, str) and 0 < len(x) <= MAX_STR] if isinstance(v, list) else []


def _expand(p, home, project, rule=False):
    """A settings path -> an absolute path with trailing glob parts cut (`~/.ssh/**` -> <home>/.ssh). Permission rules: `//x` absolute,
    `/x` and `./x` project-relative, `~/x` home. sandbox.filesystem: `/x` absolute, `~/x` home, `.` / `x` project-relative."""
    if not isinstance(p, str) or not p:
        return None
    if p.startswith("//"):
        q = p[1:]
    elif p == "~" or p.startswith("~/"):
        q = home + p[1:]
    elif p.startswith("/") and not rule:
        q = p
    else:
        q = os.path.join(project or "/nonexistent-project", p.lstrip("/") if rule else p)
    q = os.path.normpath(q)
    while q.endswith(("/**", "/*")):
        q = q.rsplit("/", 1)[0]
    return q[:MAX_STR]


def _git_root(p):
    q = os.path.realpath(p)
    while True:
        if os.path.exists(os.path.join(q, ".git")):
            return q
        n = os.path.dirname(q)
        if n == q:
            return None
        q = n


def _transcript_config_dir(transcript):
    """Claude Code keeps a session's transcript at <config dir>/projects/<project slug>/<session>.jsonl -> <config dir>, else None."""
    if not isinstance(transcript, str) or not os.path.isabs(transcript):
        return None
    d = os.path.dirname(os.path.dirname(os.path.normpath(transcript)))
    return os.path.dirname(d) if os.path.basename(d) == "projects" else None


def layers(project, env, home, transcript=None):
    """[(name, status, dict)] highest precedence first.
    0.2.56: CLAUDE_CODE_SUBPROCESS_ENV_SCRUB removes CLAUDE_CONFIG_DIR from the hook's environment (env-vars, "What the subprocess
    environment scrub removes"), so the hook may not see where Claude Code keeps the user settings. The event's transcript_path names the
    directory Claude Code really uses: when it is not the one read here, the user layer is reported "unread" (the witness then asks)."""
    out = []
    for p in reversed(failsafe.managed_files()):
        st, d = _load(p)
        if st != "absent":
            out.append(("managed", st, d))
    for p in MDM_PLISTS:
        if failsafe.MANAGED_DIR_OVERRIDE is None and os.path.exists(p):
            out.append(("managed-mdm", "unread", None))
    if project:
        root = _git_root(project)
        if root and root != project:                  # Claude Code 2.1.211+: the local file lives at the repository root (and an older one
            st, d = _load(os.path.join(root, ".claude", "settings.local.json"))     # in the starting directory is read too; root wins a key)
            out.append(("local-root", st, d))
        for n, f in (("local", "settings.local.json"), ("project", "settings.json")):
            st, d = _load(os.path.join(project, ".claude", f))
            out.append((n, st, d))
    cfg = env.get("CLAUDE_CONFIG_DIR")
    udir = cfg if cfg and os.path.isabs(cfg) else os.path.join(home, ".claude")
    real = _transcript_config_dir(transcript)
    if real is not None and os.path.realpath(real) != os.path.realpath(udir):
        out.append(("user", "unread", None))          # the user settings live elsewhere ($CLAUDE_CONFIG_DIR hidden from the hook)
        return out
    st, d = _load(os.path.join(udir, "settings.json"))
    out.append(("user", st, d))
    return out


def fact(tool_input, project, env=None, home=None, platform=None, transcript=None, permission_mode=None) -> dict:
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    L = layers(project, env, home, transcript)
    ok = [d for _, st, d in L if st == "ok"]

    def scalar(*path):
        for d in ok:                                  # highest first
            v = _get(d, *path)
            if v is not None:
                return v
        return None

    def union(*path):
        out = []
        for d in reversed(ok):
            for x in _strs(_get(d, *path)):
                if x not in out:
                    out.append(x)
        return out[:MAX_LIST * 4]

    # 0.2.56: a relative sandbox path ("./x" or "x") resolves "to the project root for project settings, or to ~/.claude for user
    # settings" (settings-reference, "Sandbox path prefixes"). The prototype resolved every one against the project, so a user-level
    # `"allowRead": ["."]` (really ~/.claude, which re-opens ~/.claude/.credentials.json) looked harmless. Each layer now resolves its own;
    # a relative path in managed settings has no documented base -> reported "unread" (the witness asks).
    cfg = env.get("CLAUDE_CONFIG_DIR")
    udir = cfg if cfg and os.path.isabs(cfg) else os.path.join(home, ".claude")
    root = _git_root(project) if project else None
    base = {"user": udir, "project": project, "local": project, "local-root": root or project}
    named = [(n, d) for n, st, d in L if st == "ok"]
    deny, allow, unknown = [], [], []

    def rel(x):
        return isinstance(x, str) and not (x.startswith("/") or x == "~" or x.startswith("~/"))

    for n, d in reversed(named):
        b = base.get(n)
        for key, out in (("denyRead", deny), ("allowRead", allow)):
            for x in _strs(_get(d, "sandbox", "filesystem", key)):
                if rel(x) and b is None:
                    unknown.append(n)
                    continue
                out.append(_expand(x, home, b))
        for c in _get(d, "sandbox", "credentials", "files") or []:
            if isinstance(c, dict) and c.get("mode") in ("deny", "mask"):
                if rel(c.get("path")) and b is None:
                    continue                          # a deny we cannot place counts as absent (fail closed)
                deny.append(_expand(c.get("path"), home, b))
    for r in union("permissions", "deny"):
        if r.startswith("Read(") and r.endswith(")"):
            deny.append(_expand(r[5:-1], home, project, rule=True))
    deny, allow = list(dict.fromkeys(deny))[:MAX_LIST * 4], list(dict.fromkeys(allow))[:MAX_LIST * 4]
    domains = union("sandbox", "network", "allowedDomains")
    for r in union("permissions", "allow"):
        if r.startswith("WebFetch(domain:") and r.endswith(")"):
            domains.append(r[len("WebFetch(domain:"):-1])
    # 0.2.57 (L2 b2/b3): the scrub is on only when Claude Code was STARTED with it; then the variable reaches the hook's own environment
    # (b3). A settings `env` block naming it does not switch it on (b2), so it is not read from the layers any more.
    scrub = env.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")
    # 0.2.57 (L2 a1/a2): in bypassPermissions mode the sandbox proxy lets a host outside allowedDomains through unless strictAllowlist or
    # allowManagedDomainsOnly is on (sandboxing.md, "Hosts outside your allowed domains"); a2: with strictAllowlist curl got HTTP=000
    # "host is not on the allow list". The key counts from the managed and the user layer only (project/local: no effect; --settings:
    # unseen -> absent -> the witness asks).
    lock_layers = [d for n, st, d in L if st == "ok" and n in ("managed", "user")]

    def lock_scalar(*path):
        for d in lock_layers:                         # managed first, then user
            v = _get(d, *path)
            if v is not None:
                return v
        return None
    strict_allow = lock_scalar("sandbox", "network", "strictAllowlist")
    managed_only = any(_get(d, "sandbox", "network", "allowManagedDomainsOnly") is True for n, st, d in L if st == "ok" and n == "managed")
    plat = platform or sys.platform
    if plat.startswith("linux"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                plat = "wsl" if "microsoft" in f.read().lower() else "linux"
        except OSError:
            plat = "linux"
    envf = []
    if project:
        try:
            envf = sorted(os.path.join(project, n) for n in os.listdir(project) if n == ".env" or n.startswith(".env."))[:MAX_LIST]
        except OSError:
            envf = []
    ti = tool_input if isinstance(tool_input, dict) else {}
    return {
        "v": 1, "platform": plat,
        "sources": dict({n: st for n, st, _ in L}, **{"relative-" + n: "unread" for n in unknown}),
        "enabled": scalar("sandbox", "enabled"),
        "fail_if_unavailable": scalar("sandbox", "failIfUnavailable"),
        "allow_unsandboxed": scalar("sandbox", "allowUnsandboxedCommands"),
        "excluded": union("sandbox", "excludedCommands")[:MAX_LIST],
        "ignore_violations": bool(scalar("sandbox", "ignoreViolations")),
        "fs_disabled": scalar("sandbox", "filesystem", "disabled"),
        "deny_read": [x for x in deny if x][:MAX_LIST],
        "allow_read": [x for x in allow if x][:MAX_LIST],
        "domains": domains[:MAX_LIST],
        "unix_sockets": union("sandbox", "network", "allowUnixSockets")[:MAX_LIST],
        "all_unix_sockets": scalar("sandbox", "network", "allowAllUnixSockets"),
        "mach_lookup": union("sandbox", "network", "allowMachLookup")[:MAX_LIST],
        "local_binding": scalar("sandbox", "network", "allowLocalBinding"),
        "weaker": [k for k in WEAKER if scalar("sandbox", k) is True],
        "env_scrub": str(scrub).strip().lower() in ("1", "true", "yes"),
        "disable_flag": ti.get("dangerouslyDisableSandbox") not in (None, False),   # any other value: fail closed
        "env_files": envf,
        "strict_allowlist": strict_allow if isinstance(strict_allow, bool) else None,
        "managed_domains_only": managed_only,
        "permission_mode": permission_mode[:32] if isinstance(permission_mode, str) and permission_mode else None,
    }
