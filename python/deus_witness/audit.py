"""deus-witness audit (0.2.64): how open is your Claude Code to the agent, in 10 seconds, with no account and no server.

  uvx deus-witness audit [--json] [--project DIR]

Read only: no network request (no socket is opened), nothing is written, no account. It reads Claude Code's settings layers the way the
hook does (hook/sandbox_fact.layers: managed > local > project > user, $CLAUDE_CONFIG_DIR honoured; failsafe.settings_files for hooks) and
the names of the variables in the project's .env files -- never a value. Every line it prints follows from a setting it read; what the
settings do not decide (a launch flag such as --dangerously-skip-permissions, what an unknown hook does, auto mode's classifier) is said
as "not determined". Exit code is always 0: this is a report, not a gate.

Checked on a live Claude Code (L3: claude 2.1.323 with Haiku 5.5, 12.11.2026, fake keys in a scratch folder):
  - sandbox on, "Bash(*)" allowed, allowUnsandboxedCommands not false, default mode: a command retried with dangerouslyDisableSandbox
    is NOT run silently -- Claude Code asks ("Bash command (unsandboxed)"; claude -p: denied). In bypassPermissions it ran outside
    without a question; in auto mode the classifier let the same retry through (one run).
  - the sandbox refuses writes to the project's .git/hooks, .git/config, .claude/settings.json and .claude/settings.local.json; other
    files under .git and the project are writable.
  - the Read tool does NOT honour sandbox.filesystem.denyRead (it read a file the sandbox denied to `cat`); a permissions.deny
    "Read(...)" rule stops the Read tool AND is applied to sandboxed commands; outside the project the Read tool asks in default mode.

Grade: F = something critical runs without asking (any shell command outside a sandbox, persistence, secrets out to any host);
D = two or more high findings; C = one high or three or more medium; B = one or two medium; A = nothing above low."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys

from . import _compat
from .hook import failsafe, sandbox_fact

TOOL = "audit-0.1"
HOOK_SETUP = "uvx --from deus-witness deus-witness-hook --setup-strict"
WITNESS = "Deus Witness closes this: its Claude Code hook asks you (passkey) before such a call runs -- `uvx deus-witness try`"
WITNESS_TOOLS = ("Bash", "Edit", "Write", "WebFetch")

# what an agent would take: (path under home, words)
SECRETS = ((".ssh", "~/.ssh (SSH keys)"), (".aws", "~/.aws (AWS keys)"), ("Library/Keychains", "~/Library/Keychains (keychain files)"),
           (".config/gh", "~/.config/gh (GitHub token)"), (".netrc", "~/.netrc"), (".docker/config.json", "~/.docker/config.json"),
           (".kube", "~/.kube"), (".gnupg", "~/.gnupg"), (".npmrc", "~/.npmrc"), (".pypirc", "~/.pypirc"),
           (".git-credentials", "~/.git-credentials"), (".config/gcloud", "~/.config/gcloud"), (".azure", "~/.azure"))
KEY_SECRETS = (".ssh", ".aws", "Library/Keychains")          # the three the person asked about by name; always reported
# where a write survives the session: shell start files, macOS login items, Claude Code's own settings (its hooks run every call)
PERSIST = ((".zshrc", "~/.zshrc"), (".zprofile", "~/.zprofile"), (".bashrc", "~/.bashrc"), (".bash_profile", "~/.bash_profile"),
           (".profile", "~/.profile"), ("Library/LaunchAgents", "~/Library/LaunchAgents"))
NET_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "http", "https", "xh",
            "aria2c", "gh", "httpie"}
CODE_CMDS = {"sh", "bash", "zsh", "fish", "dash", "ksh", "python", "python3", "python2", "node", "deno", "bun", "ruby", "perl", "php",
             "lua", "osascript", "npx", "npm", "pnpm", "yarn", "uv", "uvx", "pip", "pip3", "pipx", "make", "cargo", "go", "env", "xargs",
             "eval", "exec", "sudo", "su", "docker", "podman", "find", "awk", "git", "open", "source", ".", "timeout", "nohup", "watch",
             "nice", "command", "builtin", "tee", "cp", "mv", "chmod", "crontab", "launchctl", "java", "dotnet", "rustc", "gcc", "cc"}
ENV_SKIP = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults")
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{0,127})\s*=\s*(\S?)")
SEV = ("critical", "high", "medium", "low")


# ---- reading -----------------------------------------------------------------------------------------------------------------------
def read_layers(project, env, home):
    """[(name, path, status, dict)] highest precedence first -- sandbox_fact.layers with the file of each layer (no `ps`: cli={})."""
    paths = []
    L = sandbox_fact.layers(project, env, home, None, paths, cli={})
    by_name = {}
    for n, p in paths:
        by_name[n] = p
    managed = [p for p in reversed(failsafe.managed_files()) if sandbox_fact._load(p)[0] != "absent"]
    out, mi = [], 0
    for n, st, d in L:
        if n == "managed":
            p = managed[mi] if mi < len(managed) else "managed"
            mi += 1
        else:
            p = by_name.get(n, n)
        out.append((n, p, st, d if isinstance(d, dict) else None))
    return out


def _rules(L, kind):
    """[(rule, file)] of permissions.<kind> over every readable layer (lists merge)."""
    out = []
    for _, p, st, d in L:
        if st == "ok":
            for r in sandbox_fact._strs(sandbox_fact._get(d, "permissions", kind)):
                if (r, p) not in out:
                    out.append((r, p))
    return out


def _scalar(L, *path):
    for _, p, st, d in L:
        if st == "ok":
            v = sandbox_fact._get(d, *path)
            if v is not None:
                return v, p
    return None, None


def _parse(rule):
    m = re.fullmatch(r"\s*([A-Za-z_][\w-]*)\s*(?:\((.*)\))?\s*", rule, re.S)
    return (m.group(1), m.group(2)) if m else (None, None)


def _rule_pattern(arg, home, project):
    """A permission rule's path (`~/x`, `//x` absolute, `/x` `./x` project, bare `x` anywhere) -> an absolute glob."""
    a = arg.strip()
    if a in ("", "*", "**", "//**"):
        return "/**"
    if a.startswith("//"):
        return a[1:]
    if a == "~" or a.startswith("~/"):
        return home + a[1:]
    if a.startswith("/") or a.startswith("./"):
        return os.path.join(project or "/nonexistent-project", a[2:] if a.startswith("./") else a.lstrip("/"))
    return "/**/" + a                                    # gitignore-like: a bare name matches at any depth


def covers(pattern, path) -> bool:
    """Does a path rule cover this path (the path itself, or the folder it is in)?"""
    if pattern == "/**":
        return True
    pat = pattern.rstrip("/")
    base = re.sub(r"/\*\*?$", "", pat)
    if "*" not in base and (path == base or path.startswith(base + "/")):
        return True
    return fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, pat.replace("/**/", "/"))


def _tool_rules(rules, tools):
    return [(t, a, r, p) for r, p in rules for t, a in [_parse(r)] if t in tools]


def path_rule(rules, tools, path, home, project):
    """The first (rule, file) of `rules` for one of `tools` that covers `path` (a bare tool name covers everything)."""
    for t, a, r, p in _tool_rules(rules, tools):
        if a is None or covers(_rule_pattern(a, home, project), path):
            return r, p
    return None


def bash_kind(arg):
    """`Bash(...)` argument -> "all" | "net" | "code" | None (a narrow rule)."""
    if arg is None or arg.strip() in ("", "*", "**", ":*", "* *"):
        return "all"
    a = arg.strip()
    if a.startswith("*"):
        return "all"
    if "*" not in a:
        return None                                      # an exact command line ("Bash(npm test)") is narrow
    m = re.match(r"([^\s:*]+)", a)
    w = os.path.basename(m.group(1)) if m else ""
    w = re.sub(r"(\d+(\.\d+)*)$", "", w) or w           # python3.12 -> python
    rest = a[m.end():] if m else ""
    if w == "git" and re.match(r"\s+push\b", rest):
        return "net"
    if w in NET_CMDS:
        return "net"
    if w in CODE_CMDS:
        return "code"
    return None


def net_target(rule):
    """`Bash(ssh vps:*)` -> "vps" (the rule names its host), `Bash(curl:*)` -> None (any host)."""
    _, a = _parse(rule)
    words = re.split(r"[\s:]+", re.sub(r"[:\s]*\*.*$", "", (a or "").strip()))
    w = [x for x in words[1:] if x and not x.startswith("-")]
    if words and os.path.basename(words[0]) in ("ssh", "scp", "sftp", "rsync", "telnet", "nc", "ncat") and w:
        return w[0][:60]
    return None


def _net_words(rules):
    t = [net_target(r) for r, _, _ in rules]
    if any(x is None for x in t):
        return "can upload any file it can read to any host"
    return "can send any file it can read to %s" % ", ".join(list(dict.fromkeys(t))[:4])


def env_files(project):
    """[{path, names}] -- names of the variables with a non-empty value in the project's .env files. Values are never kept."""
    out = []
    if not project:
        return out
    try:
        names = sorted(n for n in os.listdir(project) if (n == ".env" or n.startswith(".env.")) and n not in ENV_SKIP)
    except OSError:
        return out
    for n in names[:16]:
        p = os.path.join(project, n)
        if not os.path.isfile(p):
            continue
        vs = []
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f.read(256 * 1024).splitlines():
                    m = ENV_LINE.match(line)
                    if m and m.group(2) and m.group(1) not in vs:      # group(2): only whether a value is there, never the value
                        vs.append(m.group(1))
        except OSError:
            vs = None
        out.append({"path": p, "names": vs})
    return out


def pretooluse_hooks(project, env):
    """[{file, matcher, command}] -- every PreToolUse command hook in the settings Claude Code reads (failsafe.settings_files, with the
    Deus Witness plugin when a settings file switches it on). command = the program name only (arguments may carry a secret)."""
    files = failsafe.settings_files(project, env)
    managed = set(failsafe.managed_files())
    off_all, off_other = False, False
    for p in files:
        d = failsafe._load(p) or {}
        if d.get("disableAllHooks") is True:
            if p in managed:
                off_all = True
            else:
                off_other = True
    out = []
    for p in files:
        d = failsafe._load(p) or {}
        if off_all or (off_other and p not in managed):
            continue
        for grp in ((d.get("hooks") or {}).get("PreToolUse") or []) if isinstance(d.get("hooks"), dict) else []:
            if not isinstance(grp, dict):
                continue
            for h in grp.get("hooks") or []:
                if isinstance(h, dict) and isinstance(h.get("command"), str) and h["command"].strip():
                    words = h["command"].strip().split()
                    first = words[0]
                    if os.path.basename(first) in ("bash", "sh", "zsh", "python", "python3", "node", "uv", "uvx", "npx") and len(words) > 1:
                        first = next((x for x in words[1:] if not x.startswith("-")), first)   # the script, not its interpreter
                    out.append({"file": p, "matcher": str(grp.get("matcher", "") or "*")[:80],
                                "command": os.path.basename(first)[:60], "witness": "deus-witness-hook" in h["command"]})
    return out, {"disable_all_hooks": off_all or off_other}


def _matches(matcher, tool):
    if matcher in ("", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return False


# ---- the audit ---------------------------------------------------------------------------------------------------------------------
def audit(project=None, env=None, home=None, platform=None) -> dict:
    env = dict(os.environ if env is None else env)
    home = home or _compat.home(env)
    env["HOME"] = home
    project = os.path.realpath(project or os.getcwd())
    plat = platform or sys.platform
    L = read_layers(project, env, home)
    f = sandbox_fact.fact({}, project, env=env, home=home, platform=plat, cli={})
    strict_why = sandbox_fact.strict_reasons(f, home)
    allow, deny, ask = _rules(L, "allow"), _rules(L, "deny"), _rules(L, "ask")
    unknown, findings = [], []

    # permission mode
    mode, mode_src = _scalar(L, "permissions", "defaultMode")
    dis, _ = _scalar([x for x in L if x[0] == "managed"], "permissions", "disableBypassPermissionsMode")
    mode = mode if isinstance(mode, str) else "default"
    if mode == "bypassPermissions" and dis == "disable":
        mode, mode_src = "default", None
    bypass = mode == "bypassPermissions"
    unknown.append("launch flags (--dangerously-skip-permissions, --permission-mode, --settings) are not in the settings files: if you "
                   "start Claude Code with them, the real mode is theirs")
    if mode == "auto":
        unknown.append("auto mode: Claude Code's classifier decides which calls run without asking; what it lets through is not in "
                       "the settings (L3 12.11: it let a command retried outside the sandbox run without a question)")

    # sandbox
    sb_on = f.get("enabled") is True
    auto_sb, _ = _scalar(L, "sandbox", "autoAllowBashIfSandboxed")
    escape = f.get("allow_unsandboxed") is not False
    domains = f.get("domains") or []
    wide = [d for d in domains if not sandbox_fact.domain_narrow(d)]
    strict = sb_on and not strict_why

    # allow rules
    bash_rules = [(r, p, bash_kind(a)) for t, a, r, p in _tool_rules(allow, ("Bash",))]
    bash_all = [(r, p) for r, p, k in bash_rules if k == "all"]
    bash_wide = [(r, p, k) for r, p, k in bash_rules if k in ("net", "code")]
    edit_all = [(r, p) for t, a, r, p in _tool_rules(allow, ("Edit", "Write", "MultiEdit"))
                if a is None or _rule_pattern(a, home, project) in ("/**",) or a.strip() in ("~/**", "~", "//**")]
    web_all = [(r, p) for t, a, r, p in _tool_rules(allow, ("WebFetch",)) if a is None or a.strip() in ("", "*", "domain:*")]
    broad = [{"rule": r, "file": p, "kind": "any command"} for r, p in bash_all] + \
            [{"rule": r, "file": p, "kind": "network" if k == "net" else "runs any code"} for r, p, k in bash_wide] + \
            [{"rule": r, "file": p, "kind": "edit any file"} for r, p in edit_all] + \
            [{"rule": r, "file": p, "kind": "fetch any site"} for r, p in web_all]

    # who runs a shell command without asking, and where
    shell_free = bypass or bool(bash_all)
    if not sb_on:
        out_free = shell_free                                       # any command, no sandbox, no question
    else:
        # L3 12.11 (Claude Code 2.1.323): with the sandbox on, a retry with dangerouslyDisableSandbox is ASKED even under "Bash(*)" in
        # default mode; only bypassPermissions ran it outside without a question. excludedCommands run outside the sandbox (docs).
        out_free = (bypass and escape) or (shell_free and bool(f.get("excluded")))
    in_sb_free = sb_on and (auto_sb is not False or shell_free)      # sandboxed commands run without asking (Claude Code's default)
    code_out = [(r, p, k) for r, p, k in bash_wide if not sb_on or escape]
    any_host_sb = in_sb_free and (bool(wide) or (bypass and f.get("strict_allowlist") is not True and f.get("managed_domains_only") is not True))

    # witness / hooks
    hooks, hflags = pretooluse_hooks(project, env)
    witness_on = {t: any(h["witness"] and _matches(h["matcher"], t) for h in hooks) for t in WITNESS_TOOLS}
    other_hooks = [h for h in hooks if not h["witness"]]
    en = {}
    for _, p, st, d in reversed(L):
        if st == "ok" and isinstance(d.get("enabledPlugins"), dict):
            en.update(d["enabledPlugins"])
    plugins = sorted(k for k, v in en.items() if v is True and not str(k).startswith(failsafe.PLUGIN_NAME + "@"))
    if plugins:
        unknown.append("plugins on (%s): their own hooks are not read here" % ", ".join(plugins[:4]))
    if other_hooks:
        unknown.append("what your PreToolUse hook%s (%s) decide%s is not determined from settings" % (
            "s" if len(other_hooks) > 1 else "", ", ".join(sorted({h["command"] for h in other_hooks})[:3]), "" if len(other_hooks) > 1 else "s"))

    def W(*tools):
        return WITNESS if not any(witness_on.get(t) for t in tools) else None

    def add(fid, sev, can, fix, witness=None, tools=()):
        if tools and any(witness_on.get(t) for t in tools):
            sev = SEV[min(SEV.index(sev) + 1, 3)]
            can += " -- unless the Deus Witness hook installed here asks you first"
            witness = None
        findings.append({"id": fid, "severity": sev, "can": can, "fix": fix, "witness": witness})

    how_mode = ('set "defaultMode": "default" under "permissions" in %s' % mode_src) if bypass else None
    how_bash = "remove %s from permissions.allow in %s" % (", ".join('"%s"' % r for r, _ in bash_all[:2]), bash_all[0][1]) if bash_all else None

    if out_free:
        src = "permission mode bypassPermissions (%s)" % mode_src if bypass else "allow rule %s (%s)" % (bash_all[0][0], bash_all[0][1])
        add("shell-free", "critical", "can run ANY shell command without asking you, outside a sandbox -- %s" % src,
            how_mode or how_bash or HOOK_SETUP, W("Bash"), ("Bash",))
    # secrets
    present = [(rel, words) for rel, words in SECRETS if os.path.exists(os.path.join(home, rel))]
    if plat != "darwin":
        present = [x for x in present if not x[0].startswith("Library/")]
    deny_sb = f.get("deny_read") or []
    allow_sb = f.get("allow_read") or []

    def sb_closed(path):
        return any(sandbox_fact._covered(e, path) for e in deny_sb) and not any(
            sandbox_fact._covered(a, path) or sandbox_fact._covered(path, a) for a in allow_sb)
    secrets = {}
    for rel, words in SECRETS:
        ap = os.path.join(home, rel)
        secrets[rel] = {"path": "~/" + rel, "exists": os.path.exists(ap), "read_rule": (path_rule(deny, ("Read",), ap, home, project) or (None,))[0],
                        "sandbox_denied": sb_closed(ap)}
    reach = [words for rel, words in present if not sb_on or not sb_closed(os.path.join(home, rel))]
    if out_free and present:
        add("secrets-out", "critical", "can send %s to any address on the internet" % ", ".join(w for _, w in present[:3]) +
            (" and %d more" % (len(present) - 3) if len(present) > 3 else ""),
            how_mode or how_bash or HOOK_SETUP, W("Bash"), ("Bash",))
    elif in_sb_free and reach and any_host_sb:
        add("secrets-out", "critical", "can read %s inside the sandbox and send it to any host (%s)" % (
            ", ".join(reach[:3]), "allowedDomains has %s" % ", ".join(wide[:2]) if wide else
            "bypassPermissions without sandbox.network.strictAllowlist"), HOOK_SETUP, W("Bash"), ("Bash",))
    elif in_sb_free and reach and sandbox_fact.write_hosts(domains):
        add("secrets-out", "high", "can read %s inside the sandbox; allowedDomains lets commands reach %s" % (
            ", ".join(reach[:3]), ", ".join(sandbox_fact.write_hosts(domains)[:3])), HOOK_SETUP, W("Bash"), ("Bash",))
    # the Read tool. L3 12.11 (Claude Code 2.1.323): it ignores sandbox.filesystem.denyRead; a Read deny rule stops it; outside the
    # project (and additionalDirectories) it asks in default mode; bypassPermissions reads without a question.
    unread = [(rel, words) for rel, words in present if rel in KEY_SECRETS + (".config/gh",) and not secrets[rel]["read_rule"]]
    add_dirs = []
    for _, p, st, d in L:
        if st == "ok":
            add_dirs += [x for x in (sandbox_fact._expand(y, home, project) for y in
                                     sandbox_fact._strs(sandbox_fact._get(d, "permissions", "additionalDirectories"))) if x]

    def read_free(rel):
        ap = os.path.join(home, rel)
        return (ap == project or ap.startswith(project + "/") or
                any(ap == a or ap.startswith(a.rstrip("/") + "/") for a in add_dirs) or bool(path_rule(allow, ("Read",), ap, home, project)))
    fix_read = 'add %s to permissions.deny (or: %s)' % (", ".join('"Read(~/%s/**)"' % r for r, _ in unread[:2]), HOOK_SETUP)
    if unread:
        words = ", ".join(w for _, w in unread[:3])
        free = [w for r, w in unread if read_free(r)]
        sbx = " (the sandbox's denyRead does not stop the Read tool)" if all(secrets[r]["sandbox_denied"] for r, _ in unread) else ""
        if bypass:
            add("read-secrets", "high", "can open %s with its Read tool without asking (no Read deny rule); the content goes to the model"
                % words, fix_read)
        elif free:
            add("read-secrets", "medium", "can open %s with its Read tool without asking (inside the project, additionalDirectories or a "
                "Read allow rule; no Read deny rule)%s" % (", ".join(free[:3]), sbx), fix_read)
        elif mode == "auto":
            add("read-secrets", "medium", "in auto mode Claude Code's classifier decides whether its Read tool opens %s without asking "
                "(no Read deny rule)%s" % (words, sbx), fix_read)
        else:
            add("read-secrets", "low", "Claude Code asks you before its Read tool opens %s (outside the project); one yes sends the "
                "content to the model -- a Read deny rule makes it a no without a question%s" % (words, sbx), fix_read)
    # .env
    envs = env_files(project)
    for e in envs:
        e["read_rule"] = (path_rule(deny, ("Read",), e["path"], home, project) or (None,))[0]
    open_env = [e for e in envs if e["names"] and not e["read_rule"]]
    if open_env:
        nm = []
        for e in open_env:
            nm += [n for n in e["names"] if n not in nm]
        sev = "high" if (out_free or bypass) else "medium"
        add("env-file", sev, "can read %s in this project: %s" % (
            ", ".join(os.path.basename(e["path"]) for e in open_env[:3]), ", ".join(nm[:6]) + (" ..." if len(nm) > 6 else "")) +
            (" and send it anywhere" if out_free else ""), 'add "Read(./.env*)" to permissions.deny in %s' % os.path.join(project, ".claude", "settings.json"))
    # persistence
    targets = [(os.path.join(home, rel), words) for rel, words in PERSIST]
    cfg = env.get("CLAUDE_CONFIG_DIR")
    udir = cfg if cfg and os.path.isabs(cfg) else os.path.join(home, ".claude")
    targets += [(os.path.join(udir, "settings.json"), "its own settings and hooks (%s)" % os.path.join(udir.replace(home, "~", 1), "settings.json")),
                (os.path.join(project, ".git", "hooks"), "this project's .git/hooks")]
    allow_w = []
    for _, p, st, d in L:
        if st == "ok":
            allow_w += [sandbox_fact._expand(x, home, project) for x in sandbox_fact._strs(sandbox_fact._get(d, "sandbox", "filesystem", "allowWrite"))]
    persist = {}
    for ap, words in targets:
        denied = path_rule(deny, ("Edit", "Write"), ap, home, project)
        by_edit = None
        if not denied:
            if bypass:
                by_edit = "bypassPermissions"
            elif path_rule(allow, ("Edit", "Write", "MultiEdit"), ap, home, project):
                by_edit = "allow rule " + path_rule(allow, ("Edit", "Write", "MultiEdit"), ap, home, project)[0]
            elif mode == "acceptEdits" and (ap == project or ap.startswith(project + "/")):
                by_edit = "acceptEdits (inside the project)"
        by_shell = None
        if out_free:
            by_shell = "shell outside the sandbox"
        elif in_sb_free and ap.endswith("/Library/LaunchAgents") and (ap.startswith(project + "/") or any(sandbox_fact._covered(a, ap) for a in allow_w if a)):
            # Claude Code's sandbox keeps shell start files, its own settings, .git/hooks and .git/config read-only even inside the
            # project (L3 12.11, 2.1.323: .git/hooks, .git/config, .claude/settings.json, .claude/settings.local.json refused; other
            # files under .git written); a login item folder it does not know of is writable when the project or allowWrite holds it
            by_shell = "sandboxed shell (the folder is writable in the sandbox)"
        persist[words] = {"path": ap, "edit_tool": by_edit, "shell": by_shell, "deny_rule": denied[0] if denied else None}
    pw = [w for w, v in persist.items() if v["edit_tool"] or v["shell"]]
    if pw:
        crit = [w for w in pw if not w.startswith("this project")]
        add("persist", "critical" if crit else "medium",
            "can change %s without asking -- code that runs again in every new terminal, login or Claude Code session" % ", ".join(pw[:4])
            + (" ..." if len(pw) > 4 else "") if crit else "can change %s without asking (runs at the next git commit)" % pw[0],
            how_mode or how_bash or (('add "Edit(~/.zshrc)", "Edit(~/Library/LaunchAgents/**)", "Edit(~/.claude/settings.json)" to '
                                      'permissions.deny') if crit else 'add "Edit(./.git/hooks/**)" to permissions.deny'),
            W("Edit", "Write", "Bash"), ("Edit", "Write", "Bash"))
    # network by the WebFetch tool
    if bypass or web_all:
        add("fetch-any", "high", "can open any web address with WebFetch without asking -- data can leave in the address itself",
            how_mode or "remove %s from permissions.allow in %s" % (web_all[0][0], web_all[0][1]), W("WebFetch"), ("WebFetch",))
    # wide allow rules (not already covered by "any command")
    if code_out and not out_free:
        r, p, k = code_out[0]
        add("wide-allow", "high", "runs %s without asking (%s): %s" % (
            ", ".join('"%s"' % x[0] for x in code_out[:3]), p,
            _net_words([x for x in code_out if x[2] == "net"]) if k == "net" else "that is any program, not one command"),
            "remove %s from permissions.allow, or %s (commands then run in the strict sandbox)" % ('"%s"' % r, HOOK_SETUP), W("Bash"), ("Bash",))
    # no sandbox, everything asked
    if not sb_on and not out_free:
        add("no-sandbox", "medium", "every command you approve runs with your full access: all your files, any host (no sandbox)",
            HOOK_SETUP + " (macOS: strict sandbox, secrets closed, network only to a short list)" if plat == "darwin" else
            'set "sandbox": {"enabled": true, "allowUnsandboxedCommands": false} in ~/.claude/settings.json')
    elif sb_on and not strict and not any(x["id"] == "secrets-out" and x["severity"] == "critical" for x in findings):
        add("sandbox-weak", "medium" if escape or wide else "low", "the sandbox is on but not strict: %s" % "; ".join(
            _short(x) for x in strict_why[:3]), HOOK_SETUP)
    order = {s: i for i, s in enumerate(SEV)}
    findings.sort(key=lambda x: order[x["severity"]])
    n = {s: sum(1 for x in findings if x["severity"] == s) for s in SEV}
    grade = "F" if n["critical"] else "D" if n["high"] >= 2 else "C" if n["high"] == 1 or n["medium"] >= 3 else "B" if n["medium"] else "A"
    return {
        "tool": TOOL, "grade": grade, "read_only": True, "network": False, "project": project, "home": home,
        "settings": [{"layer": n_, "path": p, "status": st} for n_, p, st, _ in L],
        "checks": {
            "sandbox": {"enabled": sb_on, "strict": strict, "not_strict_because": strict_why, "allow_unsandboxed_commands": escape,
                        "auto_allow_bash": auto_sb is not False, "excluded_commands": f.get("excluded") or []},
            "network": {"allowed_domains": domains, "wide": wide, "strict_allowlist": f.get("strict_allowlist") is True,
                        "managed_domains_only": f.get("managed_domains_only") is True},
            "permission_mode": {"value": mode, "source": mode_src, "bypass_disabled_by_managed": dis == "disable"},
            "secrets": secrets,
            "persistence": persist,
            "broad_allow": broad,
            "ask_rules": len(ask), "deny_rules": len(deny),
            "env_files": [{"path": e["path"], "names": e["names"], "read_rule": e["read_rule"]} for e in envs],
            "pretooluse_hooks": hooks, "hooks_disabled": hflags["disable_all_hooks"],
            "witness_hook": {t: v for t, v in witness_on.items()},
        },
        "findings": findings, "not_determined": unknown,
    }


def _short(why):
    return re.sub(r"\s+", " ", str(why))[:90]


MEANING = {"A": "nothing found that runs without your yes outside a strict sandbox",
           "B": "it asks before most things, but some doors are open",
           "C": "serious gaps",
           "D": "several serious open doors",
           "F": "the agent can do real damage without asking you"}


RUNTIME = ("A setting closes a door for good, but it judges a call by its name and prefix: once a command class is allowed (or the mode "
           "is bypassPermissions), no setting can tell `curl` to your API from `curl` with your keys to a stranger. Only a check of each "
           "call while it runs can. Deus Witness is such a check (a Claude Code hook; the risky call waits for your passkey; needs an "
           "account): `uvx deus-witness try`. It would cover finding%s %s here; it does not cover the Read tool.")


def render(r: dict) -> str:
    c = r["checks"]
    home = r.get("home") or ""

    def t(x):
        x = str(x)
        return x.replace(home + "/", "~/") if home and home != "/" else x
    L = ["Claude Code audit -- how open your set-up is to the agent (deus-witness %s, read only, no network)" % TOOL,
         "", "  Grade: %s   %s" % (r["grade"], MEANING[r["grade"]]), "  project: %s" % r["project"].replace((r.get("home") or "\0") + "/", "~/"), ""]
    if r["findings"]:
        L.append("What the agent can do right now (from your settings):")
        fixes, wit = {}, []
        for i, x in enumerate(r["findings"][:8], 1):
            L.append("  %d. [%s] %s" % (i, x["severity"], t(x["can"])))
            L.append("     fix (setting): %s" % (("same as %d" % fixes[x["fix"]]) if x["fix"] in fixes else t(x["fix"])))
            fixes.setdefault(x["fix"], i)
            if x.get("witness"):
                wit.append(str(i))
        if wit:
            L += ["", "What a setting cannot close:", "  " + RUNTIME % ("s" if len(wit) > 1 else "", ", ".join(wit))]
    else:
        L.append("Nothing in your settings lets the agent act on your secrets or outside the project without asking.")
    sb = c["sandbox"]
    net = c["network"]
    L += ["", "Checks:",
          "  sandbox          %s" % ("off" if not sb["enabled"] else "strict" if sb["strict"] else "on, not strict (%s)" % (
              "; ".join(_short(x) for x in sb["not_strict_because"][:2]) or "?")),
          "  network list     %s%s" % (", ".join(net["allowed_domains"][:5]) or "(none)",
                                       "; wide: " + ", ".join(net["wide"]) if net["wide"] else ""),
          "  permission mode  %s%s" % (c["permission_mode"]["value"], " (%s)" % t(c["permission_mode"]["source"]) if c["permission_mode"]["source"] else " (no setting: default)"),
          "  secrets denied   %s" % (", ".join("%s%s" % (v["path"], " (Read rule)" if v["read_rule"] else " (sandbox)")
                                                for v in c["secrets"].values() if v["exists"] and (v["read_rule"] or v["sandbox_denied"]))[:200] or "none"),
          "  wide allow rules %s" % (", ".join("%s [%s]" % (b["rule"], b["kind"]) for b in c["broad_allow"][:5]) or "none"),
          "  .env files       %s" % ("; ".join("%s: %s%s" % (os.path.basename(e["path"]),
                                                               "unreadable" if e["names"] is None else "%d variable(s)" % len(e["names"]),
                                                               ", Read denied" if e["read_rule"] else "") for e in c["env_files"]) or "none"),
          "  PreToolUse hooks %s" % ("; ".join("%s on %s" % (h["command"], h["matcher"]) for h in c["pretooluse_hooks"][:4]) or "none") +
          (" (disableAllHooks is set)" if c["hooks_disabled"] else "")]
    if r["not_determined"]:
        L.append("")
        L.append("Not determined:")
        L += ["  - " + x for x in r["not_determined"]]
    L.append("")
    L.append("Settings read: " + "; ".join("%s %s%s" % (s["layer"], t(s["path"]), "" if s["status"] == "ok" else " (%s)" % s["status"])
                                          for s in r["settings"]))
    L.append("Nothing was written, nothing was sent. Values of secrets are never read into this report: names and paths only.")
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deus-witness audit", description="How open is your Claude Code to the agent (read only, no network).")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--project", default=None, help="project directory (default: current)")
    o = ap.parse_args(argv)
    try:
        r = audit(project=o.project)
    except Exception as e:      # noqa: BLE001  a report, never a gate
        print("deus-witness audit: could not finish (%s)" % type(e).__name__)
        return 0
    print(json.dumps(r, indent=1, ensure_ascii=False) if o.json else render(r))
    return 0
