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
  sandbox.credentials.envVars[{name, mode}] (12.11, r0263: the names hidden from sandboxed commands -> env_hidden, env_tokens),
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
and the witness treats the fact as unknown. An MDM plist (macOS) is reported "unread".

0.2.56 client (server 0.2.88), freshness -- the fact must describe the settings Claude Code really runs with (fail closed):
  settings_digest  SHA-256 over every layer's status and its sandbox-relevant part (the whole `sandbox` object, the Read(...) deny rules,
                   the WebFetch(domain:) allow rules, permissions.additionalDirectories). Other permission rules ("Yes, don't ask again" for
                   a command or an MCP tool, which Claude Code writes into settings.local.json mid-session) do not change it. The witness
                   keeps the first digest of a session and treats the session as not strict from the first change on (until a new session).
  since_start      the layers whose file was modified after the session started (start = birth time of the session's transcript); the
                   witness uses it only for the FIRST fact it sees of a session. "session start unknown" when there is no readable
                   transcript birth time.
  doubt            reasons the fact cannot be collected unambiguously -> the witness never calls it strict: Claude Code started with
                   --settings / --setting-sources / --add-dir (read from the process's command line, `ps`; unreadable -> doubt), or settings
                   that let sandboxed code write outside the project (sandbox.filesystem.allowWrite, permissions.additionalDirectories)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
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


def _bool_or_none(v):
    return v if isinstance(v, bool) or v is None else True       # any other value: fail closed (counted as "allowed")


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


# 0.2.56 client: Claude Code command-line flags that change the settings the hook cannot see (code.claude.com/docs/en/cli-reference):
# --settings (a whole layer above project/user), --setting-sources (which layers are loaded at all), --add-dir (more writable directories).
CLI_FLAGS = ("--settings", "--setting-sources", "--add-dir")
ANCESTRY_OVERRIDE = None      # TESTS ONLY: [command line, ...] of the hook's ancestors, nearest first; "unreadable" = ps failed


def _ancestry():
    """-> the command lines of the hook's ancestor processes, nearest first (the hook's parent shell, Claude Code, ...), or None."""
    if ANCESTRY_OVERRIDE is not None:
        return None if ANCESTRY_OVERRIDE == "unreadable" else list(ANCESTRY_OVERRIDE)
    if os.name != "posix":
        return None
    ps = "/bin/ps" if os.path.exists("/bin/ps") else "ps"
    try:
        r = subprocess.run([ps, "-ww", "-A", "-o", "pid=,ppid=,args="], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if r.returncode != 0:
        return None
    tab = {}
    for line in r.stdout.splitlines():
        p = line.split(None, 2)
        if len(p) >= 2 and p[0].isdigit() and p[1].isdigit():
            tab[int(p[0])] = (int(p[1]), p[2] if len(p) > 2 else "")
    out, pid, seen = [], os.getppid(), set()
    while pid > 1 and pid in tab and pid not in seen and len(out) < 64:
        seen.add(pid)
        pid, args = tab[pid][0], tab[pid][1]
        out.append(args)
    return out or None


def _claude_like(args) -> bool:
    w = args.split()
    return bool(w) and (os.path.basename(w[0]).lower() == "claude" or (len(w) > 1 and os.path.basename(w[1]).lower() in ("claude", "cli.js")
                                                                      and "claude" in w[1].lower()) or "@anthropic-ai/claude-code" in w[0])


def cli_doubts(chain):
    """Flags of the Claude Code process (and of the processes between it and the hook) that the hook cannot read the effect of. The walk
    stops at the first process that looks like Claude Code; without one every ancestor counts (fail closed)."""
    if chain is None:
        return ["Claude Code's command line is not readable (ps): --settings / --setting-sources / --add-dir cannot be ruled out"]
    found = []
    for args in chain:
        for t in args.split():
            k = t.split("=", 1)[0]
            if k in CLI_FLAGS and k not in found:
                found.append(k)
        if _claude_like(args):
            break
    return ["Claude Code was started with %s: the hook cannot read what it sets" % f for f in found]


def _session_start(transcript):
    """Birth time of the session's transcript (Claude Code creates it when the session starts), or None."""
    if not isinstance(transcript, str) or not os.path.isabs(transcript):
        return None
    try:
        b = getattr(os.stat(transcript), "st_birthtime", None)
    except OSError:
        return None
    return b if isinstance(b, (int, float)) and b > 0 else None


def _relevant(d):
    """The part of one settings layer the sandbox fact depends on (see the module doc, settings_digest)."""
    if not isinstance(d, dict):
        return None
    p = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
    return {"sandbox": d.get("sandbox"),
            "deny": [r for r in _strs(p.get("deny")) if r.startswith("Read(")],
            "allow": [r for r in _strs(p.get("allow")) if r.startswith("WebFetch(")],
            "dirs": p.get("additionalDirectories")}


def settings_view(project, env, home, transcript=None):
    """0.2.56 client: -> (layers, {"settings_digest", "since_start"}) -- also sent with every non-Bash call (facts.settings), so that the
    witness has the session's first view before the first Bash call."""
    paths = []
    L = layers(project, env, home, transcript, paths)
    raw = json.dumps([[n, st, _relevant(d)] for n, st, d in L], sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    start = _session_start(transcript)
    since = []
    if start is None:
        since = ["session start unknown"]
    else:
        for n, p in paths:
            try:
                if os.stat(p).st_mtime > start and n not in since:
                    since.append(n)
            except OSError:
                pass
    return L, {"settings_digest": hashlib.sha256(raw.encode()).hexdigest(), "since_start": since[:MAX_LIST]}


def layers(project, env, home, transcript=None, paths=None):
    """[(name, status, dict)] highest precedence first.
    0.2.56: CLAUDE_CODE_SUBPROCESS_ENV_SCRUB removes CLAUDE_CONFIG_DIR from the hook's environment (env-vars, "What the subprocess
    environment scrub removes"), so the hook may not see where Claude Code keeps the user settings. The event's transcript_path names the
    directory Claude Code really uses: when it is not the one read here, the user layer is reported "unread" (the witness then asks)."""
    out = []
    paths = [] if paths is None else paths           # 0.2.56 client: (layer, file) of every file read, for since_start

    def load(n, p):
        paths.append((n, p))
        return _load(p)
    for p in reversed(failsafe.managed_files()):
        st, d = load("managed", p)
        if st != "absent":
            out.append(("managed", st, d))
    for p in MDM_PLISTS:
        if failsafe.MANAGED_DIR_OVERRIDE is None and os.path.exists(p):
            out.append(("managed-mdm", "unread", None))
    if project:
        root = _git_root(project)
        if root and root != project:                  # Claude Code 2.1.211+: the local file lives at the repository root (and an older one
            st, d = load("local-root", os.path.join(root, ".claude", "settings.local.json"))   # in the starting directory is read too; root wins)
            out.append(("local-root", st, d))
        for n, f in (("local", "settings.local.json"), ("project", "settings.json")):
            st, d = load(n, os.path.join(project, ".claude", f))
            out.append((n, st, d))
    cfg = env.get("CLAUDE_CONFIG_DIR")
    udir = cfg if cfg and os.path.isabs(cfg) else os.path.join(home, ".claude")
    real = _transcript_config_dir(transcript)
    if real is not None and os.path.realpath(real) != os.path.realpath(udir):
        out.append(("user", "unread", None))          # the user settings live elsewhere ($CLAUDE_CONFIG_DIR hidden from the hook)
        return out
    st, d = load("user", os.path.join(udir, "settings.json"))
    out.append(("user", st, d))
    return out


# 10.11 (r0260, decision Р-1011-сеть-в-строгой): the NAMES (never the values) of the variables in the hook's environment that let a program
# publish or act as the user on a service: with a non-empty allowedDomains the witness keeps the strict fact only when there is none
# (code in the sandbox -- a test, `npm run release` -- could otherwise publish to a listed registry with it, and the line would not show
# it). The hook runs with the same scrubbed environment as the Bash tool (CLAUDE_CODE_SUBPROCESS_ENV_SCRUB covers hooks too).
TOKEN_NAMES = {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN",
               "YARN_NPM_AUTH_TOKEN", "TWINE_PASSWORD", "TWINE_USERNAME", "PYPI_TOKEN", "PYPI_API_TOKEN", "UV_PUBLISH_TOKEN",
               "UV_PUBLISH_PASSWORD", "CARGO_REGISTRY_TOKEN", "GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN", "HF_TOKEN",
               "HUGGING_FACE_HUB_TOKEN", "DOCKER_PASSWORD", "DOCKERHUB_TOKEN", "GEM_HOST_API_KEY", "NUGET_API_KEY", "VSCE_PAT", "OVSX_PAT"}
TOKEN_RX = re.compile(r"^(?:POETRY_PYPI_TOKEN_\w+|POETRY_HTTP_BASIC_\w+_PASSWORD|[A-Z0-9_]*(?:_TOKEN|_PASSWORD|_PASSWD|_SECRET|_API_KEY|_APIKEY"
                      r"|_ACCESS_KEY|_AUTH|_PAT))$")
TOKEN_NOT = {"TOKENIZERS_PARALLELISM", "DEUS_WITNESS_KEY"}
TOKEN_NOT_PREFIX = ("CLAUDE_", "DEUS_WITNESS_")       # Claude Code's own session variables (CLAUDE_CODE_MESSAGING_TOKEN) and the hook's key:
#                                                       not a credential of a registry / forge a listed domain could take


# 12.11 (r0263): forge / registry hosts whose credentials have a KNOWN name (TOKEN_NAMES) or a KNOWN value shape (FORGE_SHAPE). While every
# listed host is one of them, a variable counts only by that name or shape: OPENAI_API_KEY, DB_PASSWORD, ANTHROPIC_API_KEY open nothing on
# github.com / npm / PyPI, so they no longer make the person's quiet mode loud (with the scrub gone, the hook sees them, L2+ 12.11). A host
# outside this family listed: any credential-like NAME counts, as before (its credential may be called anything).
FORGE_HOSTS = frozenset({"github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
                         "uploads.github.com", "gist.github.com", "ghcr.io", "npm.pkg.github.com", "gitlab.com", "registry.gitlab.com",
                         "bitbucket.org", "api.bitbucket.org", "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org",
                         "files.pythonhosted.org", "upload.pypi.org", "test.pypi.org", "crates.io", "index.crates.io", "static.crates.io",
                         "rubygems.org", "proxy.golang.org", "sum.golang.org"})
FORGE_SHAPE = re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}"
                         r"|gl(?:pat|dt|rt|ptt|ft|cbt|oas)-[A-Za-z0-9_-]{15,}|ATBB[A-Za-z0-9]{20,}|cio[A-Za-z0-9]{28,}|rubygems_[0-9a-f]{20,})")
# the names of TOKEN_NAMES whose credential works on a FORGE_HOSTS host (HF_TOKEN, DOCKER_PASSWORD, NUGET_API_KEY... do not)
FORGE_NAMES = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN",
               "YARN_NPM_AUTH_TOKEN", "TWINE_PASSWORD", "TWINE_USERNAME", "PYPI_TOKEN", "PYPI_API_TOKEN", "UV_PUBLISH_TOKEN",
               "UV_PUBLISH_PASSWORD", "CARGO_REGISTRY_TOKEN", "GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN", "GEM_HOST_API_KEY")
_OLD_SHAPE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")   # classic GitHub PAT, legacy npm


def env_denied(L) -> list:
    """12.11 (r0263): the variable names `sandbox.credentials.envVars` hides from sandboxed commands, from every readable layer ("a deny
    entry only ever narrows access, so any scope can add one"); `mask` also keeps the value out (the command sees a sentinel)."""
    out = []
    for _, st, d in L:
        if st != "ok":
            continue
        for c in _get(d, "sandbox", "credentials", "envVars") or []:
            if isinstance(c, dict) and c.get("mode") in ("deny", "mask") and isinstance(c.get("name"), str) and c["name"] not in out:
                out.append(c["name"])
    return out[:MAX_LIST * 4]


def env_tokens(env, domains=None, denied=()) -> list:
    """The NAMES of the variables sandboxed code sees (not hidden by sandbox.credentials.envVars) that could act as the person on a listed
    host. domains None (a caller before r0263): every credential-like name, as before."""
    e = env if isinstance(env, dict) else {}
    dn = set(denied or ())
    forge_only = isinstance(domains, list) and bool(domains) and all(isinstance(d, str) and d.strip().lower().rstrip(".") in FORGE_HOSTS for d in domains)
    out = []
    for k, v in e.items():
        if not (isinstance(k, str) and isinstance(v, str) and v.strip()) or k in TOKEN_NOT or k.startswith(TOKEN_NOT_PREFIX) or k in dn:
            continue
        named = k in TOKEN_NAMES or TOKEN_RX.match(k)
        if forge_only:
            named = k in FORGE_NAMES or k.startswith(("POETRY_PYPI_TOKEN_", "POETRY_HTTP_BASIC_")) or FORGE_SHAPE.search(v) or (TOKEN_RX.match(k) and _OLD_SHAPE.match(v.strip()))
        if named:
            out.append(k)
    return sorted(out)[:64]


# 12.11 (r0263): the variables that carry the witness's own agent key into Claude Code (DEUS_WITNESS_KEY; the plugin option agent_key).
WITNESS_KEY_VARS = ("DEUS_WITNESS_KEY", "CLAUDE_PLUGIN_OPTION_AGENT_KEY")


def env_hidden(env, denied) -> bool:
    """12.11 (r0263): the agent key is not in the environment sandboxed commands get: absent, or hidden by sandbox.credentials.envVars
    (L2+ 12.11, Claude Code 2.1.322, real Seatbelt, scripted model: `env` in a sandboxed Bash call did not show DEUS_WITNESS_KEY /
    GITHUB_TOKEN listed as deny, and showed OPENAI_API_KEY / DB_PASSWORD not listed; `ps -E` of the parent: "Operation not permitted")."""
    e = env if isinstance(env, dict) else {}
    dn = set(denied or ())
    return all(not (isinstance(e.get(k), str) and e[k].strip()) or k in dn for k in WITNESS_KEY_VARS)


# ---- 11.11 (r0260): credentials in config files the sandbox must keep READABLE (git, npm and yarn read them on every run) ---------------
# Reported by NAME (never a value): a git config with a URL that carries a credential (`https://<token>@github.com`, insteadOf, a remote
# url), an http.extraHeader (actions/checkout leaves one in .git/config), a credential helper other than the keychain / the default
# store / the cache (a `!shell` helper, `store --file x`, GCM with a store outside its default); an auth token in the project's .npmrc /
# .yarnrc.yml / .pypirc, in ~/.yarnrc.yml or in a system npmrc. Any of them = the person's credential reachable by code in the sandbox ->
# the witness keeps 87facd5 (lines that run code are asked while a write host is listed). An existing file that cannot be read: reported.
SYSTEM_GITCONFIGS = ("/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig",
                     "/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig",
                     "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig")
SYSTEM_NPMRCS = ("/opt/homebrew/etc/npmrc", "/usr/local/etc/npmrc", "/etc/npmrc")
_URL_CRED = re.compile(r"(?i)\bhttps?://[^/\s@\"'\]]+@")
_GIT_SECTION = re.compile(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\](.*)$')
_HELPERS_OK = {"osxkeychain", "store", "cache", "manager", "manager-core", "git-credential-manager"}
_NPM_TOKEN = re.compile(r"(?im)^\s*[^#;\n]*(?:_authToken|_auth|_password)\s*=")
_YARN_TOKEN = re.compile(r"(?m)^\s*(?:npmAuthToken|npmAuthIdent)\s*:")
_PYPIRC_PW = re.compile(r"(?im)^\s*password\s*[=:]")


def _read_small(path):
    """-> text | None (absent) | False (exists, unreadable)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(1 << 20)
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        return None
    except OSError:
        return False


def _gitcfg_scan(path, label, home, out, depth=0):
    t = _read_small(path)
    if t is None:
        return
    if t is False:
        out.append(label + ": unreadable")
        return
    sec, helpers, found = "", [], []
    for raw in t.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = _GIT_SECTION.match(line)
        if m:
            sec = m.group(1).lower()
            if m.group(2) is not None and _URL_CRED.search(m.group(2)):
                found.append("a URL with a credential")
            line = m.group(3).strip()
            if not line:
                continue
        k, eq, v = line.partition("=")
        k, v = k.strip().lower(), v.split(" #")[0].split(" ;")[0].strip().strip('"') if eq else ""
        if _URL_CRED.search(v):
            found.append("a URL with a credential")
        if k == "extraheader" and sec == "http":
            found.append("http.extraHeader")
        if sec == "credential" and k == "helper":
            if not v:
                helpers = []
            else:
                helpers.append(v)
        if sec == "credential" and k in ("credentialstore", "plaintextstorepath", "gpgpasspath") and \
                not (k == "credentialstore" and v.lower() in ("keychain", "cache", "plaintext", "")):
            found.append("credential.%s" % k)
        if sec in ("include", "includeif") and k == "path" and v and depth < 5:
            q = home + v[1:] if v == "~" or v.startswith("~/") else (v if v.startswith("/") else os.path.join(os.path.dirname(path), v))
            q = os.path.normpath(q)
            lab = "~" + q[len(home):] if q.startswith(home + "/") else q
            _gitcfg_scan(q, lab, home, out, depth + 1)
    for h in helpers:
        w = h.split()
        if not w or w[0].startswith(("!", "/")) or w[0] not in _HELPERS_OK or (w[0] == "store" and len(w) > 1):
            found.append("credential.helper")
            break
    for x in dict.fromkeys(found):
        out.append("%s: %s" % (label, x))


def _git_common_config(root):
    """<root>/.git/config, or for a worktree (`.git` is a file `gitdir: X`) the common dir's config."""
    g = os.path.join(root, ".git")
    if os.path.isdir(g):
        return os.path.join(g, "config")
    t = _read_small(g)
    if not isinstance(t, str) or not t.startswith("gitdir:"):
        return None
    gd = t[7:].strip()
    gd = gd if os.path.isabs(gd) else os.path.normpath(os.path.join(root, gd))
    cd = _read_small(os.path.join(gd, "commondir"))
    if isinstance(cd, str) and cd.strip():
        c = cd.strip()
        gd = c if os.path.isabs(c) else os.path.normpath(os.path.join(gd, c))
    return os.path.join(gd, "config")


def cred_files(project, home, env=None) -> list:
    e = env if isinstance(env, dict) else {}
    out = []

    def lab(p):
        return "~" + p[len(home):] if home and p.startswith(home + "/") else p
    try:
        for p in SYSTEM_GITCONFIGS:
            _gitcfg_scan(p, p, home, out)
        glob_ = e.get("GIT_CONFIG_GLOBAL")
        xdg = e.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        for p in ([glob_] if glob_ else [os.path.join(home, ".gitconfig")]) + [os.path.join(xdg, "git", "config")]:
            _gitcfg_scan(p, lab(p), home, out)
        roots = []
        if project:
            for r in (project, _git_root(project)):
                if r and r not in roots:
                    roots.append(r)
        if roots and roots[-1]:
            gc = _git_common_config(roots[-1])
            if gc:
                _gitcfg_scan(gc, ".git/config", home, out)
        # 11.11 (real #1037: `GH_CONFIG_DIR=~/.claude/state/gh gh repo view`): gh pointed elsewhere by the hook's environment keeps its
        # token outside ~/.config/gh (SECRETS): reported when that hosts.yml holds one
        for var, d in (("GH_CONFIG_DIR", e.get("GH_CONFIG_DIR")), ("XDG_CONFIG_HOME", os.path.join(e["XDG_CONFIG_HOME"], "gh")
                                                                   if e.get("XDG_CONFIG_HOME") else None)):
            if d and os.path.isabs(d) and os.path.normpath(d) != os.path.join(home, ".config", "gh"):
                t = _read_small(os.path.join(d, "hosts.yml"))
                if t is False:
                    out.append("%s: unreadable" % var)
                elif isinstance(t, str) and re.search(r"(?m)^\s*oauth_token\s*:", t):
                    out.append("%s: a gh token" % var)
        for p, rx, what in [(os.path.join(home, ".yarnrc.yml"), _YARN_TOKEN, "an auth token")] + \
                [(p, _NPM_TOKEN, "an auth token") for p in SYSTEM_NPMRCS] + \
                [(os.path.join(r, n), rx_, "an auth token") for r in roots
                 for n, rx_ in ((".npmrc", _NPM_TOKEN), (".yarnrc.yml", _YARN_TOKEN), (".pypirc", _PYPIRC_PW))]:
            t = _read_small(p)
            name = lab(p) if not any(p.startswith(r + "/") for r in roots) else os.path.basename(p)
            if t is False:
                out.append(name + ": unreadable")
            elif isinstance(t, str) and rx.search(t):
                out.append("%s: %s" % (name, what))
    except Exception as x:      # noqa: BLE001  fail closed: the witness then keeps 87facd5
        out.append("not known: %s" % type(x).__name__)
    return list(dict.fromkeys(out))[:MAX_LIST]


def fact(tool_input, project, env=None, home=None, platform=None, transcript=None, permission_mode=None) -> dict:
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    L, fresh = settings_view(project, env, home, transcript)
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
    denv = env_denied(L)                              # 12.11 (r0263): sandbox.credentials.envVars deny / mask
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
    # 10.11 (r0260, Р-1011-сеть-в-строгой): the hosts the PERSON listed -- the user and managed layers only. A project / local layer is
    # the repository's file (a cloned repository can ship .claude/settings.json): a host it adds is not the person's consent.
    domains_user = []
    for d in lock_layers:
        for x in _strs(_get(d, "sandbox", "network", "allowedDomains")) + \
                [r[len("WebFetch(domain:"):-1] for r in _strs(_get(d, "permissions", "allow")) if r.startswith("WebFetch(domain:") and r.endswith(")")]:
            if x not in domains_user:
                domains_user.append(x)
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
    # 0.2.56 client: what the hook cannot see or what breaks the "no write outside the project" premise -> doubt (never strict)
    doubt = cli_doubts(_ancestry())
    if any(_get(d, "sandbox", "filesystem", "allowWrite") not in (None, []) for d in ok):
        doubt.append("sandbox.filesystem.allowWrite is set: sandboxed code may write outside the project")
    if any(_get(d, "permissions", "additionalDirectories") not in (None, []) for d in ok):
        doubt.append("permissions.additionalDirectories is set: sandboxed code may write outside the project")
    return {
        "v": 1, "platform": plat,
        "sources": dict({n: st for n, st, _ in L}, **{"relative-" + n: "unread" for n in unknown}),
        "enabled": scalar("sandbox", "enabled"),
        "fail_if_unavailable": scalar("sandbox", "failIfUnavailable"),
        "allow_unsandboxed": scalar("sandbox", "allowUnsandboxedCommands"),
        "excluded": union("sandbox", "excludedCommands")[:MAX_LIST],
        "ignore_violations": bool(scalar("sandbox", "ignoreViolations")),
        "fs_disabled": scalar("sandbox", "filesystem", "disabled"),
        # 06.11 (r0260): Claude Code's sandbox refuses writes to .git/config unless this is true (runtime: "Enables git remote URL
        # updates while keeping .git/hooks protected"); true = core.hooksPath / filters writable from the sandbox -> the witness: not strict
        "allow_git_config": _bool_or_none(scalar("sandbox", "filesystem", "allowGitConfig")),
        "deny_read": [x for x in deny if x][:MAX_LIST],
        "allow_read": [x for x in allow if x][:MAX_LIST],
        "domains": domains[:MAX_LIST],
        "domains_user": domains_user[:MAX_LIST],
        "unix_sockets": union("sandbox", "network", "allowUnixSockets")[:MAX_LIST],
        "all_unix_sockets": scalar("sandbox", "network", "allowAllUnixSockets"),
        "mach_lookup": union("sandbox", "network", "allowMachLookup")[:MAX_LIST],
        "local_binding": scalar("sandbox", "network", "allowLocalBinding"),
        "weaker": [k for k in WEAKER if scalar("sandbox", k) is True],
        "env_scrub": str(scrub).strip().lower() in ("1", "true", "yes"),
        "env_hidden": env_hidden(env, denv),             # 12.11 (r0263): the agent key out of sandboxed commands without the scrub
        "disable_flag": ti.get("dangerouslyDisableSandbox") not in (None, False),   # any other value: fail closed
        "env_files": envf,
        "env_tokens": env_tokens(env, domains[:MAX_LIST], denv),
        "cred_files": cred_files(project, home, env),    # 11.11 (r0260): names only
        "strict_allowlist": strict_allow if isinstance(strict_allow, bool) else None,
        "managed_domains_only": managed_only,
        "permission_mode": permission_mode[:32] if isinstance(permission_mode, str) and permission_mode else None,
        "settings_digest": fresh["settings_digest"], "since_start": fresh["since_start"], "doubt": doubt[:MAX_LIST],
    }


# ---- 0.2.58b (L3 04.11): `--doctor` says whether the sandbox is strict for a folder -------------------------------------------------
# The witness (server/app/hookjudge/sandbox.py:evaluate) decides "strict" from this very fact; the client has no copy of the server, so this
# is a SHORT mirror of its conditions, for the doctor's one line only. It never allows anything: the hook still sends the fact and the
# witness decides. Where the mirror and the server could differ, the line says NOT strict (fail closed in the words).
SECRETS = (".ssh", ".aws", ".config/gh", ".netrc", ".docker", ".kube", ".gnupg", ".npmrc", ".pypirc", ".git-credentials",
           ".config/gcloud", ".azure", ".config/deus-witness", ".claude.json", ".claude/.credentials.json")
# 11.11 (r0260) = server hookjudge/sandbox.CRED_SOURCES (the reasons are there): where code would find a credential to act in the person's
# name -- the login keychain (L2 10.11: denied -> `security` finds nothing), the browsers' cookie stores, the editors' token stores, CLI
# files. --setup-strict writes them into denyRead; the witness lets a write host of allowedDomains keep the strict fact for code only
# when every one is denied and cred_files (below) is empty.
CRED_SOURCES = ("Library/Keychains", "Library/Cookies", "Library/HTTPStorages", "Library/Safari", "Library/Containers/com.apple.Safari",
                "Library/Application Support/Google/Chrome", "Library/Application Support/BraveSoftware",
                "Library/Application Support/Microsoft Edge", "Library/Application Support/Arc", "Library/Application Support/Chromium",
                "Library/Application Support/Vivaldi", "Library/Application Support/com.operasoftware.Opera",
                "Library/Application Support/Firefox", "Library/Application Support/Code/User/globalStorage",
                "Library/Application Support/Cursor/User/globalStorage", ".config/hub", ".config/glab-cli",
                "Library/Application Support/glab-cli", ".config/git/credentials", ".gcm", ".cargo/credentials", ".cargo/credentials.toml",
                ".gem/credentials", "Library/Application Support/pypoetry/auth.toml")


def _covered(entry, path):
    return isinstance(entry, str) and entry.startswith("/") and (path == entry.rstrip("/") or path.startswith(entry.rstrip("/") + "/"))


_DOMAIN = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
LOCAL_TLDS = {"local", "localhost", "internal", "lan", "home", "arpa", "localdomain", "test", "invalid", "example", "onion", "corp", "intranet"}


def domain_narrow(d) -> bool:
    """= server hookjudge/sandbox.domain_narrow: a host name with a registrable part; not `*`, a bare TLD, an IP, a local name."""
    if not isinstance(d, str) or len(d) > 253 or not _DOMAIN.fullmatch(d.lower()):
        return False
    labels = d.lower().split(".")
    return labels[-1] not in LOCAL_TLDS and len([x for x in labels if x != "*"]) >= 2


# 10.11 (r0260) = server hookjudge/sandbox.READ_ONLY_HOSTS: hosts known to take no write in the person's name. Any other listed host is a
# WRITE host: the login keychain is readable from the sandbox (L2 10.11), so code there could push / publish with git's or gh's credential;
# the witness then asks about lines that run code (the server decides; this is the doctor's words).
READ_ONLY_HOSTS = frozenset({"codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com", "files.pythonhosted.org",
                             "pypi.org", "proxy.golang.org", "sum.golang.org", "index.crates.io", "static.crates.io"})


def write_hosts(domains) -> list:
    out = []
    for d in domains if isinstance(domains, list) else []:
        h = d.strip().lower().rstrip(".") if isinstance(d, str) else ""
        if h and h not in READ_ONLY_HOSTS and h not in out:
            out.append(h)
    return out


def strict_reasons(f, home) -> list:
    """Every unmet condition (empty list = strict as far as the client can tell)."""
    why = []
    if not isinstance(f, dict):
        return ["no sandbox fact"]
    if f.get("platform") != "darwin":
        why.append("platform %s: only macOS is accepted" % f.get("platform"))
    bad = sorted(k for k, v in (f.get("sources") or {}).items() if v not in ("ok", "absent"))
    if bad:
        why.append("settings not readable: " + ", ".join(bad))
    if f.get("enabled") is not True:
        why.append("sandbox.enabled is not true")
    if f.get("fail_if_unavailable") is not True:
        why.append("sandbox.failIfUnavailable is not true")
    if f.get("fs_disabled") is True:
        why.append("sandbox.filesystem.disabled")
    if f.get("allow_git_config") is True:
        why.append("sandbox.filesystem.allowGitConfig")
    if f.get("ignore_violations"):
        why.append("sandbox.ignoreViolations")
    if f.get("weaker"):
        why.append("weakening keys: " + ", ".join(f["weaker"]))
    for d in (f.get("doubt") or [])[:4]:
        why.append("not known: " + str(d)[:160])
    if f.get("allow_unsandboxed") is not False:
        why.append("sandbox.allowUnsandboxedCommands is not false")
    if f.get("excluded"):
        why.append("sandbox.excludedCommands is not empty")
    if f.get("domains"):
        # 10.11 (r0260, Р-1011-сеть-в-строгой): a narrow list keeps the sandbox strict (the server's hookjudge/sandbox.evaluate decides)
        if not all(domain_narrow(x) for x in f["domains"]):
            why.append("network: allowedDomains has a wide entry")
        if not isinstance(f.get("domains_user"), list) or not set(f["domains"]) <= set(f["domains_user"]):
            why.append("network: allowedDomains names a host the project's settings added")
        if f.get("env_tokens") != []:
            why.append("network: allowedDomains listed while the environment carries a publishing token")
    if f.get("unix_sockets") or f.get("all_unix_sockets") is True:
        why.append("network: Unix sockets allowed")
    if f.get("local_binding") is True:
        why.append("network: allowLocalBinding")
    if f.get("mach_lookup"):
        why.append("network: allowMachLookup")
    if f.get("strict_allowlist") is not True and f.get("managed_domains_only") is not True:
        why.append("network: sandbox.network.strictAllowlist is not true in user or managed settings")
    if not f.get("env_scrub") and f.get("env_hidden") is not True:
        why.append("the agent key is visible to commands (DEUS_WITNESS_KEY in the environment, not in sandbox.credentials.envVars): "
                   "run deus-witness-hook --setup-strict again")
    if not isinstance(home, str) or not home.startswith("/") or home == "/":
        why.append("home unknown")
    else:
        deny, allow = f.get("deny_read") or [], f.get("allow_read") or []
        miss = [s for s in SECRETS if not any(_covered(e, os.path.join(home, s)) for e in deny)
                or any(_covered(a, os.path.join(home, s)) or _covered(os.path.join(home, s), a) for a in allow)]
        if miss:
            why.append("denyRead does not cover ~/" + ", ~/".join(miss[:6]) + (" ..." if len(miss) > 6 else ""))
    return why


def strict_line(project, env=None, home=None, platform=None) -> str:
    """`sandbox: strict` / `sandbox: NOT strict (reason; ...)` for the doctor. Never raises."""
    try:
        f = fact({}, os.path.realpath(project) if project else None, env=env, home=home, platform=platform)
        why = strict_reasons(f, home or os.path.expanduser("~"))
    except Exception as e:      # noqa: BLE001
        return "sandbox: NOT strict (cannot tell: %s)" % type(e).__name__
    if not why:
        wh = write_hosts(f.get("domains"))
        if wh:
            h_ = home or os.path.expanduser("~")
            deny, allow = f.get("deny_read") or [], f.get("allow_read") or []
            open_ = [s for s in SECRETS + CRED_SOURCES if not any(_covered(e, os.path.join(h_, s)) for e in deny)
                     or any(_covered(a, os.path.join(h_, s)) or _covered(os.path.join(h_, s), a) for a in allow)]
            cf = f.get("cred_files")
            if not open_ and cf == []:
                return ("sandbox: strict (client estimate); allowedDomains has %s: your keychain, browser cookies and credential files "
                        "are closed to code, so only commands that name such a host or publish are asked" % ", ".join(wh[:4]))
            return ("sandbox: strict (client estimate), but allowedDomains has %s: code in the sandbox can read your login keychain and "
                    "could publish there in your name, so commands that run code are asked (%s)" % (
                        ", ".join(wh[:4]), ("credential in " + ", ".join(cf[:2])) if cf else
                        "close the sources: deus-witness-hook --setup-strict"))
        return "sandbox: strict (client estimate; the witness decides for each call by the permission mode and the command)"
    return "sandbox: NOT strict (%s)" % "; ".join(why[:6])
