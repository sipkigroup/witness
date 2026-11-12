"""0.2.58 (FABLE-NOL 03.11 p.5.4): `deus-witness-hook --setup-strict` writes the strict Claude Code sandbox into the USER settings
(~/.claude/settings.json), with a backup and a printed diff; `--undo-strict` puts the backup back. Under the standing mandate the lines
the classifier cannot read (opaque: `$(...)`, eval, functions, interpreter code with a path not shown) are asked unless this sandbox holds
the call (server: hookjudge/sandbox.evaluate + allowances.code_cover, 0.2.82): macOS Seatbelt, no network but the allow-list, secrets
unreadable, no retry outside the sandbox. macOS only (sandbox.py).
0.2.60 (r0262): CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 is written into the USER settings' `env` too -- no `export` by hand any more. L2 12.11
(Claude Code 2.1.322, CLAUDE_CONFIG_DIR as the user layer, a SessionStart hook dumping its environment): from the user layer's `env` the
scrub IS on (a launch variable FAKE_DB_PASSWORD and CLAUDE_CONFIG_DIR are gone from the hook, the variable itself reaches the hook); from
the PROJECT layer it is not (the 0.2.57 b2 result, reproduced); a project's settings.local.json with "0" does not switch the user's "1" off.
Side effect, measured the same day: with the scrub on, `claude -p --permission-mode acceptEdits` prints "Permission mode forced to
default" (the hook sees permission_mode "default"); the witness then answers allow / ask itself, so Claude Code's own prompts appear only
for what the witness does not decide.
0.2.60 (r0262): `offer()` -- what `deus-witness try` and the session start say: one line on what quiet mode is, the change as a diff, how
to say yes. The switch itself is the person's: a terminal (`--setup-strict`, typed yes), or the agent's fixed line
`deus-witness-hook --setup-strict --yes`, which the witness ASKS the owner about (passkey, once; server bashparse QUIET_ON) and the hook
lets run only with the owner's approval (main.STRICT_SWITCH).
0.2.60 (r0263): NO scrub any more. Measured 12.11 (L3, interactive Claude Code 2.1.322 in tmux, scripted model): with the scrub in the
user `env`, a session whose defaultMode is acceptEdits starts in "manual mode" (forced to default); without it, "accept edits on". And the
scrub hid OPENAI_API_KEY, DB_PASSWORD & co. from every command (the person's tests broke). Instead `sandbox.credentials.envVars` (Claude
Code docs, sandboxing "Protect credentials": "environment variables are unset before each sandboxed command runs") hides by NAME only the
witness's agent key and the forge / registry tokens (HIDE_ENV); L2+ 12.11 (real Seatbelt, scripted model): a sandboxed `env` lacked
DEUS_WITNESS_KEY / GITHUB_TOKEN and kept OPENAI_API_KEY / DB_PASSWORD; `ps -E` of the parent: "Operation not permitted". The witness accepts
that as the strict fact (env_hidden). The person's own CLAUDE_CODE_SUBPROCESS_ENV_SCRUB, if any, is left as it is.
0.2.60 (r0263): the network list. `allowedDomains: []` made `npm install` / `pip install` / `git clone` fail on the first try; the offer now
lists DEFAULT_HOSTS (read hosts of GitHub, npm and PyPI, all narrow) in the same diff, under the same one yes; `--host NAME` adds the
person's own (narrow names only). A wide entry the person had (`*`, `*.com`, an IP) is dropped (shown in the diff): it ends the strict fact.
0.2.60 (r0263): the offer is not the first touch. `try` ends with ONE line (quiet mode exists, the command); the session-start hint comes
from the second session after the key was saved, at most once in 7 days, never after an explicit no (hint_due / declined)."""
from __future__ import annotations

import difflib
import re
import json
import os
import sys
import time

from . import sandbox_fact

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
# 12.11 (r0263): what quiet mode lists for the network (narrow host names): npm and PyPI downloads, GitHub's read hosts (tarballs, raw
# files, release assets) and github.com itself (`git fetch` / `git pull` of a public repository, `pip install git+https://github.com/...`,
# which clones into temp: L2+ 12.11 worked). NOT api.github.com, although the brief listed it: in quiet mode `gh` cannot log in (keychain
# and GH_TOKEN closed), so the host would let nothing work and is the one a stray token would publish to. github.com and
# registry.npmjs.org also take writes: the witness keeps code silent with them only while every credential source is closed (cred_closed:
# CRED_SOURCES, HIDE_ENV, cred_files) -- which this same change does. Measured cost (L2, friction stand, real corpus, 2 days, after day 1):
# empty list 7.8 questions a day, these 7 hosts 9.0, without github.com 8.6 (a write host in the list asks lines that hide a program and
# `gh` with a token in a folder not closed); dev corpus 0.23 either way. `git clone` / `git init` INTO the project fail in Claude Code's
# sandbox whatever the list (.git/config protected; L2+ 12.11) -- said in the offer.
DEFAULT_HOSTS = ["github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
                 "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
# 12.11 (r0263): hidden from sandboxed commands by name (sandbox.credentials.envVars, mode deny): the agent key, and the tokens that act
# on those hosts. Nothing else: OPENAI_API_KEY, DATABASE_URL, AWS_* stay for the person's tests (no listed host takes them).
HIDE_ENV = list(sandbox_fact.WITNESS_KEY_VARS) + list(sandbox_fact.FORGE_NAMES)
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


def hide_names(env=None) -> list:
    """HIDE_ENV + the names of variables in this environment whose VALUE has a forge / registry token shape (a GitHub token kept as
    MY_GH): hidden too. Names only; the order is stable."""
    e = os.environ if env is None else env
    extra = sorted(k for k, v in (e.items() if isinstance(e, dict) or hasattr(e, "items") else [])
                   if isinstance(k, str) and isinstance(v, str) and k not in HIDE_ENV and not k.startswith(("CLAUDE_", "DEUS_WITNESS_"))
                   and sandbox_fact.FORGE_SHAPE.search(v) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", k))
    return HIDE_ENV + extra[:32]


def strict_settings(cur: dict, hosts=(), env=None) -> dict:
    """The user settings with quiet mode. hosts: names to ADD to allowedDomains (the offer passes DEFAULT_HOSTS); the narrow names the
    person already listed are kept, a wide one is dropped."""
    out = json.loads(json.dumps(cur)) if isinstance(cur, dict) else {}
    sb = out.get("sandbox") if isinstance(out.get("sandbox"), dict) else {}
    for k in WEAKER:
        sb.pop(k, None)
    sb.update({k: v for k, v in BLOCK.items() if k not in ("network", "filesystem")})
    net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
    had = [x for x in (net.get("allowedDomains") or []) if isinstance(x, str)] if isinstance(net.get("allowedDomains"), list) else []
    net.update({k: v for k, v in BLOCK["network"].items() if k != "allowedDomains"})
    dom = [x for x in had if sandbox_fact.domain_narrow(x)]
    for h in hosts or ():
        if sandbox_fact.domain_narrow(h) and h not in dom:
            dom.append(h)
    net["allowedDomains"] = dom
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
    cr = sb.get("credentials") if isinstance(sb.get("credentials"), dict) else {}
    ev = [x for x in (cr.get("envVars") or []) if isinstance(x, dict)] if isinstance(cr.get("envVars"), list) else []
    named = {x.get("name") for x in ev if x.get("mode") in ("deny", "mask")}
    for n in hide_names(env):
        if n not in named:
            ev = [x for x in ev if x.get("name") != n] + [{"name": n, "mode": "deny"}]
    cr["envVars"] = ev
    sb["credentials"] = cr
    out["sandbox"] = sb
    env_ = out.get("env") if isinstance(out.get("env"), dict) else {}
    have = {k.lower() for k in env_}
    for k, v in tool_env().items():
        if k.lower() not in have:                     # the person's own value wins (npm reads NPM_CONFIG_CACHE too)
            env_[k] = v
    out["env"] = env_                                 # 0.2.60 (r0263): no CLAUDE_CODE_SUBPROCESS_ENV_SCRUB (see the module's note)
    return out


SCRUB = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"
QUIET_LINE = ("Quiet mode = Claude Code's own strict sandbox: commands run without network (except hosts you list) and cannot read your "
              "keys, keychain or browser cookies, so Witness only asks about what could leave this Mac or cannot be undone.")
NOT_MAC = ("Quiet mode is macOS only for now: Claude Code's sandbox also runs on Linux and WSL2 (bubblewrap + socat), but Witness has not "
           "measured it there, so it keeps asking as usual.")


def _platform(platform=None):
    p = platform or sys.platform
    if p.startswith("linux"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                return "wsl" if "microsoft" in f.read().lower() else "linux"
        except OSError:
            return "linux"
    return p


def _load(p):
    """-> (dict, None) | (None, why)"""
    try:
        cur = json.load(open(p)) if os.path.exists(p) else {}
    except ValueError as e:
        return None, "%s is not JSON (%s); fix it first" % (p, e)
    except OSError as e:
        return None, "cannot read %s (%s)" % (p, e.strerror or type(e).__name__)
    if not isinstance(cur, dict):
        return None, "%s is not an object" % p
    return cur, None


def _diff(p, cur, new):
    a = json.dumps(cur, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    b = json.dumps(new, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    return list(difflib.unified_diff(a, b, fromfile=p, tofile=p + " (strict)", lineterm=""))


def state(env=None, platform=None) -> str:
    """'on' (the user settings already hold what --setup-strict writes, hosts aside) | 'off' | 'not-mac' | 'unreadable'. Never raises."""
    try:
        if _platform(platform) != "darwin":
            return "not-mac"
        cur, why = _load(settings_path(env))
        if cur is None:
            return "unreadable"
        return "on" if strict_settings(cur, env=env) == cur else "off"
    except Exception:      # noqa: BLE001
        return "unreadable"


KEEPS = ("Your permission mode and your other environment variables (OPENAI_API_KEY, DATABASE_URL...) stay as they are; hidden from the "
         "agent's commands: your Witness key and GitHub / npm / PyPI tokens.")
LIMIT = ("In quiet mode a push or a publish the agent runs cannot use your login (keychain and tokens are closed to its commands): "
         "Witness asks, and you run it in your own terminal. `git clone` / `git init` inside the project fail there too (Claude Code's "
         "sandbox protects .git/config): run them in your terminal.")


def _hosts_line(cmd):
    return ("Network: the agent's commands reach only " + ", ".join(DEFAULT_HOSTS) + " (npm install and pip install work). "
            "Add your own host: %s --setup-strict --host example.com (in your terminal; a host name, no *)." % cmd)


def offer(env=None, platform=None, out=None, cmd="deus-witness-hook") -> str:
    """0.2.60 (r0262/r0263): print what quiet mode is and the exact change (a dry run); -> state(). The first line is machine-plain for
    /deus-witness:quiet: `QUIET MODE: on | offer | macOS only | cannot read settings`."""
    out = out or sys.stdout
    st = state(env, platform)
    if st == "not-mac":
        print("QUIET MODE: macOS only. " + NOT_MAC, file=out)
        return st
    p = settings_path(env)
    if st == "unreadable":
        print("QUIET MODE: cannot read settings (%s). Fix it, then: %s --setup-strict --dry-run" % (_load(p)[1] or p, cmd), file=out)
        return st
    if st == "on":
        print("QUIET MODE: on (%s already holds Claude Code's strict sandbox; undo: %s --undo-strict in your terminal)." % (p, cmd), file=out)
        return st
    cur = _load(p)[0]
    print("QUIET MODE: offer. " + QUIET_LINE, file=out)
    print(_hosts_line(cmd), file=out)
    print(KEEPS + " " + LIMIT, file=out)
    print("It changes %s (for all your projects; a backup is kept; undo: %s --undo-strict in your terminal):" % (p, cmd), file=out)
    print("\n".join(_diff(p, cur, strict_settings(cur, DEFAULT_HOSTS, env))), file=out)
    print("To turn it on: run `%s --setup-strict` in your terminal, or let the agent run `%s --setup-strict --yes`: Witness then asks "
          "YOU (passkey, this once); the agent cannot switch it on or off by itself. Not now: %s --quiet-no (no more reminders)."
          % (cmd, cmd, cmd), file=out)
    return st


def setup(env=None, write=True, platform=None, hosts=None, show=True) -> int:
    """hosts None = DEFAULT_HOSTS; extra names come from --host. show=False: the change was just shown (the terminal's yes), not again."""
    p = settings_path(env)
    if _platform(platform) != "darwin":
        print("deus-witness-hook --setup-strict: " + NOT_MAC + " Nothing changed.", file=sys.stderr)
        return 1
    cur, why = _load(p)
    if cur is None:
        print("deus-witness-hook --setup-strict: " + why, file=sys.stderr)
        return 1
    hs = list(DEFAULT_HOSTS if hosts is None else hosts)
    bad = [h for h in hs if not sandbox_fact.domain_narrow(h)]
    if bad:
        print("deus-witness-hook --setup-strict: not a narrow host name: %s (a name like example.com or api.example.com; no *, no IP, no "
              "port). Nothing changed." % ", ".join(bad[:3]), file=sys.stderr)
        return 1
    new = strict_settings(cur, hs, env)
    diff = _diff(p, cur, new)
    if not diff:
        print("already strict: %s" % p)
        return 0
    if show:
        print(QUIET_LINE)
        print(KEEPS + " " + LIMIT)
        print("\n".join(diff))
    if not write:
        return 0
    bak = "%s.bak-strict-%s" % (p, time.strftime("%Y%m%dT%H%M%S"))
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p):
            with open(p, "rb") as f, open(bak, "wb") as g:
                g.write(f.read())
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(new, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(p + ".tmp", p)
    except OSError as x:
        # 0.2.60: run by the agent inside a (not yet strict) Claude Code sandbox, the write is refused by the OS: said plainly
        print("deus-witness-hook --setup-strict: could not write %s (%s). If Claude Code's sandbox is already on, run "
              "`deus-witness-hook --setup-strict` in your own terminal. Nothing changed." % (p, x.strerror or type(x).__name__), file=sys.stderr)
        return 1
    print("written: %s (backup: %s; undo: deus-witness-hook --undo-strict)" % (p, bak if os.path.exists(bak) else "none, the file was new"))
    print("Quiet mode starts with your NEXT Claude Code session: /exit, then start claude again (the witness treats a session whose "
          "settings changed as not strict).")
    return 0


# ---- 0.2.60 (r0263): when the session-start reminder may show ------------------------------------------------------------------------
# One small file next to the agent key (never read by the witness): {"first": t, "shown": t, "declined": t}. The first session that sees
# the key only writes "first" (the person has not met a real question yet: the reminder would be the first thing Witness says); later
# sessions show the line at most once in HINT_EVERY; an explicit no (`--quiet-no`, a terminal answer other than yes, the owner's Reject of
# the agent's switch line) stops it for good (quiet mode is still one command away: /deus-witness:quiet).
HINT_FILE = "quiet-hint.json"
HINT_EVERY = 7 * 86400


def _hint_path(env=None):
    from ..trial import key_path
    return os.path.join(os.path.dirname(key_path(env)) or ".", HINT_FILE)


def _hint_load(env=None) -> dict:
    try:
        with open(_hint_path(env), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _hint_save(d, env=None) -> None:
    try:
        p = _hint_path(env)
        if not os.path.isdir(os.path.dirname(p)):
            return                                    # no key directory: nothing to remember (and nothing is made)
        with open(p + ".tmp", "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(p + ".tmp", p)
    except OSError:
        pass


def declined(env=None, now=None) -> None:
    d = _hint_load(env)
    d["declined"] = int(now if now is not None else time.time())
    _hint_save(d, env)


def hint_due(env=None, now=None) -> bool:
    """True = show the reminder now (and remember that it was shown). Never raises."""
    try:
        t = int(now if now is not None else time.time())
        d = _hint_load(env)
        if d.get("declined"):
            return False
        if not d.get("first"):
            d["first"] = t
            _hint_save(d, env)
            return False
        if isinstance(d.get("shown"), int) and t - d["shown"] < HINT_EVERY:
            return False
        d["shown"] = t
        _hint_save(d, env)
        return True
    except Exception:      # noqa: BLE001
        return False


def _key_file(env) -> bool:
    try:
        from ..trial import load_key
        return bool(load_key(env))
    except Exception:      # noqa: BLE001
        return False


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
