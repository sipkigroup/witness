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
from the second session after the key was saved, at most once in 7 days, never after an explicit no (hint_due / declined).
0.2.64 (r0266): permissions.deny "Read(...)" for the places with keys that `deus-witness audit` names (READ_DENY). L3 12.11 (Claude Code
2.1.323, fake key in a scratch folder): the Read tool does NOT honour sandbox.filesystem.denyRead (it read a file the sandbox denied to
`cat`), a Read deny rule does stop it -- and Claude Code applies that rule to sandboxed commands too, so it adds nothing commands could
read before (every path below is already in denyRead). `--undo-strict` takes out exactly these rules (READ_DENY minus the ones the
backup had) and keeps any rule the person added since; the rest of the file comes back from the backup as before. No rule for the
project's .env: it would also close .env to sandboxed commands (L3 above) and break tests that load it.
r0268 (13.11): Linux and WSL2. Claude Code's sandbox there is bubblewrap + socat + its seccomp filter (no AF_UNIX sockets); L3 13.11 on
Azure (Debian 12, Claude Code 2.1.323) gave the same four properties as Seatbelt (writes only in the project and /tmp/claude-<uid>,
~/.ssh closed, network only to the listed hosts, python / git work) and "Seccomp: 2" + EPERM on socket(AF_UNIX) inside. --setup-strict
checks first (preflight): bwrap and socat on PATH (else: the apt / dnf line, nothing written -- with failIfUnavailable a missing bwrap
would stop every command), a bubblewrap start like Claude Code's (Ubuntu 24.04's kernel.apparmor_restrict_unprivileged_userns, a
container that cannot mount /proc), the architecture (the filter exists for x86_64 / arm64), WSL1 (Claude Code refuses it) and, on WSL2,
Windows interop (a .exe runs outside the Linux sandbox). The paths are Linux ones (CRED_SOURCES_LINUX, /tmp/claude-<uid>, the Windows
homes under /mnt on WSL2). `--weaker-nested` writes sandbox.enableWeakerNestedSandbox (for a container without /proc): an explicit
weakening -- sandboxed commands then see every process of the machine -- that the witness does not count as quiet mode."""
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
# 13.11 (r0268): Linux and WSL2 (see the module's note)
LINUX_FAMILY = ("linux", "wsl2")
CRED_SOURCES_LINUX = list(sandbox_fact.CRED_SOURCES_LINUX)
WIN_SECRETS = list(sandbox_fact.WIN_SECRETS)
# 0.2.64 (r0266): the Read tool's own lock on the places with keys = audit.SECRETS (a test keeps the two equal). Folders get /**.
READ_SECRET_DIRS = [".ssh", ".aws", "Library/Keychains", ".config/gh", ".kube", ".gnupg", ".config/gcloud", ".azure"]
READ_SECRET_FILES = [".netrc", ".docker/config.json", ".npmrc", ".pypirc", ".git-credentials"]
READ_DENY = ["Read(~/%s/**)" % x for x in READ_SECRET_DIRS] + ["Read(~/%s)" % x for x in READ_SECRET_FILES]
# 13.11 (r0268): on Linux the keychain's place is the GNOME keyring's folder
READ_DENY_LINUX = [r.replace("Library/Keychains", ".local/share/keyrings") for r in READ_DENY]
READ_DENY_ALL = READ_DENY + [r for r in READ_DENY_LINUX if r not in READ_DENY]


def read_deny(plat="darwin") -> list:
    return READ_DENY_LINUX if plat in LINUX_FAMILY else READ_DENY
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
def tool_env(uid=None, plat="darwin"):
    """13.11 (r0268): Linux / WSL2 -- Claude Code's temp root is /tmp/claude-<uid> (L3 13.11: the one place under /tmp a sandboxed command
    could write), and no PIP_USE_DEPRECATED (pip's truststore there reads the system CA files, no Mach service to be denied)."""
    u = os.getuid() if uid is None and hasattr(os, "getuid") else (uid or 0)
    if plat in LINUX_FAMILY:
        root = "/tmp/claude-%d" % u
        return {"npm_config_cache": root + "/npm-cache", "UV_CACHE_DIR": root + "/uv-cache", "GIT_TEMPLATE_DIR": ""}
    root = "/private/tmp/claude-%d" % u
    return {"npm_config_cache": root + "/npm-cache", "UV_CACHE_DIR": root + "/uv-cache", "PIP_USE_DEPRECATED": "legacy-certs",
            "GIT_TEMPLATE_DIR": ""}


def deny_list(plat="darwin", homes=None) -> list:
    """denyRead of quiet mode for this system: SECRETS + the credential places (macOS or Linux); WSL2: + each Windows home's WIN_SECRETS."""
    if plat in LINUX_FAMILY:
        out = ["~/" + x for x in SECRETS + CRED_SOURCES_LINUX]
        for h in (homes or []) if plat == "wsl2" else []:
            out += [h.rstrip("/") + "/" + x for x in WIN_SECRETS]
        return out
    return ["~/" + x for x in SECRETS + CRED_SOURCES]


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


def strict_settings(cur: dict, hosts=(), env=None, plat="darwin", weaker=False, homes=None) -> dict:
    """The user settings with quiet mode. hosts: names to ADD to allowedDomains (the offer passes DEFAULT_HOSTS); the narrow names the
    person already listed are kept, a wide one is dropped. plat (r0268): darwin | linux | wsl2 -- the paths of that system; weaker: Linux
    only, the person's explicit --weaker-nested (sandbox.enableWeakerNestedSandbox); homes: WSL2's Windows homes (sandbox_fact.win_homes)."""
    out = json.loads(json.dumps(cur)) if isinstance(cur, dict) else {}
    sb = out.get("sandbox") if isinstance(out.get("sandbox"), dict) else {}
    for k in WEAKER:
        sb.pop(k, None)
    if weaker and plat in LINUX_FAMILY:
        sb["enableWeakerNestedSandbox"] = True        # r0268: asked for by name; the witness does not count it as strict
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
    want = deny_list(plat, homes)
    fs["denyRead"] = deny + [x for x in want if x not in deny]
    srcs = CRED_SOURCES_LINUX + WIN_SECRETS if plat in LINUX_FAMILY else CRED_SOURCES
    fs["allowRead"] = [x for x in (fs.get("allowRead") or []) if isinstance(x, str) and not any(x.rstrip("/").endswith(s) for s in SECRETS)
                       and not any(("/" + s + "/") in (x.rstrip("/") + "/") for s in srcs)]   # 11.11: nor one inside a source
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
    perm = out.get("permissions") if isinstance(out.get("permissions"), dict) else {}
    dn = [x for x in perm.get("deny")] if isinstance(perm.get("deny"), list) else []
    perm["deny"] = dn + [r for r in read_deny(plat) if r not in dn]
    out["permissions"] = perm
    env_ = out.get("env") if isinstance(out.get("env"), dict) else {}
    have = {k.lower() for k in env_}
    for k, v in tool_env(plat=plat).items():
        if k.lower() not in have:                     # the person's own value wins (npm reads NPM_CONFIG_CACHE too)
            env_[k] = v
    out["env"] = env_                                 # 0.2.60 (r0263): no CLAUDE_CODE_SUBPROCESS_ENV_SCRUB (see the module's note)
    return out


SCRUB = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"
QUIET_LINE = ("Quiet mode = Claude Code's own strict sandbox: commands run without network (except hosts you list) and cannot read your "
              "keys, keychain or browser cookies, so Witness only asks about what could leave this computer or cannot be undone.")
NOT_MAC = ("Quiet mode needs macOS, Linux or WSL2 (Claude Code's sandbox runs only there); on this system Witness keeps asking as usual.")
# 13.11 (r0268): WSL1 / a kernel Claude Code reads as WSL1 (a Microsoft kernel without "WSL2" in /proc/version: old WSL2 kernels, Azure
# Container Instances -- L3 13.11: "WSL1 is not supported (requires WSL2)")
WSL1 = ("Claude Code reads this system as WSL1 (/proc/version has \"microsoft\" but not \"WSL2\") and its sandbox does not start on WSL1. "
        "On Windows: convert the distribution to WSL2 (in PowerShell: wsl --update; wsl --set-version <distribution> 2). In a container that "
        "only looks like WSL (Azure Container Instances) quiet mode is not available.")


def _platform(platform=None):
    """darwin | linux | wsl2 | wsl1 | other (r0268: sandbox_fact.os_kind; "wsl" of old callers = wsl2)."""
    return sandbox_fact.os_kind(platform)


# ---- 13.11 (r0268): preflight on Linux / WSL2 -- nothing is written unless Claude Code's sandbox can start here ---------------------
PROC = "/proc/sys"
OS_RELEASE = "/etc/os-release"
BWRAP_PROBE = ["bwrap", "--new-session", "--die-with-parent", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/", "--dev", "/dev",
               "--proc", "/proc", "--", "true"]
APPARMOR_PROFILE = ("abi <abi/4.0>,\ninclude <tunables/global>\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n"
                    "  include if exists <local/bwrap>\n}\n")


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(65536)
    except OSError:
        return None


def _run(argv):
    import subprocess
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
        return r.returncode, r.stderr.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as x:
        return 127, str(x)


def install_line(read=None) -> str:
    """The package line for this distribution (/etc/os-release ID / ID_LIKE); both when unknown."""
    t = ((read or _read)(OS_RELEASE) or "").lower()
    ids = set()
    for ln in t.splitlines():
        if ln.startswith(("id=", "id_like=")):
            ids.update(ln.split("=", 1)[1].strip().strip('"').split())
    if ids & {"debian", "ubuntu", "linuxmint", "pop"}:
        return "sudo apt install bubblewrap socat"
    if ids & {"fedora", "rhel", "centos", "rocky", "almalinux", "amzn"}:
        return "sudo dnf install bubblewrap socat"
    if ids & {"arch", "manjaro"}:
        return "sudo pacman -S bubblewrap socat"
    if ids & {"opensuse", "suse", "opensuse-leap", "opensuse-tumbleweed"}:
        return "sudo zypper install bubblewrap socat"
    return "Debian / Ubuntu: sudo apt install bubblewrap socat; Fedora / RHEL: sudo dnf install bubblewrap socat"


def linux_problems(plat, weaker=False, which=None, read=None, run=None, machine=None, binfmt=None) -> list:
    """r0268: why Claude Code's sandbox cannot be quiet mode here, each a sentence a person acts on ([] = go). Never raises."""
    rd = read or _read
    try:
        if plat == "wsl1":
            return [WSL1]
        if plat not in LINUX_FAMILY:
            return [NOT_MAC]
        lx = sandbox_fact.linux_probe(plat, which=which, machine=machine, binfmt=binfmt, mnt=None)
        miss = [n for n in ("bwrap", "socat") if not lx.get(n)]
        if miss:
            return ["Claude Code's sandbox on Linux needs bubblewrap and socat; not found: %s. Install them: %s -- then run this again."
                    % (", ".join("bubblewrap (bwrap)" if n == "bwrap" else n for n in miss), install_line(rd))]
        out = []
        if lx.get("arch") not in sandbox_fact.SECCOMP_ARCH:
            out.append("This machine is %s: Claude Code's filter that closes Unix sockets (docker.sock, ssh-agent, the keyring) exists "
                       "only for x86_64 and arm64, so the sandbox here leaves them open and Witness would keep asking."
                       % (lx.get("arch") or "of an unknown architecture"))
        if plat == "wsl2" and lx.get("interop") is not False:
            out.append("WSL: Windows programs (.exe) can be started from Linux, and they run outside the Linux sandbox. Turn that off "
                       "for quiet mode: put \"[interop]\" and \"enabled=false\" into /etc/wsl.conf, then run `wsl --shutdown` in "
                       "PowerShell and open WSL again (`code .` and other .exe stop working from WSL)." if lx.get("interop") else
                       "WSL: cannot tell whether Windows programs (.exe) can be started from Linux (/proc/sys/fs/binfmt_misc is not "
                       "readable), so quiet mode cannot be checked here.")
        argv = list(BWRAP_PROBE)
        if weaker:                                    # Claude Code's weaker nested sandbox mounts no new /proc
            i = argv.index("--proc")
            del argv[i:i + 2]
        rc, err = (run or _run)(argv)
        if rc != 0:
            e = (err or "").strip().splitlines()
            first = re.sub(r"^bwrap:\s*", "", e[0])[:200] if e else "exit %s" % rc
            aa = (rd(PROC + "/kernel/apparmor_restrict_unprivileged_userns") or "").strip()
            mx = (rd(PROC + "/user/max_user_namespaces") or "").strip()
            clone = (rd(PROC + "/kernel/unprivileged_userns_clone") or "").strip()
            if aa == "1":
                out.append("Ubuntu 24.04 (and 23.10+) stops programs like bubblewrap from creating user namespaces "
                           "(kernel.apparmor_restrict_unprivileged_userns = 1), so Claude Code's sandbox cannot start (bwrap: %s). "
                           "Allow it for bubblewrap only: save this as /etc/apparmor.d/bwrap --\n%s"
                           "-- then run: sudo apparmor_parser -r /etc/apparmor.d/bwrap. (Or for every program: sudo sysctl -w "
                           "kernel.apparmor_restrict_unprivileged_userns=0, and to keep it after a reboot add that line to "
                           "/etc/sysctl.d/60-userns.conf.) Then run this again." % (first, APPARMOR_PROFILE))
            elif mx == "0" or clone == "0":
                out.append("User namespaces are switched off on this machine (%s), so bubblewrap cannot start (bwrap: %s). Switch them on: "
                           "%s -- then run this again." % ("user.max_user_namespaces = 0" if mx == "0" else
                                                           "kernel.unprivileged_userns_clone = 0", first,
                                                           "sudo sysctl -w user.max_user_namespaces=15000" if mx == "0" else
                                                           "sudo sysctl -w kernel.unprivileged_userns_clone=1"))
            elif "proc" in first.lower() and not weaker:
                out.append("bubblewrap cannot mount /proc here (bwrap: %s): this is a container that does not allow it (Docker without "
                           "extra rights, Azure Container Instances). Claude Code runs its sandbox here only with "
                           "sandbox.enableWeakerNestedSandbox, which lets the agent's commands see every process of this machine and "
                           "their environment: a weaker sandbox. Witness does not count it as quiet mode and keeps asking. To have that "
                           "sandbox anyway: deus-witness-hook --setup-strict --weaker-nested" % first)
            else:
                out.append("bubblewrap does not start here (bwrap: %s), so Claude Code's sandbox would stop every command. Nothing to "
                           "turn on until `bwrap --ro-bind / / --unshare-net true` works for your user." % first)
        return out
    except Exception as x:      # noqa: BLE001
        return ["cannot check this system (%s)" % type(x).__name__]


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


def _weaker_set(cur) -> bool:
    sb = cur.get("sandbox") if isinstance(cur, dict) and isinstance(cur.get("sandbox"), dict) else {}
    return sb.get("enableWeakerNestedSandbox") is True


def state(env=None, platform=None, problems=None) -> str:
    """'on' (the user settings already hold what --setup-strict writes, hosts aside) | 'off' | 'not-ready' (r0268: Linux / WSL2 where
    Claude Code's sandbox cannot be quiet mode yet: linux_problems) | 'not-supported' (Windows, WSL1, another system) | 'unreadable'.
    problems: linux_problems' arguments (tests). Never raises."""
    try:
        plat = _platform(platform)
        if plat not in ("darwin",) + LINUX_FAMILY:
            return "not-supported"
        cur, why = _load(settings_path(env))
        if cur is None:
            return "unreadable"
        if strict_settings(cur, env=env, plat=plat, weaker=_weaker_set(cur), homes=_homes(plat)) == cur:
            return "on"
        if plat in LINUX_FAMILY and linux_problems(plat, **(problems or {})):
            return "not-ready"
        return "off"
    except Exception:      # noqa: BLE001
        return "unreadable"


def _homes(plat):
    return sandbox_fact.win_homes() if plat == "wsl2" else None


KEEPS = ("Your permission mode and your other environment variables (OPENAI_API_KEY, DATABASE_URL...) stay as they are; hidden from the "
         "agent's commands: your Witness key and GitHub / npm / PyPI tokens.")
LIMIT = ("In quiet mode a push or a publish the agent runs cannot use your login (keychain and tokens are closed to its commands): "
         "Witness asks, and you run it in your own terminal. `git clone` / `git init` inside the project fail there too (Claude Code's "
         "sandbox protects .git/config): run them in your terminal.")


def _hosts_line(cmd):
    return ("Network: the agent's commands reach only " + ", ".join(DEFAULT_HOSTS) + " (npm install and pip install work). "
            "Add your own host: %s --setup-strict --host example.com (in your terminal; a host name, no *)." % cmd)


def summary(cur, new, hosts=None) -> list:
    """0.2.61 (r0263, L3 12.11 З5): the change in a few lines a person reads (the offer printed a 157-line diff). Built from the two
    settings (what really changes), not from a fixed text. The full diff: --quiet-offer --full / --setup-strict --dry-run."""
    cur = cur if isinstance(cur, dict) else {}
    sb0 = cur.get("sandbox") if isinstance(cur.get("sandbox"), dict) else {}
    sb1 = new.get("sandbox") if isinstance(new.get("sandbox"), dict) else {}
    net = sb1.get("network") if isinstance(sb1.get("network"), dict) else {}
    dom = [d for d in (net.get("allowedDomains") or []) if isinstance(d, str)]
    deny = [d for d in ((sb1.get("filesystem") or {}).get("denyRead") or []) if isinstance(d, str)]
    cred = sb1.get("credentials") if isinstance(sb1.get("credentials"), dict) else {}
    hid = [v.get("name") if isinstance(v, dict) else v for v in (cred.get("envVars") or [])]
    hid = [h for h in hid if isinstance(h, str)]
    out = ["- every command the agent runs stays inside Claude Code's sandbox (no way to run it outside)",
           "- network for those commands: only %s" % (", ".join(dom) if dom else "none"),
           "- they cannot read %d places with keys (%s ...), your login keychain or browser cookies" % (len(deny), ", ".join(deny[:3])),
           "- Claude Code's Read tool cannot open %d of them either (~/.ssh, ~/.aws, the keychain ...: permissions.deny)" % len(READ_DENY),
           "- hidden from them: %s" % (", ".join(hid[:4]) + (" and %d more token names" % (len(hid) - 4) if len(hid) > 4 else "") if hid else "nothing"),
           "- npm / uv caches move into Claude Code's own temp folder (so installs work inside the sandbox)"]
    gone = [k for k in WEAKER if k in sb0]
    if gone:
        out.append("- removed (they weaken the sandbox): %s" % ", ".join(gone))
    wide = [d for d in ((sb0.get("network") or {}).get("allowedDomains") or []) if isinstance(d, str) and d not in dom]
    if wide:
        out.append("- dropped from your host list (too wide): %s" % ", ".join(wide[:5]))
    return out


def offer(env=None, platform=None, out=None, cmd="deus-witness-hook", full=False, problems=None) -> str:
    """0.2.60 (r0262/r0263): print what quiet mode is and the exact change (a dry run); -> state(). The first line is machine-plain for
    /deus-witness:quiet: `QUIET MODE: on | offer | not ready | not supported | cannot read settings` (r0268: "not ready" = Linux / WSL2
    with what to install or switch, "not supported" = Windows / WSL1 / another system; "macOS only" before r0268)."""
    out = out or sys.stdout
    st = state(env, platform, problems)
    plat = _platform(platform)
    if st == "not-supported":
        print("QUIET MODE: not supported. " + (WSL1 if plat == "wsl1" else NOT_MAC), file=out)
        return st
    if st == "not-ready":
        print("QUIET MODE: not ready. " + " ".join(linux_problems(plat, **(problems or {}))), file=out)
        return st
    p = settings_path(env)
    if st == "unreadable":
        print("QUIET MODE: cannot read settings (%s). Fix it, then: %s --setup-strict --dry-run" % (_load(p)[1] or p, cmd), file=out)
        return st
    if st == "on":
        cur = _load(p)[0]
        print("QUIET MODE: on (%s already holds Claude Code's strict sandbox; undo: %s --undo-strict in your terminal)." % (p, cmd)
              + (" Note: it has sandbox.enableWeakerNestedSandbox (you chose it), so Witness keeps asking." if _weaker_set(cur) else ""),
              file=out)
        return st
    cur = _load(p)[0]
    print("QUIET MODE: offer. " + QUIET_LINE, file=out)
    if full:
        print(_hosts_line(cmd), file=out)
    print(KEEPS + " " + LIMIT, file=out)
    new = strict_settings(cur, DEFAULT_HOSTS, env, plat=plat, homes=_homes(plat))
    print("It changes %s (for all your projects; a backup is kept; undo: %s --undo-strict in your terminal):" % (p, cmd), file=out)
    if full:
        print("\n".join(_diff(p, cur, new)), file=out)
    else:
        print("\n".join(summary(cur, new)), file=out)    # 0.2.61 (r0263, L3 З5): a short list, not a 157-line diff
        print("Your own host: %s --setup-strict --host example.com (in your terminal). The exact change, line by line: %s --quiet-offer --full"
              % (cmd, cmd), file=out)
    print("To turn it on: run `%s --setup-strict` in your terminal, or let the agent run `%s --setup-strict --yes`: Witness then asks "
          "YOU (passkey, this once); the agent cannot switch it on or off by itself. Not now: %s --quiet-no (no more reminders)."
          % (cmd, cmd, cmd), file=out)
    return st


def setup(env=None, write=True, platform=None, hosts=None, show=True, full=None, weaker=False, problems=None) -> int:
    """hosts None = DEFAULT_HOSTS; extra names come from --host. show=False: the change was just shown (the terminal's yes), not again.
    full (0.2.61): the whole diff (default: only for a dry run, the explicit "show me the change"); else the short list (summary).
    weaker (r0268, --weaker-nested): Linux only, sandbox.enableWeakerNestedSandbox -- said as a weakening. problems: linux_problems' test
    arguments."""
    p = settings_path(env)
    plat = _platform(platform)
    if plat == "wsl1" or plat not in ("darwin",) + LINUX_FAMILY:
        print("deus-witness-hook --setup-strict: " + (WSL1 if plat == "wsl1" else NOT_MAC) + " Nothing changed.", file=sys.stderr)
        return 1
    if weaker and plat not in LINUX_FAMILY:
        print("deus-witness-hook --setup-strict: --weaker-nested is for Linux containers only. Nothing changed.", file=sys.stderr)
        return 1
    if plat in LINUX_FAMILY:
        why = linux_problems(plat, weaker=weaker, **(problems or {}))
        # --weaker-nested: the person accepted the weaker sandbox, so its own "cannot mount /proc" is not a stop; the rest still is
        if why:
            for w in why:
                print("deus-witness-hook --setup-strict: " + w, file=sys.stderr)
            print("Nothing changed.", file=sys.stderr)
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
    new = strict_settings(cur, hs, env, plat=plat, weaker=weaker, homes=_homes(plat))
    diff = _diff(p, cur, new)
    if not diff:
        print("already strict: %s" % p)
        return 0
    if weaker:
        print("WEAKER SANDBOX (--weaker-nested): sandbox.enableWeakerNestedSandbox lets the agent's commands see every process of this "
              "machine and read the environment of your other processes. Witness does not count it as quiet mode: it keeps asking.")
    if show:
        print(QUIET_LINE)
        print(KEEPS + " " + LIMIT)
        # 0.2.61 (r0263): the terminal's yes reads the short list; --dry-run (the explicit "show me") prints the whole diff
        print("\n".join(diff if (not write if full is None else full) else
                        summary(cur, new) + ["The exact change, line by line: deus-witness-hook --setup-strict --dry-run"]))
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
    with open(src, "rb") as f:
        raw = f.read()
    try:
        old = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        cur = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
    except (ValueError, OSError, UnicodeDecodeError):
        old = cur = None
    if isinstance(old, dict) and isinstance(cur, dict):
        # 0.2.64 (r0266): exactly our Read rules go; a deny rule the person added after --setup-strict stays
        op = old.get("permissions") if isinstance(old.get("permissions"), dict) else None
        od = [x for x in (op or {}).get("deny") or []] if isinstance((op or {}).get("deny"), list) else []
        cp = cur.get("permissions") if isinstance(cur.get("permissions"), dict) else {}
        cd = [x for x in cp.get("deny") or []] if isinstance(cp.get("deny"), list) else []
        added = [x for x in cd if x not in od and x not in READ_DENY_ALL]
        if added:
            op = op if op is not None else {}
            op["deny"] = od + added
            old["permissions"] = op
            raw = (json.dumps(old, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with open(p + ".tmp", "wb") as g:
        g.write(raw)
    os.replace(p + ".tmp", p)
    print("restored %s from %s" % (p, src))
    # r0273 (ISPYTANIE-MAC-S-NULYA-1311, P2): what stays on disk, said once; nothing is deleted here (a backup is the person's way back)
    print("kept: %d backup file(s) %s.bak-strict-* (delete them when you no longer need them). Removing Witness altogether: "
          "`claude plugin uninstall %s`, then `rm -rf %s` (the agent key and pins)." % (
              len(baks), p, "deus-witness@sipkigroup", _key_dir(env)))
    return 0


def _key_dir(env=None) -> str:
    e = os.environ if env is None else env
    return e.get("DEUS_WITNESS_HOME") or "~/.config/deus-witness"
