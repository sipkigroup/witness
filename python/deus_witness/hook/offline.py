"""0.2.48: what the hook lets run while the witness cannot be reached (cloud/OTCHET-DEGRADACIYA-STASH-0272.md).

Before 0.2.48 a witness that could not be reached (network, 5xx, timeout) meant a deny for EVERY call: one witness down and Claude Code could
not even read a file. Now, by default, a call that only READS a file of the project is not blocked (no decision: Claude Code's own
permission rules apply, as for a witness `pass`); it is written to the local journal (`offline.log` next to the key file) and the user is
told once. Everything else is refused as before: a write, a run, the network, MCP, WebFetch / WebSearch, a subagent, PowerShell.

The witness never judged such a call, so the hook decides alone and stricter than the witness would:
  - the tools: Read, NotebookRead, Grep, Glob, LS, and a Bash command that read_only_shell() takes as reading only AND whose every program is
    in OFFLINE_PROGRAMS (no git: .git/config can make `git status` / `git diff` run a program -- core.fsmonitor, filter.*.clean, gpg; no
    rg / jq: --hidden / --pre, `jq -n env`, --rawfile; no cd: it moves the base of the relative paths), with no option that reads a list of
    files or walks a tree into file contents (grep -r, diff -r, grep -f, file -f);
  - every path (each word of the command, the value of an `--opt=value`) lies, as written and as its realpath, inside the project root,
    which is never `/`, the home directory or a folder above it; no `~`, no glob `*`;
  - no secret: the server's own credential names and directories (.env, .netrc, id_rsa, *.pem, *.key, secrets.yaml, .ssh, .aws ...), and
    nothing of the agent's harness (.git, .claude, .mcp.json, the Deus Witness key files);
  - 0.2.73 (N13): no regular file with more than one name (a hard link may be a credential file under a plain name), and no Grep while a
    credential file of the project has more than one name;
  - only when the witness URL is one this machine has pinned (it worked here before), only when the witness gave no verdict on this call (an
    owner's pending question is not skipped by a dropped connection), and only when the journal line was written.
DEUS_WITNESS_HOOK_OFFLINE=strict (or any value but `read`) switches it off: a deny for every call, as before 0.2.48.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
import time

ENV = "DEUS_WITNESS_HOOK_OFFLINE"
JOURNAL = "offline.log"
NOTICE = "offline-notice"
NOTICE_EVERY_S = 600
JOURNAL_MAX = 1 << 20
READ_TOOLS = {"Read": "file_path", "NotebookRead": "notebook_path"}
DIR_TOOLS = ("Grep", "Glob", "LS")
OFFLINE_PROGRAMS = {"ls", "cat", "head", "tail", "wc", "grep", "stat", "du", "file", "pwd", "echo", "which", "find", "readlink", "realpath",
                    "basename", "dirname", "diff", "cmp"}
NO_PATH_ARGS = {"echo", "pwd", "which", "basename", "dirname"}       # their words are text / program names, never opened
# options that read a list of files / patterns from a file or walk a tree into file contents (find only prints names)
BAD_SHORT = {"grep": set("rRdDf"), "diff": set("r"), "file": set("fm")}
BAD_LONG = {"grep": ("--recursive", "--dereference-recursive", "--directories", "--devices", "--file"),
            "diff": ("--recursive", "--new-file", "--unidirectional-new-file"), "file": ("--files-from", "--magic-file"),
            "wc": ("--files0-from",), "du": ("--files0-from",), "find": ("-files0-from",)}

# the server's credential names and directories (its classifier's two patterns and its list of sample names); a test keeps them equal
SECRET_NAME = re.compile(r"(^|/)(\.env(\.[\w.-]+)?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|\.?credentials(\.json)?|"
                         r"\.vault-token|\.terraformrc|credentials\.tfrc\.json|\.s3cfg|\.boto|\.my\.cnf|\.authinfo(\.gpg)?|rclone\.conf|\.(zsh|bash)_history|[\w.-]+\.ovpn|"
                         r"id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|[\w.-]+\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|p8)|secrets?\.(ya?ml|json|toml|env))$", re.I)
SECRET_DIR = re.compile(r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.config/(gcloud|gh|op|hub|doctl|fly|rclone|containers|sops)|\.azure|Library/Keychains)(/|$)", re.I)
CREDENTIAL_NAMES = (".env", ".env.local", ".env.production", ".envrc", ".netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials", "credentials",
                  "credentials.json", ".vault-token", "id_rsa", "id_ed25519", "id_ecdsa", "server.pem", "server.key", "cert.p12", "store.jks",
                  "db.kdbx", "secrets.yaml", "secrets.yml", "secret.json", "secrets.toml", "secrets.env", ".terraformrc")
HARNESS = (".git", ".claude", ".mcp.json", ".claude.json", ".deus-witness", "agent-key.json", ".gitconfig")


def enabled(env) -> bool:
    return (env or {}).get(ENV, "read") == "read"


def _secret(p):
    return bool(SECRET_NAME.search(p) or SECRET_DIR.search(p) or re.search(r"(^|/)config/deus-witness(/|$)", p, re.I))


def _harness(p):
    return any(c.rstrip(". ").lower() in HARNESS for c in re.split(r"[/\\]+", p) if c)


def _under(p, base):
    return p == base or p.startswith(base.rstrip("/") + "/")


def project_root(ev, env):
    """The project the hook may read without the witness: CLAUDE_PROJECT_DIR, else the call's cwd (realpath); None when it is '/', the home
    directory or a folder above it (form.refuse_reason: such a 'project' would be the whole machine)."""
    from .form import refuse_reason
    p = (env or {}).get("CLAUDE_PROJECT_DIR")
    cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) else None
    r = p if isinstance(p, str) and os.path.isabs(p) else cwd
    if not isinstance(r, str) or not os.path.isabs(r):
        return None
    try:
        rr = os.path.realpath(r)
        home = (env or {}).get("HOME") or os.path.expanduser("~")
        if refuse_reason(rr, home) or refuse_reason(rr):
            return None
    except (OSError, ValueError):
        return None
    return rr


def path_ok(p, cwd, root, keyhome):
    """-> None when `p` may be read without the witness, else why not (a short English phrase)."""
    if not isinstance(p, str) or not p or len(p) > 4096 or "\0" in p:
        return "a path the hook cannot check"
    if "~" in p or "*" in p or "$" in p:
        return "a path the shell would expand"
    a = p if os.path.isabs(p) else os.path.join(cwd, p)
    n = os.path.normpath(a)
    try:
        r = os.path.realpath(a)
    except (OSError, ValueError):
        return "a path the hook cannot resolve"
    for q in (n, r):
        if not _under(q, root):
            return "outside the project"
        if _secret(q) or _secret(q[len(root):] or "/"):
            return "a credential file"
        if _harness(q[len(root):]):
            return "the agent's harness (.git, .claude, .mcp.json, key files)"
        if keyhome and _under(q, keyhome):
            return "the Deus Witness key files"
    from .samefile import links
    if links(r) is not None:
        # 0.2.73 (N13, polygon series 9): a hard link is the same file under another name (`hl.txt` = .env): realpath does not show it, and
        # without the witness the hook does not tell such a name of a credential file from any other (cloud/OTCHET-N13-N15-0273.md)
        return "a file with more than one name (a hard link: it may be a credential file under another name)"
    return None


def _glob_ok(g):
    if not isinstance(g, str) or not g:
        return "a pattern the hook cannot check"
    if g.startswith(("/", "~")) or ".." in g or "\0" in g:
        return "a pattern that leaves the project"
    alts = [g]
    m = re.search(r"\{([^{}]*)\}", g)
    if m:
        alts = [g[:m.start()] + x + g[m.end():] for x in m.group(1).split(",")]
    for a in alts:
        last = a.rstrip("/").rsplit("/", 1)[-1]
        if _secret(a) or _harness(a) or any(fnmatch.fnmatchcase(s, last) for s in CREDENTIAL_NAMES) or \
                re.search(r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker)(/|$)", a):
            return "a pattern that picks a credential file"
    return None


def _segments(cmd):
    """The argv of every segment of a command read_only_shell() already accepted (its redirections to /dev/null dropped)."""
    lx = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>")
    lx.whitespace_split, lx.commenters = True, ""
    toks, segs, seg, i = list(lx), [], [], 0
    while i < len(toks):
        t = toks[i]
        if t in ("&&", "||", ";", "|"):
            segs.append(seg)
            seg = []
        elif t in (">", ">>", "&>", ">&"):
            i += 1                                        # its target: /dev/null or a descriptor (read_only_shell checked it)
        else:
            seg.append(t)
        i += 1
    segs.append(seg)
    return segs


def _shell_ok(cmd, cwd, root, keyhome):
    from .main import read_only_shell
    if not read_only_shell(cmd):
        return "not a command that only reads"
    if "~" in cmd or "*" in cmd:
        return "a word the shell would expand"
    for argv in _segments(cmd):
        if not argv or argv[0] not in OFFLINE_PROGRAMS:
            return "%s is not run without the witness" % (argv[0] if argv else "an empty command")
        prog = argv[0]
        for a in argv[1:]:
            if a.startswith("-") and a != "-":
                name, _, val = a.partition("=")
                if not re.fullmatch(r"--?[A-Za-z0-9][A-Za-z0-9-]*", name):
                    return "an option the hook cannot read"
                if name in BAD_LONG.get(prog, ()) or (not name.startswith("--") and set(name[1:]) & BAD_SHORT.get(prog, set())):
                    return "%s %s reads more than the files it names" % (prog, name)
                if val and prog not in NO_PATH_ARGS and not re.fullmatch(r"[\w,:+-]*", val):     # `--color=never` is no path
                    why = path_ok(val, cwd, root, keyhome)
                    if why:
                        return why
                continue
            if prog in NO_PATH_ARGS:
                continue
            why = path_ok(a, cwd, root, keyhome)
            if why:
                return why
    return None


def local_read(ev, env):
    """-> None when this event may run without the witness (a read of a project file), else why not."""
    tool = ev.get("tool_name")
    inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else None
    if not isinstance(tool, str) or inp is None:
        return "not a read"
    root = project_root(ev, env)
    if root is None:
        return "no project directory (the home directory or / is not one)"
    cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and os.path.isabs(ev.get("cwd")) else root
    try:
        from ..trial import home_dir
        kh = os.path.realpath(home_dir(env))
    except Exception:      # noqa: BLE001
        kh = None
    if tool in READ_TOOLS:
        return path_ok(inp.get(READ_TOOLS[tool]), cwd, root, kh)
    if tool in DIR_TOOLS:
        p = inp.get("path")
        why = path_ok(p if isinstance(p, str) and p else cwd, cwd, root, kh)
        if why:
            return why
        if tool == "Grep":
            # 0.2.73 (N13): Grep prints the lines of the files it walks; a hard link of a project credential file under a plain name would
            # be one of them. Such a link exists somewhere when a credential file has more than one name: then no Grep without the witness
            from .samefile import Secrets
            try:
                linked = Secrets(root, None, _secret).any_linked()
            except Exception:      # noqa: BLE001
                linked = "?"
            if linked:
                return "a credential file of this project has another name (a hard link) that Grep could print"
        for k in ("glob", "pattern") if tool != "Grep" else ("glob",):
            if inp.get(k) is not None:
                why = _glob_ok(inp.get(k))
                if why:
                    return why
        return None
    if tool == "Bash":
        cmd = inp.get("command")
        return _shell_ok(cmd, cwd, root, kh) if isinstance(cmd, str) else "not a read"
    return "not a read"


def _args_sha(ev):
    inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
    return hashlib.sha256(json.dumps([ev.get("tool_name"), inp], sort_keys=True, ensure_ascii=False).encode("utf-8", "replace")).hexdigest()


def journal(ev, env, code, allowed) -> str | None:
    """One line in <key dir>/offline.log: time, tool, the SHA-256 of [tool, tool_input] (never the arguments, as the stderr log), the
    witness error, the decision. -> the journal path, or None when it could not be written (then the call is refused)."""
    try:
        from ..trial import home_dir
        d = home_dir(env)
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, JOURNAL)
        try:
            if os.path.getsize(p) > JOURNAL_MAX:
                os.replace(p, p + ".1")
        except OSError:
            pass
        line = json.dumps({"t": int(time.time()), "tool": str(ev.get("tool_name"))[:200], "args_sha256": _args_sha(ev), "witness": code,
                           "decision": "witness unreachable, local read allowed" if allowed else "witness unreachable, refused"})
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return p
    except Exception:      # noqa: BLE001
        return None


def notice_due(env) -> bool:
    """True once per NOTICE_EVERY_S (a marker next to the journal): the user is told once, not on every read."""
    try:
        from ..trial import home_dir
        m = os.path.join(home_dir(env), NOTICE)
        try:
            if time.time() - os.path.getmtime(m) < NOTICE_EVERY_S:
                return False
        except OSError:
            pass
        with open(m, "w") as f:
            f.write(str(int(time.time())))
        return True
    except Exception:      # noqa: BLE001
        return True


def message(code, path) -> str:
    return ("Deus Witness: the witness cannot be reached (%s). Until it answers, only reading files of this project runs, outside the witness "
            "(no credential files, nothing that writes, runs code or uses the network); every such read is listed in %s. "
            "To refuse everything instead: set %s=strict in the hook's environment." % (code, path, ENV))
