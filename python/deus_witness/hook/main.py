"""deus-witness-hook: Claude Code PreToolUse hook. Every matched tool call goes through the witness before it runs.

  stdin   the PreToolUse event (JSON: tool_name, tool_input, cwd, ...)
  stdout  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": allow|deny|ask, "permissionDecisionReason": ...}}
  exit    0 always when a decision was printed; 2 (= Claude Code blocks the call) if even that failed

Fail-closed, three layers (see failsafe.py): the hook answers `deny` on every error it can catch; settings.json runs it as
`deus-witness-hook || exit 2` (a missing or broken install = exit 2 = block); and the entry carries `"onFailure": "block"`
(Claude Code 2.1.295+: a timeout, crash or bad output of the hook blocks the call). `--doctor` / the SessionStart hook
(`--session-start`) warn loudly when a layer is missing or Claude Code is too old to honour it.

Witness verdict -> Claude Code decision
  allow (receipt verified, consumed in the ledger)  -> allow   (0.2.10: also OK_ALLOWANCE, an owner-signed project allowance)
  pass  (class pass: not witnessed)                 -> no decision: Claude Code's own permission rules apply
  defer (owner approval pending)                    -> deny (default) | ask | defer   (DEUS_WITNESS_HOOK_ON_DEFER)
  deny / refused / expired / any error / timeout    -> deny with the reason

Env: DEUS_WITNESS_KEY (required), DEUS_WITNESS_URL, DEUS_WITNESS_HOME (key pin dir),
     DEUS_WITNESS_HOOK_TIMEOUT  seconds for the whole decision, default 20, at most 900 (keep it at least 5 s BELOW the hook
                                `timeout` in settings.json: a hook that Claude Code cancels for time gives no decision),
     DEUS_WITNESS_HOOK_WAIT     seconds to wait for the owner on defer before answering, default 0, cut to TIMEOUT - 5
                                (to wait the whole approval window: WAIT 600, TIMEOUT 610, settings `timeout` 620),
     DEUS_WITNESS_HOOK_ON_DEFER deny | ask | defer, default deny (0.2.22; was ask). A held call waits for the OWNER in Witness (phone);
                                the person at the terminal must not approve in the owner's place. `ask` shows a yes/no prompt in
                                the terminal - yes runs the call WITHOUT a witness receipt - so it is an explicit choice only.
                                defer: print mode / Agent SDK only - interactive Claude Code ignores it. Anything else: deny,
     DEUS_WITNESS_HOOK_ALLOW    allow | neutral, default allow (neutral: a witnessed allow still goes through Claude Code's prompts),
     DEUS_WITNESS_VERIFY=0      do not check receipts (not recommended). 0.2.32: ignored once the URL has a pinned key.
0.2.32 (K1): the URL is the one the key file (`deus-witness try`) was set up for; DEUS_WITNESS_URL may only repeat it (else a deny,
WITNESS_URL_MISMATCH). A URL without a pinned key is pinned at first use only when nothing is pinned yet (or it is the key file's URL);
otherwise a deny, WITNESS_URL_UNPINNED (`deus-witness-hook --trust URL` in a terminal pins it). A call that touches the agent's own
harness (.claude/, .mcp.json, .git/hooks, ~/.claude, the Deus Witness key files) runs only with an owner-approved receipt.
The log (stderr) carries the tool, rid and verdict only - never arguments.

0.2.16 (thin client): the hook does not classify anything. It sends the event as Claude Code gave it (tool name, tool_input as is, cwd),
CLAUDE_PROJECT_DIR / HOME, and the file-system facts the witness asks for (realpath / isdir / exists of the paths it names, and SHA-256
fingerprints of project files by a list the witness signs) to POST /v1/hook/judge; the witness classifies, decides through the core and
answers with the receipts. The hook checks every receipt against the pinned witness key and that each judged call is its own tool_input,
consumes them, and answers Claude Code. No answer, a bad signature or anything unexpected: deny (fail-closed, as before).
0.2.17 (R9-01): every call carries a fresh random nonce; the witness signs a statement of its answer (the nonce, the hash of the exact request,
the full list of parts, and per judged part its args_sha256, rid and verdict). The hook uses an answer only when that statement verifies
against the pinned key and matches the call; a part list that was cut, reordered or replayed from another call is a deny.
(R9-05) The hook answers file-system questions only about paths of this call: inside the project, the session's directories and their
parents, and paths built from the words of the tool_input; any other question is a deny.

  deus-witness-hook --print-form PROJECT_DIR    the recommended mandate form (default rules) as JSON; paste it into the Mandate page
                                                ("Import from JSON"), which shows what will be signed. The default form has
                                                delete.allow_irreversible = true: that is what lets Write / Edit and shell
                                                redirections work INSIDE the project and the temp dir (the witness judges a write as an
                                                irreversible delete of its path). Add --no-irreversible for a read-only mandate: then
                                                every Write / Edit is refused.
  deus-witness-hook --doctor [PROJECT_DIR]      is the hook fail-closed here? (Claude Code version, settings.json, the
                                                plugin as Claude Code registered it, the agent key); exit 1 if not or if
                                                it cannot tell
  deus-witness-hook --session-start             for a SessionStart hook: a loud warning when the hook can be bypassed
  deus-witness-hook --trust URL                 pin the key of another witness (asks you to type yes; a terminal only)
"""
from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import secrets
import sys
import threading
import time

from .. import __version__, _compat
from . import failsafe, fingerprint, gitref, sandbox_fact, selfpath
from ..client import AARError, ActionResult, Witness, WitnessError, WitnessKeyChanged, WitnessNotPinned, args_sha256, request_sha256
from .form import default_form
from .messages import LOCAL

MAX_EVENT = 16 * 1024 * 1024
VERSION = __version__
RESERVED = "_witness"
ENV_KEYS = ("CLAUDE_PROJECT_DIR", "HOME", "DEUS_WITNESS_EXEC_SCAN")
MAX_ROUNDS = 8                 # fact rounds per call; the witness asks what its classifier needs (usually one round, two with a project scan)
MAX_ASKED = 4096               # paths answered per round
CLIENT = {"name": "deus-witness-hook", "version": VERSION}
HINTS = {k: v[1] for k, v in LOCAL.items() if v[0] == "deny"}
TRIAL_REASON = "ESCALATE_TRIAL_CLAIM"       # 0.2.28 (server 0.2.38): a trial account waits for its first touch
TRIAL_OPEN_EVERY_S = 600
TRIAL_WAIT_S = 90.0                          # 0.2.34: a trial account nobody has touched yet is waited for this long (an owner's question: DEUS_WITNESS_HOOK_WAIT)
TRIAL_UNCLAIMED_TEXT = "This trial account has no passkey yet (nothing ran). Open the trial page from `/deus-witness:try` or `uvx --from deus-witness deus-witness try` (or the link it showed you), touch the passkey, then ask again."


def _trial_open(url, env) -> None:
    """Open the trial page in the browser at most once per TRIAL_OPEN_EVERY_S (a marker file next to the key). The URL holds only the
    receipt id; the claim is already in that browser (put there by `deus-witness try`). DEUS_WITNESS_OPEN_BROWSER=0: never."""
    if not isinstance(url, str) or not url.startswith(("https://", "http://localhost", "http://127.0.0.1")) or (env or {}).get("DEUS_WITNESS_OPEN_BROWSER") == "0":
        return
    try:
        from ..trial import home_dir
        mark = os.path.join(home_dir(env), "trial-opened")
        try:
            if time.time() - os.path.getmtime(mark) < TRIAL_OPEN_EVERY_S:
                return
        except OSError:
            pass
        os.makedirs(os.path.dirname(mark), exist_ok=True)
        with open(mark, "w") as f:
            f.write(str(int(time.time())))
        import webbrowser
        webbrowser.open(url, new=2)
    except Exception:      # noqa: BLE001  the hook still waits; the person can open the page from the message
        pass


REPLACED_TEXT = ("(`deus-witness try` was run again: this call belonged to the previous trial account, which no longer exists. Nothing ran. "
                 "Retry the SAME call: it now goes to the new trial account, and its page asks for the passkey)")


def _replaced(s) -> bool:
    """0.2.29: the key this hook uses came from the key file and the file now holds another key (a newer `deus-witness try`)."""
    if not getattr(s, "key_from_file", False):
        return False
    try:
        from ..trial import load_key
        d = load_key(s.env)
        return d is not None and d.get("key") != s.key
    except Exception:      # noqa: BLE001
        return False


class Fail(Exception):
    """-> deny(code, detail)"""

    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def log(msg: str) -> None:
    try:
        sys.stderr.write("[deus-witness-hook] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


def _changed(res) -> str:
    """0.2.13: the files that made the command a question, as the witness recorded them in the action."""
    ch = (res.action or {}).get("exec_changed") if isinstance(res.action, dict) else None
    if not isinstance(ch, list) or not ch:
        return ""
    names = [str(x) for x in ch[:5]]
    return " [changed: %s%s]" % (", ".join(names), " ..." if len(ch) > 5 else "")


def decision(kind: str | None, reason: str = "") -> dict:
    if kind is None:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}}


def deny(code: str, rid: str | None = None, detail: str = "", texts: dict | None = None, hint: bool = True) -> dict:
    """texts: {code: [kind, text]} from the witness' answer; the hook's own codes are in messages.LOCAL.
    hint=False (0.2.40): the detail already says what to do; the code's hint would repeat it."""
    t = (texts or {}).get(code)
    hint = (t[1] if isinstance(t, (list, tuple)) and len(t) == 2 and t[0] == "deny" and isinstance(t[1], str) else HINTS.get(code)) if hint else None
    text = "Blocked by Deus Witness: %s (receipt %s)" % (code, rid or "none")
    if detail:
        text += " %s" % (detail.rstrip(".") if hint is None else detail)
    if hint:
        text += ". " + hint
    return decision("deny", text + ". Do not try to reach the same effect another way.")


class Settings:
    def __init__(self, env=None):
        e = os.environ if env is None else env
        self.env = e
        self.timeout = _num(e.get("DEUS_WITNESS_HOOK_TIMEOUT"), 20.0, 1.0, 900.0)
        # the answer must be printed before our own deadline: a wait that eats the whole timeout ends as WITNESS_TIMEOUT
        self.wait = min(_num(e.get("DEUS_WITNESS_HOOK_WAIT"), 0.0, 0.0, 900.0), max(0.0, self.timeout - failsafe.MARGIN_S))
        v = e.get("DEUS_WITNESS_HOOK_ON_DEFER", "deny")
        self.on_defer = v if v in ("ask", "deny", "defer") else "deny"       # 0.2.22: deny by default; ask only when set explicitly
        self.allow = "neutral" if e.get("DEUS_WITNESS_HOOK_ALLOW") == "neutral" else "allow"
        # 0.2.32 (K1): DEUS_WITNESS_VERIFY=0 is only a request; judge() keeps the check on when this URL already has a pinned key
        self.verify_off = e.get("DEUS_WITNESS_VERIFY") == "0"
        self.verify = not self.verify_off
        self.key = e.get("DEUS_WITNESS_KEY")
        env_url = _url(e.get("DEUS_WITNESS_URL"))
        self.url = env_url
        self.key_from_file = False
        self.file_url = None                              # the witness the key file was set up for (`deus-witness try`)
        self.url_conflict = None                          # (DEUS_WITNESS_URL, key file URL) when they differ: a deny, never a choice
        from ..trial import load_key
        d = load_key(e)                                   # 0.2.28: the key `deus-witness try` saved (agent-key.json, mode 600)
        if d is not None and (not self.key or self.key == d["key"]):
            if not self.key:
                self.key = d["key"]
                self.key_from_file = True
            # 0.2.32 (K1): the URL comes from the key file; the environment may only repeat it (the environment is what an agent that
            # wrote .claude/settings.local.json controls: before 0.2.32 it won, and the key went to whatever witness it named)
            self.file_url = _url(d.get("url"))
            if self.file_url:
                if env_url and env_url != self.file_url:
                    self.url_conflict = (env_url, self.file_url)
                self.url = self.file_url


def _url(v):
    return v.strip().rstrip("/") if isinstance(v, str) and v.strip() else None


# ---------------------------------------------------------------- 0.2.32 (K1): the agent's own harness
# A write to these switches the witness off for the next session (Claude Code settings / hooks with their `env` and `disableAllHooks`,
# .mcp.json, git hooks, the key file and the key pins). The witness asks the owner for them (server 0.2.24, category agent-config /
# git-config); the hook does not rely on that alone: such a call runs only with a receipt the OWNER approved (status `approved`, a
# passkey in Witness), never on the mandate alone. The mandate format has no exclusions (delete = targets + allow_irreversible), so the
# rule lives here, like the server's. Shell commands: the hook does not parse them (thin client), so a command that NAMES one of these
# places needs the owner's approval too; 0.2.33: except a Bash command that surely only reads (read_only_shell, below) - and never for
# the Deus Witness key files.
WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
SHELL_TOOLS = ("Bash", "PowerShell")
# 0.2.33 (red team, git config): git's own configuration is harness too. diff.external / diff.<drv>.textconv / core.fsmonitor /
# core.pager / gpg.program there make `git diff`, `git show`, `git log`, `git status` run any program, which can rewrite .claude. So
# `.git/` (except objects, refs, logs, index, HEAD: nothing there names a program), `.gitconfig`, `/etc/gitconfig`, `.config/git`, and a
# `git config` subcommand, `--template`, `git clone -c` (they write them) need the owner's approval like .git/hooks. `.gitattributes` stays free: it only NAMES a driver,
# git runs nothing unless the driver's command is defined in a (now guarded) config file.
_GIT_WORDS = (r"|(?:^|(?<=[\s/'\"=:;&|(]))\.git(?:[/\\](?!(?:objects|refs|logs|index|HEAD|ORIG_HEAD|FETCH_HEAD|packed-refs)\b)|(?![\w./\\-]))"
              r"|gitconfig(?![\w-])|\.config[/\\]git(?![\w.-])"
              r"|(?:^|(?<=[\s;&|(]))git(?:\s+-[cC]\s+\S+|\s+--?[\w-]+(?:=\S*)?)*\s+config(?![\w-])"
              # a template directory's `config` and `git clone -c/--config` land in the new repository's .git/config
              r"|--template(?![\w-])|GIT_TEMPLATE_DIR|(?:^|(?<=[\s;&|(]))git\s(?:[^;&|]*\s)?clone\s(?:[^;&|]*\s)?(?:-c|--config)(?=[\s=]|$)")
_CONFIG_WORDS = re.compile(r"(\.claude(?![\w-])(?!/worktrees/)|\.mcp\.json|\.git[/\\]hooks|\.deus-witness|config[/\\]deus-witness|"
                           r"agent-key\.json|deus-witness-hook\s+--trust" + _GIT_WORDS + ")", re.I)
# 0.2.33: the Deus Witness key files stay owner-only even for a read (the key itself); .claude / .mcp.json / .git/hooks do not (below)
_KEY_WORDS = re.compile(r"(\.deus-witness|config[/\\]deus-witness|agent-key\.json|deus-witness-hook\s+--trust)", re.I)

# 0.2.33 (friction of K1, residual risk 3): `cat .claude/settings.json`, `ls .git/hooks`, `git diff .mcp.json` were refused with no way to
# approve them. A Bash command that can only READ is not the agent's harness being changed: it goes the normal way (the witness judges
# it, as any other command). "Only read" is decided here, conservatively, on the text alone (the thin client has no shell parser):
# every segment of `a && b || c ; d | e` starts with a listed read-only program and uses none of its writing / executing options; no
# redirection except to /dev/null (`2>/dev/null`, `2>&1`); none of $ ` ( ) { } < * ? [ ] ! # \ newline outside quotes ($ and ` not even
# inside double quotes); no `VAR=x cmd`, no path to a program. Anything else (unsure included) is refused as in 0.2.32.
_RO_PROGRAMS = {"ls", "cat", "head", "tail", "wc", "grep", "rg", "stat", "du", "file", "pwd", "cd", "echo", "which", "find", "jq",
                "readlink", "realpath", "basename", "dirname", "diff", "cmp", "git"}
_RO_GIT = {"status", "diff", "log", "show", "branch"}
_RO_GIT_DIFF = {"diff", "log", "show"}
_RO_GIT_BRANCH = {"-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "--list", "-l", "--show-current", "--no-color", "--color"}
_RO_FIND_BAD = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
_RO_UNQUOTED_BAD = set("$`(){}<*?[]!#\\")


def _ro_scan(cmd):
    """-> True when no shell expansion / substitution / glob can happen in `cmd` (quote-aware)."""
    if any(ch in cmd for ch in "\n\r\0"):
        return False
    q = None
    for ch in cmd:
        if q == "'":
            q = None if ch == "'" else q
        elif q == '"':
            if ch in "$`":
                return False
            q = None if ch == '"' else q
        elif ch in "'\"":
            q = ch
        elif ch in _RO_UNQUOTED_BAD:
            return False
    return q is None


def _ro_git_no_drivers(args):
    """0.2.33 (red team): `git diff/show/log` run the repository's diff.external and diff.<driver>.textconv programs (config +
    .gitattributes). They count as read-only only with BOTH `--no-ext-diff` and `--no-textconv` before any `--` (after `--` they are
    paths), and with no option that turns either back on (`--ext-diff`, `--textconv`, or a prefix git would expand to one of them)."""
    flags = set()
    for a in args:
        if a == "--":
            break
        if a in ("--no-ext-diff", "--no-textconv"):
            flags.add(a)
        elif len(a) > 2 and a.startswith("--") and ("--ext-diff".startswith(a.split("=")[0]) or "--textconv".startswith(a.split("=")[0])):
            return False
    return any(a in ("--ext-diff", "--textconv") for a in args) is False and flags == {"--no-ext-diff", "--no-textconv"}


def _ro_segment(argv):
    if not argv or argv[0] not in _RO_PROGRAMS:
        return False
    prog, args = argv[0], argv[1:]
    if prog == "git":
        if not args or args[0] not in _RO_GIT:
            return False                                  # `git -c x=y ...`, `git -C dir ...`, `git config ...`: not read-only here
        if any(a.startswith("--output") for a in args[1:]):
            return False                                  # `git diff --output=FILE` writes
        if args[0] in _RO_GIT_DIFF:                       # 0.2.33 (red team): see _ro_git_no_drivers
            return _ro_git_no_drivers(args[1:])
        if args[0] == "status":                           # `status -v` shows a diff (textconv)
            return not any(a in ("-v", "-vv", "--verbose") or (a.startswith("-") and not a.startswith("--") and "v" in a) for a in args[1:])
        return args[0] != "branch" or all(a in _RO_GIT_BRANCH for a in args[1:])
    if prog == "find":
        return not any(a in _RO_FIND_BAD for a in args)
    if prog == "rg":                                      # --pre / --hostname-bin run a program; -z runs decompressors
        return not any(a.startswith(("--pre", "--hostname-bin", "--search-zip")) or (a.startswith("-") and not a.startswith("--")
                                                                                      and "z" in a) for a in args)
    if prog == "file":                                    # -C / --compile writes a magic file
        return not any(a.startswith("--compile") or (a.startswith("-") and not a.startswith("--") and "C" in a) for a in args)
    return True


def read_only_shell(cmd):
    """0.2.33: True only when the Bash command `cmd` surely just reads (see above). False on any doubt."""
    import shlex
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 4096 or not _ro_scan(cmd):
        return False
    try:
        lx = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>")
        lx.whitespace_split, lx.commenters = True, ""
        toks = list(lx)
    except ValueError:
        return False
    seg, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t in ("&&", "||", ";", "|"):
            if not _ro_segment(seg):
                return False
            seg = []
        elif t in (">", ">>", "&>"):
            if i + 1 >= len(toks) or toks[i + 1] != "/dev/null":
                return False
            i += 1
        elif t == ">&":
            if i + 1 >= len(toks) or not toks[i + 1].isdigit():
                return False
            i += 1
        elif t and t[0] in ";&|<>":
            return False                                  # `&`, `>|`, `<<<`, `;;`, `|&`, ...
        else:
            seg.append(t)
        i += 1
    return _ro_segment(seg)


def _config_places(facts, env):
    from ..trial import home_dir, key_path
    out = set()
    for r in {facts.root, facts.env.get("CLAUDE_PROJECT_DIR"), facts.proc_cwd} - {None}:
        # 0.2.33 (red team): all of .git (config, info/attributes, hooks, a worktree's `.git` pointer file), not only .git/hooks
        out |= {os.path.join(r, ".claude"), os.path.join(r, ".mcp.json"), os.path.join(r, ".git")}
    for h in {facts.home, env.get("HOME")} - {None, ""}:
        out |= {os.path.join(h, n) for n in (".claude", ".claude.json", ".deus-witness", os.path.join(".config", "deus-witness"),
                                              ".gitconfig", os.path.join(".config", "git"))}
    out |= {home_dir(env), os.path.dirname(key_path(env))} | _git_config_files(facts, env)
    out |= selfpath.places(env, facts.home)          # 0.2.40 (HN rehearsal 6, K1): this client's own install (venv, package, executable)
    return {x for p in out for x in (os.path.normpath(p), _realpath(p)) if isinstance(x, str)}


def _git_config_files(facts, env):
    """0.2.33: git's global / system configuration named by the environment of the hook (= of Claude Code and its Bash)."""
    out = {"/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig"}
    for e in (env, facts.env):
        for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            if isinstance(e.get(k), str) and _is_abs(e.get(k)):
                out.add(e[k])
        x = e.get("XDG_CONFIG_HOME")
        if isinstance(x, str) and _is_abs(x):
            out.add(os.path.join(x, "git"))
    return {g for g in out if g.rstrip("/\\") and g not in ("/dev/null", os.devnull, "nul", "NUL")}


def _in_git_dir(p):
    """0.2.33: a path inside any `.git` directory (a submodule's, a nested repository's, a worktree's common one) or a `.git` file."""
    parts = re.split(r"[/\\]+", p)
    return any(c.rstrip(". ").lower() == ".git" for c in parts)          # NTFS opens `.git.` / `.GIT` as .git


def agent_config_target(ev, facts, env):
    """-> what makes this call touch the agent's own harness (a path or the word of a command), or None."""
    tool, inp = ev.get("tool_name"), ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
    if tool in WRITE_TOOLS:
        p = inp.get(WRITE_TOOLS[tool])
        if not isinstance(p, str) or not p:
            return None
        cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and _is_abs(ev.get("cwd")) else facts.proc_cwd
        a = p if _is_abs(p) else os.path.join(cwd, p)
        places = _config_places(facts, env)
        for c in {os.path.normpath(a), _realpath(a)} - {None}:
            if any(_under(c, d) for d in places) or _in_git_dir(c):
                return c
        return None
    if tool in SHELL_TOOLS:
        cmd = inp.get("command")
        if not isinstance(cmd, str):
            return None
        m = (_KEY_WORDS if tool == "Bash" and read_only_shell(cmd) else _CONFIG_WORDS).search(cmd)
        if m:
            return m.group(0)
        from ..trial import home_dir
        h = home_dir(env)
        if h and h in cmd:
            return h
        g = next((g for g in sorted(_git_config_files(facts, env)) if g in cmd), None)   # 0.2.33: GIT_CONFIG_GLOBAL, $XDG_CONFIG_HOME/git
        if g:
            return g
        if tool == "Bash" and read_only_shell(cmd):
            return None                                   # reading the client's own files is not changing them
        # 0.2.40 (HN rehearsal 6, K1): the client's own install - `cp x .venv/bin/deus-witness-hook`, a `.pth`, `pip install` into it
        cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and _is_abs(ev.get("cwd")) else None
        roots = {r for r in (facts.root, facts.env.get("CLAUDE_PROJECT_DIR"), cwd or facts.proc_cwd) if isinstance(r, str) and r}
        roots |= {x for x in map(_realpath, list(roots)) if x}
        hm = env.get("HOME") or facts.home
        return selfpath.shell_target(cmd, selfpath.places(env, facts.home), roots, hm if isinstance(hm, str) and _is_abs(hm) else None)
    return None


CONFIG_TEXT = ("(this call changes the agent's own harness: %s - Claude Code settings or hooks, .mcp.json, git hooks or git configuration, "
               "the Deus Witness key files, or the Deus Witness client itself (its venv, package or executable). A change there can switch the witness off, so it runs only after the OWNER approves this "
               "exact call in Witness (passkey), never on the mandate alone. Only reading: `git diff` / `git show` / `git log` pass with "
               "--no-ext-diff --no-textconv)")


def _num(v, default, lo, hi):
    try:
        return max(lo, min(float(v), hi)) if v not in (None, "") else default
    except ValueError:
        return default


# ---------------------------------------------------------------- raw facts
# 0.2.29: members of a tool_input that Claude Code only SHOWS and never runs. The model writes the Bash `description` anew in every run
# ("Sort lines of notes.txt" one night, "Sort lines of notes.txt and print the result" the next: measured in the live run of 0.2.29), so
# with it in the judged call no run ever made "the same call" again and an approval for later runs could never apply. The hook leaves
# these members out of what it sends; the receipt binds the command and everything that changes what runs.
COSMETIC = {"Bash": ("description",)}


def _envelope(ev):
    """The shape every event must have before anything is sent (the witness checks everything else)."""
    if not isinstance(ev, dict):
        raise Fail("EVENT_MALFORMED")
    tool, inp = ev.get("tool_name"), ev.get("tool_input")
    inp = {} if inp is None else inp
    if not isinstance(tool, str) or not tool or len(tool) > 200 or not isinstance(inp, dict):
        raise Fail("EVENT_MALFORMED")
    if RESERVED in inp:
        raise Fail("RESERVED_KEY")
    inp = json.loads(json.dumps(inp))                 # a plain JSON copy: exactly what is sent and compared with the judged call
    if any(k in inp for k in COSMETIC.get(tool, ())):
        for k in COSMETIC[tool]:
            if isinstance(inp.get(k), str):          # only a text label; any other value is sent as it is (the witness judges it)
                del inp[k]
        ev["tool_input"] = inp                        # the event sent to the witness is this same copy
    return tool, inp


def _realpath(p):
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return None                                   # the witness treats it as the error os.path.realpath raised here


# R9-05: the words of a call (split at blanks, shell operators, quotes, `=` and `/`): a path asked about outside the project must be made of them
_WORD_SPLIT = re.compile(r"""[\s;|&<>()`'"=,:{}\[\]$*?!#\\/]+""")
_PATH_FIELDS = ("command", "file_path", "notebook_path", "path", "glob", "url")
_UNQUOTE = re.compile(r"""['"\\]""")
_VAR = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
# names the classifier adds by itself (npx: <a parent of cwd>/node_modules/.bin/<tool>), and where bash puts a process substitution
# `<(...)` (/dev/fd/63: says nothing about this machine)
_DERIVED = {"node_modules", ".bin", ".", ".."}
_CLASSIFIER_DIRS = ("/dev/fd",)


def _strings(x, out):
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, dict):
        for k, v in x.items():
            _strings(k, out)
            _strings(v, out)
    elif isinstance(x, list):
        for v in x:
            _strings(v, out)
    return out


# 0.2.21: paths of this platform. POSIX: exactly as before. Windows: drive paths, both separators, case-insensitive compare.
# `windows` is a parameter only so that tests can run the Windows rules on any OS.
def _flavour(windows):
    return ntpath if (_compat.IS_WINDOWS if windows is None else windows) else posixpath


def _norm(p, windows=None):
    f = _flavour(windows)
    n = f.normpath(p)
    return f.normcase(n).replace("\\", "/") if f is ntpath else n


def _under(p, base, windows=None):
    if _flavour(windows) is ntpath:
        p, base = _norm(p, True), _norm(base, True)
    return p == base or p.startswith(base.rstrip("/") + "/")


def _rest(q, b, windows=None):
    """The path components of `q` below `b`, or None when q is not under b. Windows: both separators, case-insensitive, case kept in the result."""
    if _flavour(windows) is ntpath:
        qq, bb = ntpath.normpath(q).replace("\\", "/"), ntpath.normpath(b).replace("\\", "/").rstrip("/")
        if qq.lower() == bb.lower():
            return []
        if qq.lower().startswith(bb.lower() + "/"):
            return [c for c in qq[len(bb) + 1:].split("/") if c]
        return None
    if not _under(q, b, False):
        return None
    return [c for c in q[len(b):].split("/") if c]


def _is_abs(p, windows=None):
    return _compat.is_abs_path(p, windows)


class Facts:
    def __init__(self, ev, env):
        self.proc_cwd = os.getcwd()
        self.home = _compat.home()
        self.env = {k: env[k] for k in ENV_KEYS if isinstance(env.get(k), str)}
        self.fs = {"realpath": {}, "isdir": {}, "exists": {}, "gitref": {}}    # gitref (0.2.37): the witness may ask what a ref switch rewrites
        self.exec = "off" if self.env.get("DEUS_WITNESS_EXEC_SCAN") == "0" else None
        self.nonce = secrets.token_urlsafe(24)        # R9-01: 192 bits, fresh for every call (and for a re-judge)
        cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and _is_abs(ev.get("cwd")) else self.proc_cwd
        p = self.env.get("CLAUDE_PROJECT_DIR")
        self.root = _realpath(p if isinstance(p, str) and _is_abs(p) else cwd)    # the only directory the hook ever fingerprints
        for x in (cwd, p if isinstance(p, str) and _is_abs(p) else None, self.env.get("HOME") or self.home):
            if x:                                     # asked for every event: sent at once
                self.fs["realpath"][x] = _realpath(x)
        # R9-05: what this call may be asked about
        self.bases = {b for b in (cwd, self.proc_cwd, p if isinstance(p, str) and _is_abs(p) else None, self.home,
                                  self.env.get("HOME"), self.root) if isinstance(b, str) and _is_abs(b)}
        self.bases |= {v for v in self.fs["realpath"].values() if isinstance(v, str)}
        self.words = set()
        inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
        self.sandbox = None                           # V3: how Claude Code's sandbox is set up for this Bash call (the witness judges it)
        if ev.get("tool_name") == "Bash":
            try:
                self.sandbox = sandbox_fact.fact(inp, self.root, env, self.env.get("HOME") or self.home,
                                                transcript=ev.get("transcript_path"), permission_mode=ev.get("permission_mode"))
            except Exception:      # noqa: BLE001  no fact = the witness asks as before
                self.sandbox = None
        self.text = "\0".join(_strings([inp.get(k) for k in _PATH_FIELDS], []))    # a ref asked about must be written in the call
        # only the fields that name paths (not the text of a Write or an Edit: words of a file's content name nothing to look up)
        for t in _strings([inp.get(k) for k in _PATH_FIELDS], []):
            # as written, and with quotes / backslashes / $VAR / ${VAR} taken out (bash joins `"${HOME}/a"1` into one word `<home>/a1`)
            for v in (t, _UNQUOTE.sub("", t), _UNQUOTE.sub("", _VAR.sub("", t))):
                self.words.update(w for w in _WORD_SPLIT.split(v) if w)

    def related(self, p, windows=None) -> bool:
        """R9-05: is `p` a path of THIS call? Inside the project root; a session directory or one of its parents; or one of those plus
        names that all occur as words of the tool_input (or that the classifier derives itself, `_DERIVED`)."""
        if not isinstance(p, str) or not _is_abs(p, windows):
            return False
        f = _flavour(windows)
        nt = f is ntpath
        n = f.normpath(p)
        if (self.root and _under(n, self.root, windows)) or any(_under(n, d, windows) for d in _CLASSIFIER_DIRS):
            return True
        for b in self.bases:
            if _under(b, n, windows):                 # a parent of a session directory (the classifier walks up from cwd)
                return True
        prefixes = {f.splitdrive(b)[0] + "\\" for b in self.bases} if nt else {"/"}
        for b in list(self.bases):                    # a session directory or a parent of one (npx looks upwards from cwd)
            while b not in prefixes:
                prefixes.add(b)
                nb = f.dirname(b)
                if nb == b:
                    break
                b = nb
        for b in prefixes:
            for q in (p, n):
                rest = _rest(q, b, windows)
                if rest is not None and all(c in _DERIVED or all(x in self.words for x in _WORD_SPLIT.split(c) if x) for c in rest):
                    return True                       # (a quoted word may hold blanks: `eval 'cd /etc'` asks about "<cwd>/cd /etc")
        return False

    def prescan(self, w, tool_name):
        """With a cached list that names this tool: walk the project root now, so the witness need not ask (one round less). Never a
        network call, never another directory than the hook's own root."""
        if self.exec is not None or self.root is None:
            return
        try:
            lst = w.scan_list(cached_only=True) if hasattr(w, "scan_list") else None
        except Exception:      # noqa: BLE001  a bad cache: the witness asks, as without one
            lst = None
        if isinstance(lst, dict) and tool_name in (lst.get("prescan_tools") or ()):
            spec = fingerprint.Spec(lst)
            rep = fingerprint.scan(self.root, spec)
            self.exec = dict(fingerprint.with_gitcfg(fingerprint.with_sizes(rep, self.root), self.root, spec), rev=spec.rev) if rep is not None else {"root": self.root, "rev": spec.rev, "none": True}

    def body(self, ev, part=None):
        return {"v": 1, "event": {k: ev.get(k) for k in ("tool_name", "tool_input", "cwd") if k in ev},
                "facts": dict({"home": self.home, "proc_cwd": self.proc_cwd, "env": self.env, "fs": self.fs, "exec": self.exec},
                              **({"sandbox": self.sandbox} if self.sandbox is not None else {})),
                "client": CLIENT, "part": part, "nonce": self.nonce}

    def answer(self, need, w):
        n = 0
        kinds = (("realpath", _realpath), ("isdir", os.path.isdir), ("exists", os.path.exists))
        for kind, _fn in kinds:                       # the whole question is checked before anything is looked at
            asked = need.get(kind) or []
            if not isinstance(asked, list):
                raise Fail("HOOK_ERROR", "(bad witness answer)")
            for p in asked:
                n += 1
                if not isinstance(p, str) or len(p) > 4096 or n > MAX_ASKED:
                    raise Fail("EVENT_TOO_LARGE")
        if not all(self.related(p) for kind, _fn in kinds for p in need.get(kind) or []):
            raise Fail("HOOK_ERROR", "(the witness asked about a path unrelated to this call)")   # R9-05: nothing about the rest of the machine
        for kind, fn in kinds:
            for p in need.get(kind) or []:
                v = fn(p)
                self.fs[kind][p] = v
                if kind == "realpath" and isinstance(v, str):
                    self.bases.add(v)                 # the classifier goes on from where a link of the call points
        refs = need.get("gitref") or []
        if not isinstance(refs, list) or len(refs) > 16 or not all(isinstance(x, list) and len(x) == 2 and all(isinstance(y, str) and 0 < len(y) <= 4096 for y in x)
                                                                  for x in refs):
            raise Fail("HOOK_ERROR", "(bad witness answer)")
        if not all(self.related(top) and _is_abs(top) and (ref == "-" or ref in self.text) for top, ref in refs):
            raise Fail("HOOK_ERROR", "(the witness asked about a path unrelated to this call)")
        for top, ref in refs:                         # 0.2.37: what switching that repository to `ref` rewrites (git plumbing only, gitref.py)
            self.fs["gitref"][top + "\n" + ref] = gitref.answer(top, ref, avoid=(self.root,))
        if "scan" in need:
            if need["scan"] != self.root or self.root is None:
                raise Fail("HOOK_ERROR", "(the witness asked for another directory)")
            spec = fingerprint.Spec(w.scan_list(need.get("scan_rev")))
            rep = fingerprint.scan(self.root, spec)
            self.exec = dict(fingerprint.with_gitcfg(fingerprint.with_sizes(rep, self.root), self.root, spec), rev=spec.rev) if rep is not None else {"root": self.root, "rev": spec.rev, "none": True}


class Part:
    def __init__(self, d, inp, tool_name):
        if not isinstance(d, dict) or not isinstance(d.get("tool"), str) or not isinstance(d.get("args"), dict) or not isinstance(d.get("result"), dict):
            raise Fail("HOOK_ERROR", "(bad witness answer)")
        self.i, self.tool, self.args = d.get("i"), d["tool"], d["args"]
        self.summary = str(d.get("summary") or self.tool)
        self.why = d.get("why") if isinstance(d.get("why"), str) else ""
        # the judged call must be THIS call: exactly the tool_input Claude Code gave, plus the witness' own `_witness`; a receipt for
        # anything else is not used (and its args_sha256 binds the receipt to these args)
        if {k: v for k, v in self.args.items() if k != RESERVED} != inp:
            raise Fail("REQUEST_MISMATCH")
        self.res = ActionResult.from_json(d["result"])


def _ask(w, ev, facts, part=None):
    """One judged answer, after as many fact rounds as the witness needs. -> (answer, the body that got it)."""
    for _ in range(MAX_ROUNDS):
        body = facts.body(ev, part)
        r = w.hook_judge(body)
        if not isinstance(r, dict) or r.get("v") != 1:
            raise Fail("HOOK_ERROR", "(bad witness answer)")
        if isinstance(r.get("need"), dict):
            facts.answer(dict(r["need"], scan_rev=r.get("scan_rev")), w)
            continue
        return r, body
    raise Fail("HOOK_ERROR", "(the witness kept asking for facts)")


def _bound(w, r, body, part, parts, inp, tool_name, verify, tools=None):
    """0.2.17 (R9-01): the parts of answer `r` as [Part], after checking the witness' signed statement: it is for THIS request (nonce, hash of
    the exact body), it lists every part of the call, and the parts in `r` are exactly the judged ones (index, tool, args_sha256, rid,
    verdict, status, reason), none missing: either all parts were judged or the last judged one refused the line. tools: the part list of
    the first answer (a re-judge of one part must name the same parts). Fail(REQUEST_MISMATCH) otherwise."""
    if not isinstance(parts, list) or not parts:
        raise Fail("HOOK_ERROR", "(bad witness answer)")
    got = [Part(d, inp, tool_name) for d in parts]
    if not verify:
        return got, None
    st = w.judge_statement(r.get("statement_b64"))
    if st.get("nonce") != body["nonce"] or st.get("request_sha256") != request_sha256(body) or st.get("part") != part:
        raise Fail("REQUEST_MISMATCH", "(the answer is not for this call)")
    names, n, judged = st.get("parts"), st.get("n_parts"), st.get("judged")
    if not isinstance(names, list) or not names or n != len(names) or not isinstance(judged, list) or len(judged) != len(got) or not judged \
            or (tools is not None and names != tools):
        raise Fail("REQUEST_MISMATCH", "(the set of parts does not match)")
    want = [part] if part is not None else list(range(len(judged)))
    for k, (j, m) in enumerate(zip(judged, got)):
        res = m.res
        if not isinstance(j, dict) or j.get("i") != want[k] or m.i != want[k] or not isinstance(j.get("i"), int) or j["i"] >= n \
                or j.get("tool") != m.tool or names[j["i"]] != m.tool or j.get("args_sha256") != w.args_hash(m.tool, m.args) \
                or (res.action or {}).get("args_sha256", j["args_sha256"]) != j["args_sha256"] or j.get("rid") != res.rid or j.get("verdict") != res.verdict \
                or j.get("status") != res.status or j.get("reason") != res.reason:
            raise Fail("REQUEST_MISMATCH", "(a part does not match the witness' statement)")
    last = got[-1].res
    if part is None and len(got) < n and not (last.verdict == "deny" or last.status in ("refused", "expired")):
        raise Fail("REQUEST_MISMATCH", "(parts are missing from the answer)")
    return got, names


def judge(ev, s: Settings, witness: Witness | None = None, deadline: float | None = None) -> dict:
    """One PreToolUse event -> hook output. Never raises: anything unexpected is a deny."""
    deadline = deadline or (time.monotonic() + s.timeout)
    try:
        tool_name, inp = _envelope(ev)
    except Fail as e:
        log("refused before the witness: %s" % e.code)
        return deny(e.code)
    if not s.key and witness is None:
        return deny("WITNESS_NOT_CONFIGURED", detail="(run `uvx --from deus-witness deus-witness try` in your terminal for a trial account, or set DEUS_WITNESS_KEY; the key is shown once when you create an agent on the Agents page of https://witness.sipkigroup.com)")
    own = witness is None
    if own and s.url_conflict:                            # 0.2.32 (K1): fail-closed, and the key is not sent anywhere
        return deny("WITNESS_URL_MISMATCH", detail="(DEUS_WITNESS_URL is %s, but the agent key on this machine was set up for %s "
                    "(agent-key.json). The hook sends only to the witness the key was set up for. Unset DEUS_WITNESS_URL, or run "
                    "`uvx --from deus-witness deus-witness try --url URL` in your own terminal to move to another witness)" % s.url_conflict)
    w = witness or Witness(s.url, s.key, verify=s.verify, timeout=max(1.0, deadline - time.monotonic()), pin_new=False)
    texts = {}
    try:
        if own:
            # 0.2.32 (K1): a new URL is pinned at first use only when nothing is pinned yet on this machine, or when it is the URL the key
            # file was set up for; otherwise it is another witness, refused (WitnessNotPinned) instead of trusted silently
            pins = w._read_pins()
            w.pin_new = not pins or (s.file_url is not None and w.url == s.file_url)
            if s.verify_off:
                if w.url in pins:
                    w.verify = True
                    log("DEUS_WITNESS_VERIFY=0 ignored: %s has a pinned key, receipts are checked" % w.url)
                elif not w.pin_new:
                    raise WitnessNotPinned(w.url)
        facts = Facts(ev, s.env)
        if w.verify and getattr(w, "_pub", True) is None:
            w.witness_info()                              # the pinned key first: the answer is checked against it
        facts.prescan(w, tool_name)
        r, body = _ask(w, ev, facts)
        texts = r.get("texts") if isinstance(r.get("texts"), dict) else {}
        if r.get("refuse"):
            log("refused by the witness: %s" % r["refuse"])
            return deny(str(r["refuse"]), detail=str(r.get("detail") or ""), texts=texts)
        got, tools = _bound(w, r, body, None, r.get("parts"), inp, tool_name, w.verify)
        results = []
        for m in got:
            res = m.res
            rejudged = 0
            while res.verdict == "defer" and res.status == "pending_approval" and s.wait > 0:
                if res.reason == TRIAL_REASON:
                    _trial_open(res.approval_url, s.env)          # 0.2.28: the trial page (the claim is in that browser, never here)
                wait_s = min(s.wait, _num(s.env.get("DEUS_WITNESS_TRIAL_WAIT"), TRIAL_WAIT_S, 1.0, 900.0)) if res.reason == TRIAL_REASON else s.wait
                end = min(deadline - 1.0, time.monotonic() + wait_s)
                rid = res.rid
                while res.status == "pending_approval" and time.monotonic() < end:
                    if res.reason == TRIAL_REASON and _replaced(s):
                        return deny("TRIAL_REPLACED", res.rid, detail=REPLACED_TEXT)
                    res = w.get(rid, wait=int(max(1, min(25 if res.reason != TRIAL_REASON else 10, end - time.monotonic()))))
                    if res.rid != rid:
                        raise Fail("REQUEST_MISMATCH", "(an answer about another receipt)")
                if res.status != "covered" or not isinstance(m.i, int) or rejudged >= 2 or time.monotonic() >= deadline - 2.0:
                    break
                # 0.2.10: the owner answered with "allow in this project" (a signed allowance, not an approval of THIS receipt), or
                # 0.2.28: a trial account's first touch signed its mandate: the same part is judged again (a new receipt) and, if it is a
                # question now, waited for again within the same deadline
                rejudged += 1
                facts.nonce = secrets.token_urlsafe(24)
                r2, body2 = _ask(w, ev, facts, part=m.i)
                if isinstance(r2.get("texts"), dict):
                    texts.update(r2["texts"])
                if r2.get("refuse") or not isinstance(r2.get("parts"), list) or len(r2["parts"]) != 1:
                    return deny(str(r2.get("refuse") or "HOOK_ERROR"), detail=str(r2.get("detail") or ""), texts=texts)
                m = _bound(w, r2, body2, m.i, r2["parts"], inp, tool_name, w.verify, tools)[0][0]
                res = m.res
            log("tool=%s rid=%s verdict=%s status=%s" % (m.tool, res.rid, res.verdict, res.status))
            results.append((m, res))
            if res.verdict == "deny" or res.status in ("refused", "expired"):
                break                                     # the first refusal decides; nothing is consumed
        for m, res in results:
            if res.verdict == "deny":
                return deny(res.reason or "DENIED", res.rid, texts=texts)
            if res.status in ("refused", "expired") or res.verdict not in ("allow", "pass", "defer"):
                return deny({"refused": "APPROVAL_REFUSED", "expired": "RECEIPT_EXPIRED"}.get(res.status, res.reason or res.status or "UNKNOWN"), res.rid, texts=texts)
        pending = [(m, res) for m, res in results if res.verdict == "defer"]
        if pending:
            for m, r_ in pending:
                if r_.reason == TRIAL_REASON:
                    return deny("TRIAL_NOT_CLAIMED", r_.rid, detail=TRIAL_UNCLAIMED_TEXT, texts=texts, hint=False)   # 0.2.40: said once
            msg = " ".join("Deus Witness: %s is waiting for the owner's approval in Witness (%s, receipt %s)%s%s: %s ." % (
                m.summary, r_.reason, r_.rid, _why(m, r_, texts), _changed(r_), r_.approval_url) for m, r_ in pending) + \
                " After the owner approves there, retry the SAME call."
            if s.wait > 0:
                msg += " (No answer from the owner within %.0f s.)" % s.wait
            if s.on_defer == "ask":
                return decision("ask", msg + " Answering yes here runs it WITHOUT a witness receipt; the safe answer is No: "
                                "approve in Witness, then retry.")
            if s.on_defer == "deny":                      # 0.2.22: the default; the owner decides in Witness, not the person at the terminal
                msg += " Do not try to reach the same effect another way."
            return decision(s.on_defer, msg)
        cfg = agent_config_target(ev, facts, s.env)      # 0.2.32 (K1): the agent's own harness needs the owner's approval
        if cfg and not any(res.status == "approved" for _, res in results):
            log("tool=%s touches the agent's harness without an owner approval" % tool_name)
            return deny("AGENT_CONFIG_UNAPPROVED", results[0][1].rid if results else None, detail=CONFIG_TEXT % cfg)
        allowed = [(m, res) for m, res in results if res.verdict == "allow"]
        for m, res in allowed:                            # check every receipt BEFORE consuming any
            if res.status not in ("allowed", "approved"):
                return deny(res.reason or res.status, res.rid, texts=texts)
            if (res.action or {}).get("args_sha256") != w.args_hash(m.tool, m.args):
                return deny("REQUEST_MISMATCH", res.rid, texts=texts)
            if w.verify:
                w.check(res, sent=(m.tool, m.args))
        for m, res in allowed:
            pr = w.present(res.rid)                       # CONSUME in the ledger BEFORE the tool runs: one receipt, one run
            if pr.get("result") != "accept":
                return deny(str(pr.get("reason", "NOT_ACCEPTED")), res.rid, texts=texts)
        owned = [(m, res) for m, res in allowed if res.reason != "OK_PASS"]   # 0.2.4+: a `pass` call under a signed map is answered allow/OK_PASS WITH a receipt (consumed above); it is still not the mandate's decision
        if not owned or s.allow == "neutral":
            return decision(None)                         # only `pass` parts: Claude Code's own permission rules decide
        return decision("allow", "Deus Witness: allowed by the owner's mandate (%s)" % ", ".join(
            "%s, receipt %s" % (res.reason, res.rid) for _, res in owned))
    except Fail as e:
        log("refused: %s" % e.code)
        return deny(e.code, detail=e.detail, texts=texts)
    except AARError as e:
        log("AAR rejected: %s" % e)
        return deny("AAR_%s" % e)
    except WitnessNotPinned:
        pinned = ", ".join(sorted(w._read_pins())) if hasattr(w, "_read_pins") else ""
        return deny("WITNESS_URL_UNPINNED", detail="(%s is not the witness this machine trusts (pinned: %s), and a new witness is not "
                    "trusted silently. Moving on purpose: run `uvx --from deus-witness deus-witness try --url %s`, or `uvx --from deus-witness deus-witness-hook --trust %s`, in your own "
                    "terminal)" % (w.url, pinned or "none", w.url, w.url))
    except WitnessKeyChanged:
        return deny("WITNESS_KEY_CHANGED")
    except WitnessError as e:
        log("witness error %s %s" % (e.status, e.code))
        if e.status == 401 and e.code == "TRIAL_EXPIRED":
            return deny("BAD_KEY", detail="(the trial account expired and is being erased: run `uvx --from deus-witness deus-witness try` for a new one, or sign up at https://witness.sipkigroup.com)")
        if e.status in (401, 404) and _replaced(s):       # 0.2.29: a newer `deus-witness try` replaced this trial account (its key is gone)
            return deny("TRIAL_REPLACED", detail=REPLACED_TEXT)
        if e.status == 401 or e.code == "BAD_KEY":        # the witness answered and refused the key: not "unreachable"; the call still does not run
            return deny("BAD_KEY", detail="(the agent key is wrong or was deleted: create a new agent on the Agents page of https://witness.sipkigroup.com and use its key, or run `uvx --from deus-witness deus-witness try`)")
        return deny("WITNESS_UNAVAILABLE", detail=e.code)
    except Exception as e:      # noqa: BLE001  whatever goes wrong while judging, the call does not run
        log("cannot judge (%s)" % type(e).__name__)
        return deny("HOOK_ERROR", detail=type(e).__name__)
    finally:
        if own:
            try:
                w.close()
            except Exception:
                pass


def _why(m, res, texts) -> str:
    """The witness' words for the code of this part (it knows what the part is); a code that changed while waiting: its table text."""
    t = m.why if res.reason == m.res.reason else ""
    if not t:
        x = texts.get(res.reason) if isinstance(texts, dict) else None
        t = x[1] if isinstance(x, (list, tuple)) and len(x) == 2 and isinstance(x[1], str) else ""
    return " - " + t if t else ""


def run(stdin_bytes: bytes, env=None) -> dict | None:
    """-> the hook output, or None for an event that is not PreToolUse (no decision)."""
    s = Settings(env)
    try:
        if len(stdin_bytes) > MAX_EVENT:
            return deny("EVENT_TOO_LARGE")
        ev = json.loads(stdin_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return deny("EVENT_MALFORMED")
    if isinstance(ev, dict) and ev.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    out = {}
    deadline = time.monotonic() + s.timeout

    def work():
        out["r"] = judge(ev, s, deadline=deadline)
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(s.timeout)
    if "r" not in out:
        log("no decision within %.0f s" % s.timeout)
        return deny("WITNESS_TIMEOUT", detail="(no answer within %.0f s)" % s.timeout)
    return out["r"]


def _trust(url: str) -> int:
    """0.2.32 (K1): `deus-witness-hook --trust URL`: pin the key of another witness, by a person at a terminal (typed `yes`)."""
    url = _url(url)
    if not url or not url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        print("usage: deus-witness-hook --trust https://WITNESS", file=sys.stderr)
        return 2
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("deus-witness-hook --trust: run it yourself in a terminal (it asks you to type yes); not from a script or an agent", file=sys.stderr)
        return 1
    w = Witness(url, None, pin_new=True)
    try:
        info = w._call("GET", "/v1/witness")
        mine = {"kid_hex": info.get("kid_hex"), "pub_hex": info.get("pub_hex")}
        pins = w._read_pins()
        if pins.get(w.url) == mine:
            print("already pinned: %s kid %s" % (w.url, mine["kid_hex"]))
            return 0
        if pins.get(w.url) is not None:
            print("REFUSED: %s is pinned with another key (%s); the witness key changed. Not replaced." % (w.url, pins[w.url].get("kid_hex")))
            return 1
        print("Witness %s, key id %s. Already trusted here: %s" % (w.url, mine["kid_hex"], ", ".join(sorted(pins)) or "none"))
        if input("Pin this witness key? Type yes: ").strip() != "yes":
            print("not pinned")
            return 1
        pins[w.url] = mine
        w._write_pins(pins)
        print("pinned")
        return 0
    except WitnessError as e:
        print("cannot reach %s (%s)" % (url, e.code), file=sys.stderr)
        return 1
    finally:
        w.close()


def _out(text: str) -> None:
    """stdout as UTF-8 bytes with plain \\n: the same JSON line on every OS (Windows text mode would write cp1252 and CRLF)."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8", "replace"))
    except AttributeError:      # a stdout without .buffer (tests that replace sys.stdout)
        sys.stdout.write(text)


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--print-form"]:
        rest = [a for a in argv[1:] if a != "--no-irreversible"]
        form = default_form(rest[0] if rest else os.getcwd())
        if "--no-irreversible" in argv:
            form["delete"]["allow_irreversible"] = False      # read-only mandate: Write/Edit/redirections are refused everywhere
        print(json.dumps(form, indent=1))
        return
    if argv[:1] == ["--doctor"]:
        r = failsafe.check(argv[1] if len(argv) > 1 else os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        print(failsafe.report_text(r))
        sys.stdout.flush()
        os._exit(1 if r["problems"] or r.get("unsure") else 0)      # 0.2.40: "cannot tell" is not "fail-closed" either
    if argv[:1] == ["--session-start"]:
        try:                                              # a warning only: it never blocks the session
            raw = sys.stdin.read(MAX_EVENT) if not sys.stdin.isatty() else ""
            ev = json.loads(raw) if raw.strip() else {}
            d = (ev.get("cwd") if isinstance(ev, dict) else None) or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
            out = failsafe.session_start_output(failsafe.check(os.environ.get("CLAUDE_PROJECT_DIR") or d))
            if out:
                _out(json.dumps(out, ensure_ascii=False) + "\n")
                log(out["systemMessage"])
        except Exception as e:   # noqa: BLE001
            log("session-start check failed (%s)" % type(e).__name__)
        sys.stdout.flush()
        os._exit(0)
    if argv[:1] == ["--trust"]:
        sys.exit(_trust(argv[1] if len(argv) > 1 else ""))
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return
    try:
        r = run(sys.stdin.buffer.read(MAX_EVENT + 1))
        if r is not None:
            _out((json.dumps(r, ensure_ascii=False) + "\n"))
        sys.stdout.flush()
    except BaseException as e:   # noqa: BLE001  exit 2 is the one non-zero code Claude Code treats as "block"
        try:
            sys.stderr.write("Blocked by Deus Witness: HOOK_ERROR %s\n" % type(e).__name__)
        finally:
            os._exit(2)
    os._exit(0)                  # do not wait for a judging thread stuck on the network


if __name__ == "__main__":
    main()
