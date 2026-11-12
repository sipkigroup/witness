"""06.11 (r0260): law 2 of the Constitution -- what Claude Code's STRICT OS sandbox holds by itself is not asked.

The lock K1 (main.agent_config_target) searches a Bash line's TEXT for the words of the agent's harness (`.claude`, `.git/...`, `git config`,
`.mcp.json` ...), heredoc bodies and quoted arguments included: the thin client has no shell parser. On a developer's corpus most hits are
words inside a patch or a test (`assert ... ".git/hooks/pre-commit"`), not writes. Under a strict sandbox a write the line does NOT show
(code in a heredoc, `python3 -c '...'`) goes through the kernel, and the kernel refuses it in the places below. So:

  held(cmd, ...) is True when the K1 words of the line stand ONLY where the sandbox holds the place itself:
    - the hook's own sandbox fact is strict by the client's mirror (sandbox_fact.strict_reasons: no dangerouslyDisableSandbox, no
      excludedCommands, retry outside the sandbox off, network locked, secrets denied ...), the permission mode is one the witness
      accepts, the settings did not change since the session started, sandbox.filesystem.allowGitConfig is not true;
    - the project is not the home folder (or above it): else ~/.claude would be inside the writable project;
    - the line's WORDS (heredoc bodies cut, quoted text blanked: `skeleton`) have no K1 word at all -- a write the line shows is judged by
      the witness's parser on its own (git-config / persist / agent-config with the path, the Constitution's Н3 / Н4);
    - the WHOLE text names no place the sandbox does NOT hold (UNHELD, below), no key file of the witness, no client install.
  Then the hook sends the sandbox fact with the K1 finding marked `harness_held`; the witness counts the mark as contained ONLY when it
  judges the line strict itself (server hookjudge/mapping.py, sandbox.code_line_ok), and the lock lets the call run only with a signed
  OK_SANDBOXED receipt for it. Anything else: the lock as before (the owner approves in Witness).

HELD -- read from Claude Code 2.1.319 (the sandbox runtime inside the binary, macOS Seatbelt profile; 06.11):
  mandatory write deny in the working directory and below (`**/` regex): .gitconfig .gitmodules .bashrc .bash_profile .zshrc .zprofile
  .profile .ripgreprc .mcp.json; .vscode/** .idea/** .claude/commands/** .claude/agents/**; .git/hooks/** and .git/config (the latter
  unless sandbox.filesystem.allowGitConfig); Claude Code's settings files (.claude/settings.json, .claude/settings.local.json: L2
  OTCHET-L3-PESOCHNICA A4, EPERM); and every place outside the project and the session's temp folder.
NOT HELD (writable inside the project and run later OUTSIDE the sandbox, without the person choosing to run that file):
  .git/modules/*/hooks|config, .git/worktrees/*, .git/config.worktree, .git/info/ (not a `**/.git/hooks` / `**/.git/config` path);
  .husky/, .githooks/ (core.hooksPath), .pre-commit-config.yaml, lefthook*.yml (the git hook runs them on the person's commit);
  .envrc (direnv, on `cd`); .devcontainer (initializeCommand on the host); .claude/hooks/, .claude/skills/ (not on the runtime's list).
  A word of these anywhere in the text keeps the lock (a speed bump only: code can spell a path in pieces -- see the module's
  limits in the r0260 report; the boundary for an adversary is the sandbox, not this text).
"""
from __future__ import annotations

import os
import re

PERMISSION_MODES = ("default", "acceptEdits", "bypassPermissions")      # server hookjudge/sandbox.PERMISSION_MODES_CHECKED

UNHELD = re.compile(
    r"(?i)\.git[. ]*[/\\]+(?:modules|worktrees|info)(?![\w-])|config\.worktree|\.husky(?![\w-])|\.githooks(?![\w-])|"
    r"pre-commit-config|lefthook|\.envrc(?![\w.-])|\.devcontainer|\.claude[/\\]+(?:hooks|skills)(?![\w-])|"
    r"core\.hookspath|hookspath")


def skeleton(cmd):
    """The words of a shell line: quoted text -> '' and heredoc bodies cut (one pass, as bash reads them; quotes / escapes outside). None
    when the line is not read unambiguously (an unterminated quote or heredoc, a delimiter we do not accept): the caller keeps the lock."""
    if not isinstance(cmd, str) or len(cmd) > 200000:
        return None
    out, i, n, q, pend = [], 0, len(cmd), None, []
    while i < n:
        ch = cmd[i]
        if q == "'":
            if ch == "'":
                q = None
                out.append("''")
            i += 1
            continue
        if q == '"':
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                q = None
                out.append("''")
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if ch in "'\"":
            q = ch
            i += 1
            continue
        if cmd.startswith("<<<", i):
            out.append("<<<")
            i += 3
            continue
        if cmd.startswith("<<", i):
            j = i + 2
            strip = j < n and cmd[j] == "-"
            j += 1 if strip else 0
            while j < n and cmd[j] in " \t":
                j += 1
            m = re.match(r"(['\"]?)([A-Za-z_][\w.-]{0,63})\1(?![\w.'\"-])", cmd[j:])
            if not m:
                return None                           # `<<$X`, `<<"a b"`, `<< \EOF`: not this grammar -> keep the lock
            pend.append((m.group(2), strip))
            out.append("<<HEREDOC")
            i = j + m.end()
            continue
        if ch == "\n" and pend:
            out.append("\n")
            i += 1
            for d, strip in pend:
                while True:
                    e = cmd.find("\n", i)
                    line = cmd[i:] if e < 0 else cmd[i:e]
                    if (line.lstrip("\t") if strip else line) == d:
                        i = n if e < 0 else e + 1
                        break
                    if e < 0:
                        return None                   # a body that never ends
                    i = e + 1
            pend = []
            continue
        out.append(ch)
        i += 1
    if q is not None or pend:
        return None
    return "".join(out)


def _under(p, d):
    p, d = os.path.normpath(p), os.path.normpath(d)
    return p == d or p.startswith(d.rstrip("/") + "/")


def strict_enough(fact, home, project) -> bool:
    """The client's own view: is this Bash call in Claude Code's strict sandbox? (The witness judges it again; this only decides whether
    the lock K1 may defer to the witness's signed OK_SANDBOXED for words the sandbox holds.)"""
    from . import sandbox_fact
    if not isinstance(fact, dict) or not isinstance(home, str) or not isinstance(project, str) or not project.startswith("/"):
        return False
    if fact.get("disable_flag") is not False or fact.get("allow_git_config") is True:
        return False
    if fact.get("permission_mode") not in PERMISSION_MODES or fact.get("since_start") != [] or fact.get("doubt") != []:
        return False
    if _under(home, project):
        return False                                  # the project IS the home folder (or above it): ~/.claude is writable "project"
    if "local-root" in (fact.get("sources") or {}):
        return False                                  # the project is a subfolder of its repository: Claude Code also reads the repository
        #                                               root's .claude/settings.local.json, and the runtime's deny list is built from the
        #                                               working directory -- not shown held here (fail closed)
    try:
        return sandbox_fact.strict_reasons(fact, home) == []
    except Exception:      # noqa: BLE001
        return False


def held(cmd, fact, home, project, target_of_words, full_checks) -> bool:
    """True when every K1 word of `cmd` stands where the strict sandbox holds the place (see the module doc).
    target_of_words(text) -> the K1 finding of `text` (main.agent_config_target on a copy of the event), or None;
    full_checks(text) -> a finding on the WHOLE text that never relaxes (key files, the client's install, the witness's home), or None."""
    if not isinstance(cmd, str) or not strict_enough(fact, home, project):
        return False
    if full_checks(cmd) is not None:
        return False
    sk = skeleton(cmd)
    if sk is None:
        return False
    # r0261c (class (в)): a place the sandbox does NOT hold named only inside TEXT (a heredoc body, a quoted argument: a test line, a
    # list in a JSON file the code edits) is claimed held; the witness checks the claim on the text that RUNS (server hookjudge/
    # strict_policy.held_claim_ok: the same words in the line once the literals edit-only code only writes are cut -> not held, asked).
    # In the line's words: never held, as before.
    if UNHELD.search(sk):
        return False
    if target_of_words(sk) is None:
        return True
    return _words_outside_project(sk, home, project, target_of_words)


# 10.11 (r0260, law 2): a K1 word in the line's WORDS that is part of a literal path OUTSIDE the project under the home folder
# (`ls ~/.claude/state`, `bash ~/.claude/tools/x.sh | tail -1`, `grep -c x $HOME/.claude/projects/p/memory/MEMORY.md`): the strict sandbox
# lets the line write only the project and its temp folder, so any write there gets EPERM from the kernel; a write the line SHOWS is
# still judged by the witness's parser on its own (agent-config / persist with the path: asked or refused, never covered by this).
# Kept locked: a path with an expansion / glob / `..`, a relative path (the project's own .claude, .git ...), the home folder's
# places the sandbox does not hold (UNHELD above, searched on the whole text), the key files and the client's install (full_checks),
# and any K1 word that is not inside such a path (`git config`, `--template` ...).
_TOK = re.compile(r"[^\s;&|()<>]+")


def _abs_word(t, home, plain=()):
    t = t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "'\"" else t
    for pre in ("~/", "$HOME/", "${HOME}/"):
        if t.startswith(pre):
            t = home.rstrip("/") + "/" + t[len(pre):]
            break
    # r0261c (class (в)): a loop variable whose every value is a plain word (letters, digits, `_`, `-`: no `/`, no `.`) stays inside its
    # path component; `*` / `?` never match `.` or `..` (bash, zsh) unless the component starts with a dot -- such a path stays below its
    # literal prefix, and the prefix decides
    for v in plain:
        t = re.sub(r"\$\{%s\}|\$%s(?![\w])" % (v, v), "v", t)
    if any(re.match(r"^\.[^/]*[*?]", x) for x in t.split("/")):
        return None
    t = t.replace("*", "g").replace("?", "g")
    if not t.startswith("/") or re.search(r"[$`*?\[\]{}\\'\"]", t) or "/../" in t + "/" or "/./" in t + "/":
        return None
    return os.path.normpath(t)


_FOR = re.compile(r"(?:^|[;&|(\s])for\s+([A-Za-z_]\w*)\s+in\s+([^;&|\n]*?)\s*(?:;|\n)\s*do(?![\w-])")


def _plain_loop_vars(sk):
    """r0261c: `for a in 1a2b 3c4d; do ... $a ...; done` -> {"a"} when every value is a plain word and nothing else on the line sets `a`."""
    out = set()
    for m in _FOR.finditer(sk):
        v, vals = m.group(1), m.group(2).split()
        if not vals or not all(re.fullmatch(r"[A-Za-z0-9_-]+", x) for x in vals):
            continue
        if len(re.findall(r"(?:^|[;&|(\s])for\s+%s\b" % v, sk)) != 1 or \
                re.search(r"(?<![\w$])%s(?:\[[^\]]*\])?\+?=|\b(?:read|export|local|declare|typeset|let|unset|readonly|getopts|mapfile|"
                          r"readarray|printf\s+-v)\b[^;&|\n]*\b%s\b" % (v, v), sk):
            continue
        out.add(v)
    return out


def _words_outside_project(sk, home, project, target_of_words) -> bool:
    if not isinstance(home, str) or not home.startswith("/") or home == "/":
        return False
    plain = _plain_loop_vars(sk)
    rest = []
    for m in _TOK.finditer(sk):
        t = m.group(0)
        tv = t.split("=", 1)[1] if re.match(r"[A-Za-z_][A-Za-z0-9_]*=", t) else t     # `GH_CONFIG_DIR=~/.claude/state/gh`
        if target_of_words(tv) is None:
            rest.append(t)
            continue
        p = _abs_word(tv, home, plain)
        if p is None or not _under(p, home) or _under(p, project) or _under(project, p):
            return False                              # not a literal path outside the project under the home folder
    return target_of_words(" ".join(rest)) is None
