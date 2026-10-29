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
DEFAULT_SAFE_COMMANDS = ["ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df",
                         "date", "uname", "git status", "git log", "git diff", "git show", "git branch", "diff", "tree", "sort",
                         "uniq", "cut", "tr", "nl", "column", "basename", "dirname", "realpath", "sha1sum", "sha256sum", "sha512sum",
                         "shasum", "cmp", "comm", "test", "sleep", "git blame", "git ls-files", "git rev-parse", "git describe",
                         "git shortlog", "git grep", "git reflog",
                         "mkdir", "touch", "cp", "mv", "ln", "chmod", "rm", "rmdir", "git add", "git commit", "git checkout",
                         "git switch", "git restore", "git mv", "git rm",
                         "find", "sed", "awk", "jq"]


# 0.2.56 (V3): command.sandboxed = "allow" in the RECOMMENDED form: a test runner (pytest, npm test, make ...) runs without a question only
# while the hook reports that THIS call runs inside a strict Claude Code sandbox (macOS Seatbelt, no network, secrets unreadable, no retry
# outside it: server/app/hookjudge/sandbox.py); without that sandbox every runner is asked as before. A mandate signed WITHOUT this key is
# never widened: the core allows OK_SANDBOXED only when the signed mandate says "allow" (svidetel_v4/decide.py). Same value: the Mandate
# page's recommended section (web/js/mandate_form.js RECOMMENDED_SANDBOXED); a test keeps them equal.
DEFAULT_SANDBOXED = "allow"


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


def default_form(project_dir: str, web_domains=None, safe_commands=None, home=None) -> dict:
    """Recommended mandate form for a Claude Code agent (the 'default rules'):
      - writes (Write/Edit/NotebookEdit/Bash redirections) only inside the project and the temp dir; elsewhere deny RESOURCE;
        0.2.32 (K1): EXCEPT the agent's own harness (<proj>/.claude/**, <proj>/.mcp.json, <proj>/.git/hooks/**, ~/.claude/**, the Deus
        Witness key files): the mandate format has no exclusions, so the witness asks the owner for those (category agent-config /
        git-config) and the hook itself refuses them without an owner-approved receipt (hook/main.py agent_config_target);
      - shell commands: the listed read-only commands run, any other is asked, a dangerous one is always asked; reading a credential
        file is asked;
      - WebFetch only to the listed domains; elsewhere deny RECIPIENT;
      - no purchases.
    29.10: raises ProjectRefused for '/', the home directory or a folder above it (see refuse_reason)."""
    why = refuse_reason(project_dir, home)
    if why:
        raise ProjectRefused(why)
    proj = os.path.realpath(_expand(project_dir, home))
    tmp = os.path.realpath(tempfile.gettempdir())
    return {"currency": "USD", "valid_days": 30, "purchase": None,
            "message": {"domains": list(DEFAULT_WEB_DOMAINS if web_domains is None else web_domains), "to": []},
            "forbidden_data": [], "publish": None,
            "delete": {"targets": [proj + "/*", tmp + "/*"], "allow_irreversible": True},
            "command": {"allow": list(DEFAULT_SAFE_COMMANDS if safe_commands is None else safe_commands), "unlisted": "ask",
                        "sandboxed": DEFAULT_SANDBOXED}}
