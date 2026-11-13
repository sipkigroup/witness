---
description: Set up Deus Witness in about 2 minutes - a trial account, two passkey prompts in your browser, then the waiting call; no sign-up form
allowed-tools: Bash(deus-witness try), Bash(uvx --quiet --from "deus-witness==0.2.67" deus-witness try), Bash(deus-witness-hook --setup-strict --yes), Bash(uvx --quiet --from "deus-witness==0.2.67" deus-witness-hook --setup-strict --yes)
---
Set up Deus Witness for this project with a trial account. Use the Bash tool to run exactly ONE of these commands in the project
directory, the first that works (do not add arguments):

1. `deus-witness try`
2. `uvx --quiet --from "deus-witness==0.2.67" deus-witness try`

If neither exists, tell the user to install uv (https://docs.astral.sh/uv/) or run `pip install "deus-witness==0.2.67"` (Python 3.10+ in a venv), and stop.

Then tell the user, in a few short sentences, what the command printed:
- what it sent and what the hook will send to the witness (repeat its "will send" list in your own words): `try` already sent a trial
  request with the drafted rules for this project (they contain the project and temp directory paths) and the client version; from now on
  the hook sends the tool name and full input of every call it sees, with the working and project directories;
- a browser page opened; the first call of yours that needs them waits there up to 45 s (then it is refused: ask again after the touches),
  and the page asks for two passkey prompts (Touch ID, Windows Hello or their phone): one creates the passkey, one signs the rules; after
  that the page asks them to decide the waiting call itself.
If it said a previous trial account was replaced, add: use the page that opened last. If it said the trial account already has their
passkey, or when the next trial is possible, tell them exactly that and stop (never add --force yourself).

Quiet mode: if the output has a line that starts with `QUIET MODE: offer-now.`, end by asking the user ONE question, in your own words:
without quiet mode Witness asks about most commands (tests, installs, a virtualenv); with it (Claude Code's own strict sandbox: commands
reach only GitHub / npm / PyPI and cannot read their keys) it asks only about what could leave the Mac or cannot be undone - turn it on now?
They approve it with their passkey; it starts with their next Claude Code session; /deus-witness:quiet shows the exact change first.
- yes: AFTER they have done the two passkey touches on the page, run exactly ONE command with the same runner as above:
  `deus-witness-hook --setup-strict --yes` or `uvx --quiet --from "deus-witness==0.2.67" deus-witness-hook --setup-strict --yes`.
  Witness asks the USER to approve it (passkey); you cannot approve it. If it printed `written:`, say quiet mode starts with their next
  Claude Code session (/exit, then start claude again). If it was refused or not answered, say so and stop; do not retry.
- anything else: say they can turn it on later with /deus-witness:quiet, and stop.
If the line starts with `QUIET MODE: on` or `QUIET MODE: later.` (the user answered in a terminal), say it in one sentence. Never edit
settings.json yourself and never run --undo-strict.

Rules: do not open, print, search for or repeat any link; do not read or print the key file; do not try to finish the browser page yourself -
after the first touch only the user's passkey signs (before it, a program that controls the user's browser could claim the account, which is why you must not touch the page). If the command says it could not show the link safely, tell the user to run
`uvx --from deus-witness==0.2.67 deus-witness try` themselves in their own terminal (or `deus-witness try` if they installed it with pip).
