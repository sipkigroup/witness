---
description: Set up Deus Witness in about 2 minutes - a trial account, two passkey prompts in your browser, then the waiting call; no sign-up form
allowed-tools: Bash(deus-witness try), Bash(uvx --quiet --from "deus-witness==0.2.44" deus-witness try)
---
Set up Deus Witness for this project with a trial account. Use the Bash tool to run exactly ONE of these commands in the project
directory, the first that works (do not add arguments):

1. `deus-witness try`
2. `uvx --quiet --from "deus-witness==0.2.44" deus-witness try`

If neither exists, tell the user to install uv (https://docs.astral.sh/uv/) or run `pip install "deus-witness==0.2.44"` (Python 3.10+ in a venv), and stop.

Then tell the user, in a few short sentences, what the command printed:
- what it sent and what the hook will send to the witness (repeat its "will send" list in your own words): `try` already sent a trial
  request with the drafted rules for this project (they contain the project and temp directory paths) and the client version; from now on
  the hook sends the tool name and full input of every call it sees, with the working and project directories;
- a browser page opened; the first call of yours that needs them waits there up to 90 s (then it is refused: ask again after the touches),
  and the page asks for two passkey prompts (Touch ID, Windows Hello or their phone): one creates the passkey, one signs the rules; after
  that the page asks them to decide the waiting call itself.
If it said a previous trial account was replaced, add: use the page that opened last. If it said the trial account already has their
passkey, or when the next trial is possible, tell them exactly that and stop (never add --force yourself).

Rules: do not open, print, search for or repeat any link; do not read or print the key file; do not try to finish the browser page yourself -
after the first touch only the user's passkey signs (before it, a program that controls the user's browser could claim the account, which is why you must not touch the page). If the command says it could not show the link safely, tell the user to run
`uvx --from deus-witness==0.2.44 deus-witness try` themselves in their own terminal (or `deus-witness try` if they installed it with pip).
