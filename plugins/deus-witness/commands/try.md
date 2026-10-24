---
description: Set up Deus Witness in about 2 minutes - a trial account, two passkey prompts in your browser, then the waiting call; no sign-up form
allowed-tools: Bash(deus-witness try), Bash(uvx --quiet --from "deus-witness>=0.2.29" deus-witness try)
---
Set up Deus Witness for this project with a trial account. Use the Bash tool to run exactly ONE of these commands in the project
directory, the first that works (do not add arguments):

1. `deus-witness try`
2. `uvx --quiet --from "deus-witness>=0.2.29" deus-witness try`

If neither exists, tell the user to install uv (https://docs.astral.sh/uv/) or run `pip install "deus-witness>=0.2.29"`, and stop.

Then tell the user, in two short sentences, what the command printed: a browser page opened; the first call of yours that needs them
will wait, and that page asks them for two passkey prompts (Touch ID, Windows Hello or their phone): one creates the passkey, one signs the rules; after that the page asks them to decide the waiting call itself. Nothing else.
If it said a previous trial account was replaced, add: use the page that opened last. If it said the trial account already has their
passkey, or when the next trial is possible, tell them exactly that and stop (never add --force yourself).

Rules: do not open, print, search for or repeat any link; do not read or print the key file; do not try to finish the browser page yourself -
only the user's passkey can, and that is the point. If the command says it could not show the link safely, tell the user to run
`deus-witness try` themselves in their own terminal.
