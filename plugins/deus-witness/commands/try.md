---
description: Set up Deus Witness in 2 minutes - a trial account, one passkey touch, no sign-up form
allowed-tools: Bash(deus-witness try), Bash(uvx --quiet --from deus-witness>=0.2.28 deus-witness try)
---
Set up Deus Witness for this project with a trial account. Use the Bash tool to run exactly ONE of these commands in the project
directory, the first that works (do not add arguments):

1. `deus-witness try`
2. `uvx --quiet --from "deus-witness>=0.2.28" deus-witness try`

If neither exists, tell the user to install uv (https://docs.astral.sh/uv/) or run `pip install "deus-witness>=0.2.28"`, and stop.

Then tell the user, in two short sentences, what the command printed: a browser page opened; the first call of yours that needs them
will wait, and that page asks them for ONE passkey touch (Touch ID, Windows Hello or their phone). Nothing else.

Rules: do not open, print, search for or repeat any link; do not read or print the key file; do not try to finish the browser page yourself -
only the user's passkey can, and that is the point. If the command says it could not show the link safely, tell the user to run
`deus-witness try` themselves in their own terminal.
