---
description: Quiet mode - Claude Code's own strict sandbox, so Witness asks far fewer questions; see the change first, you approve it with your passkey
allowed-tools: Bash(deus-witness-hook --quiet-offer), Bash(uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --quiet-offer), Bash(deus-witness-hook --quiet-offer --full), Bash(uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --quiet-offer --full), Bash(deus-witness-hook --setup-strict --yes), Bash(uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --setup-strict --yes), Bash(deus-witness-hook --quiet-no), Bash(uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --quiet-no)
---
Use the Bash tool to run exactly ONE of these, the first that works (no other arguments):

1. `deus-witness-hook --quiet-offer`
2. `uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --quiet-offer`

It changes nothing; it prints a line that starts with `QUIET MODE:`.
- `QUIET MODE: offer.` - tell the user in three short sentences: what quiet mode is (Claude Code's own strict sandbox: commands reach
  only the listed hosts - npm, PyPI and GitHub downloads work - and cannot read their keys, keychain or browser cookies; Witness then asks
  only about what could leave the computer or cannot be undone); what stays (their permission mode, their other environment variables such as
  OPENAI_API_KEY; hidden from commands: the Witness key and GitHub / npm / PyPI tokens) and the one thing that changes (a push or publish
  the agent runs cannot use their login, and git clone / git init into the project fail: they run those in their own terminal); then
  show the short list of what changes in ~/.claude/settings.json exactly as printed (the lines that start with `- `; do not show more).
  If they want the line-by-line change, run the same command with `--full`. Their own hosts are added with `--host` in their terminal.
  Then ASK the user: turn it on?
  - yes: run exactly ONE command with the same runner: `deus-witness-hook --setup-strict --yes` or
    `uvx --quiet --from "deus-witness==0.2.75" deus-witness-hook --setup-strict --yes`. Witness asks the USER to approve it (passkey);
    you cannot approve it. If it printed `written:`, say quiet mode starts with their next Claude Code session (/exit, then start claude
    again). If it was refused or not answered, say so and stop; do not retry.
  - no: run `deus-witness-hook --quiet-no` (or the uvx form) - no more reminders at session start - and stop.
- `QUIET MODE: on` - say it is already on (to turn it off: `deus-witness-hook --undo-strict` in their own terminal).
- `QUIET MODE: not ready` (Linux / WSL2) - tell the user, in plain words, what the line says to install or switch (for example
  `sudo apt install bubblewrap socat`), that they run it in their own terminal, and to run /deus-witness:quiet again after. Do not run
  it yourself, and stop.
- `QUIET MODE: not supported` or `QUIET MODE: macOS only` (an older client) - repeat that sentence and stop.
Never edit settings.json yourself, never add --host yourself, and never run --undo-strict.
