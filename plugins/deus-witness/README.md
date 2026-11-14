# Deus Witness - Claude Code plugin

**Auto mode decides what is safe. Deus Witness proves a human said yes to the dangerous part - and to exactly that.**

Unlike the approve buttons of apps such as Pushary and Happy, your passkey signs the hash of the screen you were shown and the hash
of the exact arguments, so a reworded or faked dialog cannot get your signature on another command. Anyone can check the receipt
offline, without us. The whole picture, with a 15-second demo: the [repository README](../../README.md).

## Install

Needs Claude Code 2.1.295+ and uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`, then a new terminal). macOS, Linux, WSL.

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
/deus-witness:try
```

The plugin runs `uvx --from deus-witness==0.2.75 deus-witness-hook` (a pinned PyPI package whose source is in this repository under
`python/`). `try` makes a trial account and opens a page that asks for two passkey touches; until then nothing runs. Fewer questions:
`/deus-witness:quiet`. Details, SSH, an existing account, CI, MCP servers: [docs/install.md](../../docs/install.md);
quiet mode, Linux and WSL2 (`sudo apt install bubblewrap socat` first): [docs/quiet-mode.md](../../docs/quiet-mode.md).

## What this plugin sends, and where

Before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text being written)
to <https://witness.sipkigroup.com> (operated by Sipki LLC) or to the witness in `DEUS_WITNESS_URL`. Along with it go the working
directory, the project and home directory paths (`$HOME`, so your user name too) and `$TMPDIR`; answers to file-system questions the
witness asks about paths named in the call (does it exist, its real path); SHA-256 hashes and paths of project files the call could
execute; a git ref the call switches to; a digest of Claude Code's settings; and, for shell calls, how Claude Code's sandbox is
configured. Not sent: your conversation (prompts and replies), the contents of the files the agent reads, the values of your
environment variables. Masked previews shrink to ~80 characters once the call is decided and to a hash after 30 days. An account
lives while you use it and is erased 90 days after the last hook call or sign-in (a push warns you 14 days before); an unclaimed trial
account whose hook never called is deleted after 7 days. Same list as [docs/data.md](../../docs/data.md);
<https://witness.sipkigroup.com/privacy.html>.

## Quiet mode changes your Claude Code settings

`/deus-witness:quiet` (and `deus-witness-hook --setup-strict` in a terminal) edits **`~/.claude/settings.json`**. Nothing is written until
you approve it: the command first prints what it would change, and the plugin asks you to approve it with your passkey (the agent cannot
approve it). What changes: Claude Code's strict sandbox is switched on for every command the agent runs; the network of those commands
is limited to a short list of hosts (npm, PyPI, GitHub downloads; you add your own with `--host`); the places with keys, the login
keychain and browser cookies are added to `sandbox.filesystem.denyRead`; the Witness key and GitHub / npm / PyPI token names are hidden
from commands (`sandbox.credentials`); `permissions.deny` gets `Read(...)` rules for `~/.ssh`, `~/.aws` and the like; npm and uv caches move
into Claude Code's temp folder (`env`); settings that weaken the sandbox are removed and wide host entries are dropped. The old file is
kept next to it as `~/.claude/settings.json.bak-strict-<date>`, and `uvx --from "deus-witness==0.2.75" deus-witness-hook --undo-strict`
(in your terminal) restores it. Quiet mode starts with your next Claude Code session. Without quiet mode the plugin writes no
Claude Code setting. Line by line: [docs/quiet-mode.md](../../docs/quiet-mode.md).

## Honest limits

- If the witness is unreachable, every call except a read of a non-secret project file is blocked (fail closed).
- Without quiet mode Deus Witness asks about most commands. Containers are not supported for quiet mode.
- The plugin guards the agent, not the machine owner: someone who can edit your Claude Code settings can disable it. A tool or route
  outside the matcher is not witnessed.
- Other hooks that rewrite tool calls (tested: rtk 1.2.0; everything-claude-code 2.2.3 found no conflict on stdin): Claude Code takes
  the rewrite of the hook that finishes last. A call Deus Witness approved is pinned to the input it judged, and a PostToolUse check tells
  you if a different call ran; a hook that finishes later than Deus Witness can still win, and the check only reports it after the fact.
- Early (0.x): no outside users or audits yet.

## Turn it off / remove it

Off for now: `claude plugin disable deus-witness@sipkigroup` in your own terminal, then restart Claude Code. Remove: undo quiet mode
first if you turned it on (`uvx --from "deus-witness==0.2.75" deus-witness-hook --undo-strict`), then
`claude plugin uninstall deus-witness@sipkigroup` and `claude plugin marketplace remove sipkigroup`;
`rm -rf ~/.config/deus-witness` deletes the agent key.

Source: <https://github.com/sipkigroup/witness> (`plugins/deus-witness`). License: Apache-2.0. Service: run by Sipki LLC.
