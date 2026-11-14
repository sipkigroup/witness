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

The plugin runs `uvx --from deus-witness==0.2.73 deus-witness-hook` (a pinned PyPI package whose source is in this repository under
`python/`). `try` makes a trial account and opens a page that asks for two passkey touches; until then nothing runs. Fewer questions:
`/deus-witness:quiet`. Details, SSH, an existing account, CI, MCP servers: [docs/install.md](../../docs/install.md);
quiet mode, Linux and WSL2 (`sudo apt install bubblewrap socat` first): [docs/quiet-mode.md](../../docs/quiet-mode.md).

## What this plugin sends, and where

Before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text being written)
to <https://witness.sipkigroup.com> (operated by Sipki LLC) or to the witness in `DEUS_WITNESS_URL`, with the working, project and
home directory paths (`$HOME`, so your user name too). Your conversation is not sent. Full list: [docs/data.md](../../docs/data.md),
<https://witness.sipkigroup.com/privacy.html>.

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
first if you turned it on (`uvx --from "deus-witness==0.2.73" deus-witness-hook --undo-strict`), then
`claude plugin uninstall deus-witness@sipkigroup` and `claude plugin marketplace remove sipkigroup`;
`rm -rf ~/.config/deus-witness` deletes the agent key.

Source: <https://github.com/sipkigroup/witness> (`plugins/deus-witness`). License: Apache-2.0. Service: run by Sipki LLC.
