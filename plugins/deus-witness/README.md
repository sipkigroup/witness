# Deus Witness - Claude Code plugin

Every tool call Claude Code makes (Bash, Edit, Write, Read, Grep, Glob, WebFetch, WebSearch, MCP tools) goes to
[Deus Witness](https://witness.sipkigroup.com) before it runs. The witness checks it against the mandate you signed and answers
`allow`, `deny` or `defer` (wait for your approval: on the witness page in your browser, or on your phone once you set up a channel in a full
account). A decision made against your mandate gets a signed receipt you can verify offline; a few automatic refusals (e.g. no mandate yet, a
rate limit) are kept only in the server database.

## What this plugin sends, and where

Before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text being written) to the witness server at <https://witness.sipkigroup.com> (operated by Sipki LLC), or to the `witness_url` you set. Along with it go the working directory, the project and home directory paths, answers to file-system questions the witness asks about paths named in the call (does it exist, its real path), SHA-256 hashes and paths of project files the call could execute, and, for shell calls, how Claude Code's sandbox is configured. Your conversation (prompts and replies) is not sent. Masked previews shrink to ~80 characters once the call is decided and to a hash after 30 days; a trial account you don't keep is erased after 7 days. Full details: <https://witness.sipkigroup.com/privacy.html>

The plugin needs uv; it runs `uvx --from deus-witness==0.2.49 deus-witness-hook` (a pinned PyPI package whose source is in this repository under `python/`).

## Install

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
```

or in one step (Claude Code 2.1.275+): `/plugin install deus-witness --marketplace sipkigroup/witness`.
From the shell: `claude plugin marketplace add sipkigroup/witness && claude plugin install deus-witness@sipkigroup`.

## Requirements (read this)

The plugin is a thin wrapper. The hook itself is the Python client `deus-witness` (PyPI, Apache-2.0, >= 0.2.34). The plugin finds it:

1. [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`) - then the plugin runs `uvx --from "deus-witness==0.2.49" deus-witness-hook`
   (first call downloads the client into the uv cache, about 30 packages). This is the way we test.
2. `deus-witness-hook` on your PATH - `pip install "deus-witness==0.2.49"`, only with Python 3.10+ in a venv (the stock macOS Python 3.9 and
   PEP 668 system Pythons refuse it). Put that venv OUTSIDE the project: the agent may write inside the project, so the plugin does not
   use a `deus-witness-hook` (or any program) found on PATH inside the project - it falls back to uvx, or blocks the call without uv.

Requirements: Claude Code 2.1.295+ (it honours `"onFailure": "block"`) and uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`); `python3` and `bash`; macOS, Linux, WSL.

## Set up in 2 minutes (trial, no sign-up form)

In Claude Code: `/deus-witness:try` (or in your own terminal: `uvx --from "deus-witness==0.2.49" deus-witness try`).
It prints what the hook sends to the witness, saves a trial agent key to `~/.config/deus-witness/agent-key.json` (mode 600; the plugin
picks it up at once) and opens a page in your browser. The first call of the agent that needs you waits; on that page ONE button asks
for two passkey touches (Touch ID / Windows Hello / phone): one makes your passkey, one signs the recommended rules for the project. The
call that waited is then decided by those rules at once: allowed, refused (e.g. a secret written to `.env`), or - if the rules say
"ask" (e.g. `git push`) - shown on the next screen for one more touch. Nothing is allowed before the first touch. Honest limit: until
that first touch, a program that controls your browser profile (or whoever holds the claim link) could claim the account first - an agent with a shell may be such a program; after the first touch only your passkey signs. The trial account is erased after 7 days unless you press "Keep this account" on that page.

Ran `/deus-witness:try` twice? The newer run replaces the older trial while it has no passkey yet: use the page that opened LAST (an
older page says it was replaced). A trial that already has your passkey is kept (`try` refuses to replace it; `--force` makes a new one).
Too many trials from one network (10 an hour): the message says when the next one is possible; a page already open keeps working.

### "3 userConfig options not yet set" after install

That line is printed by Claude Code itself for every plugin option that has no saved value (`agent_key`, `witness_url`, `strict`). It
is not an error and needs no action: the trial path (`/deus-witness:try`) uses no option at all, and `witness_url` / `strict` have
working defaults. Set `agent_key` only if you already have a full account (below).

## Configure (an existing account)

1. Sign up at <https://witness.sipkigroup.com/signup.html>, create an agent with the **claude-code** preset, copy the key (shown once).
2. In Claude Code: `/plugin` -> deus-witness -> Configure -> `agent_key` (stored in the system keychain, not in settings.json).
   Or export `DEUS_WITNESS_KEY` in the shell that starts Claude Code (the environment wins over the plugin option).

| Option | Default | What |
|---|---|---|
| `agent_key` | empty | Your agent key. Empty = the key saved by `/deus-witness:try`, if any; none = not set up |
| `witness_url` | `https://witness.sipkigroup.com` | Witness server |
| `strict` | `false` | `true`: while no key is set, every matched call is denied |

## What happens when

| State | Tool calls | You see |
|---|---|---|
| No key, `strict` off | Run as without the plugin (**not witnessed**) | Session start and the first call of each session: "not set up ... run /deus-witness:try" |
| No key, `strict` on | Denied | Session start + the deny reason |
| Key set | Decided by the witness; witness unreachable, client missing, crash or timeout = **blocked** (fail-closed) | The witness reason on every deny |
| Owner approval pending (`defer`) | Waits up to 600 s for your approval in Witness, then denied | - |
| Trial account, nobody has touched the page yet | Waits 90 s, then denied (`TRIAL_NOT_CLAIMED`) | "touch the passkey, then ask again" |

Check your setup: `uvx --from "deus-witness==0.2.49" deus-witness-hook --doctor` - from 0.2.41 on it finds the plugin from a plain shell too (Claude Code's plugin registry and `enabledPlugins`) and the key file `try` saved; when no settings file says whether the plugin is enabled it says "CANNOT TELL" instead of guessing. Inside Claude Code the session-start message is the authoritative check.

CI and cron: `claude --bare` (and `CLAUDE_CODE_SIMPLE=1`) skips the hooks of plugins, so this plugin does not run and nothing says so; Claude Code's docs say `--bare` will become the default for `claude -p` in a future release. Run `uvx --from "deus-witness==0.2.49" deus-witness run -- claude -p "..."`: it refuses `--bare` before the run and exits non-zero after it when no Witness hook ran.

## MCP servers

The plugin does not add an MCP server: `deus-witness-mcp` is a proxy in front of *your* MCP server, so it needs your server's command.
Put it in your own `.mcp.json`: `"command": "uvx", "args": ["--from", "deus-witness==0.2.49", "deus-witness-mcp", "--", "<your server command>", "..."]`.
MCP tool calls are already covered by the hook (`mcp__.*` in the matcher).

## Honest limits

- The plugin cannot protect against someone who can edit your Claude Code settings or disable the plugin; it guards the agent, not the machine owner.
- A tool or route outside the matcher is not witnessed.
- Early (0.x). See the repository README.

Source: <https://github.com/sipkigroup/witness> (`plugins/deus-witness`). License: Apache-2.0. Service: run by Sipki LLC.
