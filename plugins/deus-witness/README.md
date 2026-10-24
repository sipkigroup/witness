# Deus Witness - Claude Code plugin

Every tool call Claude Code makes (Bash, Edit, Write, Read, Grep, Glob, WebFetch, WebSearch, MCP tools) goes to
[Deus Witness](https://witness.sipkigroup.com) before it runs. The witness checks it against the mandate you signed and answers
`allow`, `deny` or `defer` (wait for your approval on your phone). Every answer is a signed receipt you can verify offline.

## Install

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
```

or in one step (Claude Code 2.1.275+): `/plugin install deus-witness --marketplace sipkigroup/witness`.
From the shell: `claude plugin marketplace add sipkigroup/witness && claude plugin install deus-witness@sipkigroup`.

## Requirements (read this)

The plugin is a thin wrapper. The hook itself is the Python client `deus-witness` (PyPI, Apache-2.0, >= 0.2.27). The plugin finds it:

1. `deus-witness-hook` on your PATH - `pip install "deus-witness>=0.2.27"`, or
2. [uv](https://docs.astral.sh/uv/) - then the plugin runs `uvx --from "deus-witness>=0.2.27" deus-witness-hook`
   (first call downloads the client into the uv cache, about 30 packages).

Also: Claude Code 2.1.295+ (it honours `"onFailure": "block"`), `python3` and `bash` (macOS, Linux, WSL).

## Configure

1. Sign up at <https://witness.sipkigroup.com/signup.html>, create an agent with the **claude-code** preset, copy the key (shown once).
2. In Claude Code: `/plugin` -> deus-witness -> Configure -> `agent_key` (stored in the system keychain, not in settings.json).
   Or export `DEUS_WITNESS_KEY` in the shell that starts Claude Code (the environment wins over the plugin option).

| Option | Default | What |
|---|---|---|
| `agent_key` | empty | Your agent key. Empty = not configured |
| `witness_url` | `https://witness.sipkigroup.com` | Witness server |
| `strict` | `false` | `true`: while no key is set, every matched call is denied |

## What happens when

| State | Tool calls | You see |
|---|---|---|
| No key, `strict` off | Run as without the plugin (**not witnessed**, fail-open) | Session start: "installed but NOT configured" |
| No key, `strict` on | Denied | Session start + the deny reason |
| Key set | Decided by the witness; witness unreachable, client missing, crash or timeout = **blocked** (fail-closed) | The witness reason on every deny |
| Owner approval pending (`defer`) | Waits up to 600 s for your approval in Witness, then denied | - |

Check your setup: `uvx --from "deus-witness>=0.2.27" deus-witness-hook --doctor` - from a plain shell it does not see the plugin's hooks file and reports the hook as missing; inside Claude Code the session-start message is the authoritative check (it runs the same doctor with the plugin's hooks file).

## MCP servers

The plugin does not add an MCP server: `deus-witness-mcp` is a proxy in front of *your* MCP server, so it needs your server's command.
Put it in your own `.mcp.json`: `"command": "uvx", "args": ["--from", "deus-witness", "deus-witness-mcp", "--", "<your server command>", "..."]`.
MCP tool calls are already covered by the hook (`mcp__.*` in the matcher).

## Honest limits

- The plugin cannot protect against someone who can edit your Claude Code settings or disable the plugin; it guards the agent, not the machine owner.
- A tool or route outside the matcher is not witnessed.
- Early (0.x). See the repository README.

Source: <https://github.com/sipkigroup/witness> (`plugins/deus-witness`). License: Apache-2.0. Service: run by Sipki LLC.
