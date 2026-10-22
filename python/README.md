<!-- mcp-name: io.github.sipkigroup/witness -->
# deus-witness

MCP proxy and SDK for Deus Witness: every tool call of your agent is checked by an independent witness
before it runs, and you get a signed receipt for it.

## Install
```
pip install deus-witness
```
(or `pipx install deus-witness`). Then one entry in your MCP client config (the example of the quickstart and of the dashboard; the bundled demo tools, nothing real happens; after `--` put the command of the MCP server you want witnessed):
```json
{"mcpServers": {"witnessed": {"command": "deus-witness-mcp",
  "args": ["--", "deus-witness-demo-tools"],
  "env": {"DEUS_WITNESS_KEY": "dwk_YOUR_KEY", "DEUS_WITNESS_URL": "https://witness.sipkigroup.com", "DEUS_DEMO_OUT": "/Users/you/dw-demo"}}}}
```
Without installing: `uvx deus-witness -- <upstream MCP server command...>` (e.g. `uvx deus-witness -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox`) runs the same proxy as `deus-witness-mcp -- <upstream...>` (this is the launch form of the MCP Registry entry). `DEUS_WITNESS_KEY` must be set in the environment.
Where to get the key: sign up on https://witness.sipkigroup.com, then on the dashboard card **Agents** create an agent; the key `dwk_...` is shown once (quickstart step 2: https://witness.sipkigroup.com/dl/docs/quickstart.html). Without a key the proxy does not start (`deus-witness-mcp: set DEUS_WITNESS_KEY ...`); a key the witness refuses ends every call with `Blocked by Deus Witness: BAD_KEY ...` (create a new agent and use its key). In both cases nothing runs.

Fallback: a wheel is also served at `https://witness.sipkigroup.com/dl/` .

Behaviour per `tools/call`: `pass` -> forwarded; `allow` -> receipt verified (witness key pinned at first use in
`~/.config/deus-witness/witness.json`), then `present`, then the tool runs, then `report`; `deny` -> the tool is NOT called,
the agent gets `Blocked by Deus Witness: <reason> (receipt <rid>)`; `defer` -> waits up to ~50 s for the owner, then the agent gets an error result that says
`Action NOT executed: waiting for the owner's approval.`, the receipt id (`rid`) and how to retry (see "Waiting for approval / timeouts"
below). If the witness is unreachable the call is blocked (fail closed). `tools/list`, resources, prompts and notifications pass through untouched. The proxy log (stderr) holds only tool, rid, verdict.

0.2: `status: held` (held by the advisor for owner review) is waited for like `defer`, then the agent gets
`Held by advisor for owner review at <url>. Action NOT executed.` (with the rid and the same retry instruction).

At start (after the client's `initialized`) the proxy asks the upstream for `tools/list` itself (the answer is not shown to
the client), sends it as `POST /v1/catalog` (the server suggests a strict toolmap from it), runs the light doctor (configs
only, no network) and sends `POST /v1/coverage`; once per run, before the first call is judged. If the witness cannot be
reached at that moment, every call of the run is blocked (fail closed). An HTTP error there (e.g. a 0.1 server) is only logged.

Env: `DEUS_WITNESS_KEY` (required), `DEUS_WITNESS_URL`, `DEUS_WITNESS_WAIT` (s per long poll, 25), `DEUS_WITNESS_POLLS` (2), `DEUS_WITNESS_HOLD_MAX_S` (how long one call may wait for the owner; default 50 = WAIT x POLLS; 0.2.22),
`DEUS_WITNESS_VERIFY=0` or `--no-verify-aar` (testing against a stub that does not sign).

## Waiting for approval / timeouts
When the witness holds an action for the owner, the proxy does **not** run it. What the agent sees (an ordinary tool result with `isError: true`, not a protocol error):
```
Action NOT executed: waiting for the owner's approval.
Receipt (rid): r_...
The owner can approve it at: https://witness.sipkigroup.com/approve.html?rid=r_...
After the owner has approved, retry the exact same call (same tool, same arguments). Do not change the arguments.
```
After the owner approved, the repeated call (same tool and arguments) gets the same receipt and runs at once, exactly once. The proxy waits up to
`DEUS_WITNESS_HOLD_MAX_S` seconds (default 50, as before) inside one call; the witness keeps the held action for 15 minutes or more.

**Cancel (0.2.22).** If the MCP client cancels the call (`notifications/cancelled`, e.g. because its own tool timeout ran out, or you stopped the task), the proxy stops
waiting, tells the witness `report executed=false` and never forwards that call: an approval that arrives later does not run anything behind the agent's back.
The cancelled request gets no answer, as the MCP specification says. The repeated call is judged afresh; if the owner approved meanwhile, it runs once.

**Progress (0.2.22).** If the call carries `_meta.progressToken`, the proxy sends `notifications/progress` (no percentage, message `waiting for owner approval`) about every 12 s
while it waits. Clients that restart their timeout on progress (the MCP specification allows it, it does not require it) then wait longer.

| Client | Tool timeout | What to do |
|---|---|---|
| Claude Code (CLI) | `timeout` per server in `.mcp.json` (ms), else `MCP_TOOL_TIMEOUT`; unset = about 28 h. Idle (no response, no progress): 30 min for stdio (`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`). A main-conversation call still running after 2 min moves to a background task | May wait long: `DEUS_WITNESS_HOLD_MAX_S=600` in `env` and, if you set a timeout, `"timeout": 700000` in the server entry (more than the hold time) |
| Cursor | about 60 s for stdio, not configurable, progress does not extend it (user reports, no official statement) | Leave the default 50 s (margin); when the agent gets the "NOT executed" text, approve and let it repeat the call. Do not raise `HOLD_MAX_S` |
| Claude Desktop | about 60 s, the `timeout` of the config is not honoured (user reports) | Same as Cursor |

Claude Code, from https://code.claude.com/docs/en/mcp (checked 22.10.2026): "Set a per-server tool execution timeout by adding a `timeout` field in milliseconds to that server's `.mcp.json` entry, for example `"timeout": 600000` for ten minutes. This overrides the `MCP_TOOL_TIMEOUT` environment variable for that server only." and "The per-server timeout is a hard wall-clock limit per tool call, and progress notifications from the server don't extend it."
```json
{"mcpServers": {"witnessed": {"command": "deus-witness-mcp", "args": ["--", "your-mcp-server"], "timeout": 700000,
  "env": {"DEUS_WITNESS_KEY": "dwk_YOUR_KEY", "DEUS_WITNESS_HOLD_MAX_S": "600"}}}}
```
`HOLD_MAX_S` is capped at 3600; the witness' own limit for a held action (15 minutes by default) also applies: after it the call ends with `RECEIPT_EXPIRED`.
The Cursor and Desktop figures are reports of other users, not measured here. The Claude Code hook (`deus-witness-hook`) has its own waits (`DEUS_WITNESS_HOOK_WAIT`, below).

Windows: the proxy reads stdin in a thread and finds `npx` as `npx.cmd`; this is new in 0.2.21 and was tested on macOS/Linux and in CI only. If something fails on Windows, please report it.

## Doctor: where can the agent go around the witness
```
deus-witness doctor [--json] [--no-network] [--project DIR]
```
Reads (never writes) the client configs: Claude Desktop (`claude_desktop_config.json`), Claude Code (`~/.claude.json`,
`~/.claude/settings.json`, project `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`), Cursor
(`~/.cursor/mcp.json`). Prints `coverage: C0|C1|C2|C3` and one `bypass: <what> -> <how to close>` per hole; rc 0 for C2/C3, 2 for C0/C1.
- C0: no MCP server is behind `deus-witness-mcp` (a server is behind it when its `command` is `deus-witness-mcp`).
- C1: proxy in place, but a server is not behind it, or Claude Code's Bash/Write/Edit/WebFetch are not in `permissions.deny`,
  or a pass tool has a network effect (known to the proxy at start from the agent toolmap), or Cursor's built-in agent tools.
- C2: all MCP servers behind the proxy and those built-ins denied. C3: C2 + no `/bin/sh` + egress to 1.1.1.1:443 and
  example.com:443 refused (only probed without `--no-network`; the sandbox recipe gives it).

The level is a claim of the operator made from local files, not a proof; the output says so. `--no-network` opens no socket.

## Claude Code hook (built-in tools)
`deus-witness-hook` is a Claude Code PreToolUse hook: `Bash`, `Edit`, `Write`, `NotebookEdit`, `Read`, `WebFetch` and `mcp__*` calls are
judged by the witness before they run. Answers `allow` / `deny` / `ask`; fail closed. It is a thin client: it sends the call as Claude Code
gave it (the command line, paths, cwd, `CLAUDE_PROJECT_DIR`), the realpath / existence of the paths the witness asks about and SHA-256
fingerprints of project files from a list the witness signs; the witness classifies and decides, the hook verifies the signed receipts. What leaves the machine:
https://witness.sipkigroup.com/dl/docs/coverage.html and the privacy notice on https://witness.sipkigroup.com.

Set-up (full text: https://witness.sipkigroup.com/dl/docs/quickstart.html, section "Claude Code hook"):
1. Create an agent with the `claude-code` preset on the Agents page and copy its key.
2. Print the recommended mandate and import it on the Mandate page (**Import from JSON**, then review and sign):
   ```
   uvx --from deus-witness deus-witness-hook --print-form /path/to/your/project
   ```
   (`uvx deus-witness-hook` alone does not work: the command lives in the package `deus-witness`.) The form lets Write / Edit and shell redirections work inside the project and the temp directory (`delete.allow_irreversible: true`: the witness judges a write as an irreversible delete of its path); `--no-irreversible` prints a read-only form that refuses every write.
3. Put this into `<project>/.claude/settings.json` (or `~/.claude/settings.json`). The key does NOT go into this file: `export DEUS_WITNESS_KEY=dwk_...` in the shell that starts `claude`, or `env` in `<project>/.claude/settings.local.json`.
```json
{"hooks": {
  "SessionStart": [{"hooks": [{"type": "command", "command": "uvx --from deus-witness deus-witness-hook --session-start", "timeout": 15}]}],
  "PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Read|Grep|Glob|LS|WebFetch|WebSearch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*",
    "hooks": [{"type": "command", "command": "uvx --from deus-witness deus-witness-hook || exit 2", "timeout": 30, "onFailure": "block"}]}]},
 "env": {"DEUS_WITNESS_URL": "https://witness.sipkigroup.com", "DEUS_WITNESS_HOOK_TIMEOUT": "20"}}
```
   After `pip install deus-witness` / `pipx install deus-witness` write `deus-witness-hook` instead of `uvx --from deus-witness deus-witness-hook`. Keep all three layers: the hook denies itself on every error, `|| exit 2` blocks when the command is missing or broken, `"onFailure": "block"` blocks on a timeout or crash (Claude Code 2.1.295 or newer; older versions silently drop it). Keep `DEUS_WITNESS_HOOK_TIMEOUT` at least 5 s below `timeout`.
4. Check: `uvx --from deus-witness deus-witness-hook --doctor "$PWD"` must print `OK: fail-closed ...` (exit 0); in Claude Code `/hooks` lists the hook.
5. Add a second layer, Claude Code's own `permissions.deny` (recommended), into the same `settings.json`:
```json
{"permissions": {"deny": [
  "Bash(curl *)", "Bash(wget *)", "Bash(nc *)", "Bash(ncat *)", "Bash(telnet *)", "Bash(ssh *)", "Bash(scp *)", "Bash(sftp *)", "Bash(rsync *)",
  "WebFetch(domain:gist.github.com)", "WebFetch(domain:gist.githubusercontent.com)", "WebFetch(domain:raw.githubusercontent.com)",
  "WebFetch(domain:pastebin.com)", "WebFetch(domain:transfer.sh)", "WebFetch(domain:webhook.site)",
  "Read(.env)", "Read(.env.*)", "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.gnupg/**)",
  "Edit(.claude/**)", "Edit(~/.claude/**)", "Edit(.mcp.json)", "Edit(~/.claude.json)"
]}}
```
   Why: Claude Code evaluates deny rules first and "PreToolUse hook decisions don't bypass permission rules" ([code.claude.com/docs/en/permissions](https://code.claude.com/docs/en/permissions), "Extend permissions with hooks"). These rules therefore hold even if the hook is missing, broken or switched off, or the witness answers `pass` for a call. They close the direct ways out (network tools, hosts where anyone can publish, SSH keys, `.env` files) and stop the agent from editing the settings that switch the hook off. Limits: a Bash rule "matches the command text Claude writes ... and isn't a security boundary around the program" (`/usr/bin/curl` or `sh -c 'curl ...'` are not matched; same page, "What a Bash rule doesn't match"), so this is a second layer behind the witness; for enforcement independent of the command text use Claude Code's sandbox network allowlist. `Bash(curl *)` also stops harmless `curl`: the agent reads allowed documentation with WebFetch (your mandate lists the domains). `Edit(.claude/**)` means you edit your own settings by hand.

**Held calls (`DEUS_WITNESS_HOOK_ON_DEFER`).** When the witness holds a call for the owner, the hook answers `deny` by default (0.2.22; earlier versions asked in the terminal): the text names the receipt and the approval link, the owner approves in Witness (on the phone), then the agent retries the same call. A yes/no question in the terminal would let the person at the keyboard approve in the owner's place, and "yes" would run the call WITHOUT a witness receipt. `DEUS_WITNESS_HOOK_ON_DEFER=ask` brings the question back (only if you want that, set it explicitly in `env`); `defer` works in print mode / Agent SDK only. Any other value means `deny`. `deus-witness-hook --help` lists it.

**Default mandate domains (0.2.22).** `--print-form` no longer allows `github.com`, `raw.githubusercontent.com` or any other host where anyone can publish (a `WebFetch` GET with a query string to such a host is a way out for data). Kept: `localhost`, `127.0.0.1`, `docs.python.org`, `pypi.org`, `docs.github.com`, `developer.mozilla.org`, `www.npmjs.com`, `nodejs.org`, `docs.anthropic.com`, `code.claude.com`. Add a host you need on the Mandate page, knowingly. A mandate you signed earlier keeps its own list until you sign a new one.

## Cursor
Cursor reads MCP servers from `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project); the entry is the same as for Claude Desktop. Put the real MCP server after `--`:
```json
{"mcpServers": {"witnessed": {"command": "uvx",
  "args": ["deus-witness", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/sandbox"],
  "env": {"DEUS_WITNESS_KEY": "dwk_YOUR_KEY", "DEUS_WITNESS_URL": "https://witness.sipkigroup.com"}}}}
```
Cursor's own agent tools (shell, file edits) do not go through MCP and are not covered; `deus-witness doctor` lists them as a bypass.

## SDK (no MCP)
```python
from deus_witness import Witness
w = Witness("https://witness.sipkigroup.com", "dwk_...")
r = w.act("send_email", {"to": "bob@acme.example", "subject": "hi", "body": "..."})
if r.verdict == "allow" and w.present(r.rid)["result"] == "accept":
    ...                      # do the thing
    w.report(r.rid, True)
```
0.2: `w.catalog(tools)` sends a tools/list (`[{name, description, inputSchema}]`) as `POST /v1/catalog`; `w.coverage()` runs the
light doctor here and sends `POST /v1/coverage` (or pass your own report: `w.coverage({"level": "C2", "unwitnessed": []})`).
`verify_aar(aar_bytes, witness_pub, expect_request)` is a standalone receipt check.

## Demo tools
`deus-witness-demo-tools` is a stdio MCP server with `send_email`, `purchase`, `delete_resource`, `publish`, `read_file`;
nothing real happens, each call appends a line to `$DEUS_DEMO_OUT/effects.jsonl`.
