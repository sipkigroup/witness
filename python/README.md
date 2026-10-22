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
the agent gets `Blocked by Deus Witness: <reason> (receipt <rid>)`; `defer` -> waits up to ~50 s for the owner, then
`Held for owner approval at <url>. Retry the same call after approval.` If the witness is unreachable the call is blocked
(fail closed). `tools/list`, resources, prompts and notifications pass through untouched. The proxy log (stderr) holds only tool, rid, verdict.

0.2: `status: held` (held by the advisor for owner review) is waited for like `defer`, then the agent gets
`Held by advisor for owner review at <url>. Retry the same call after review.`

At start (after the client's `initialized`) the proxy asks the upstream for `tools/list` itself (the answer is not shown to
the client), sends it as `POST /v1/catalog` (the server suggests a strict toolmap from it), runs the light doctor (configs
only, no network) and sends `POST /v1/coverage`; once per run, before the first call is judged. If the witness cannot be
reached at that moment, every call of the run is blocked (fail closed). An HTTP error there (e.g. a 0.1 server) is only logged.

Env: `DEUS_WITNESS_KEY` (required), `DEUS_WITNESS_URL`, `DEUS_WITNESS_WAIT` (s per long poll, 25), `DEUS_WITNESS_POLLS` (2),
`DEUS_WITNESS_VERIFY=0` or `--no-verify-aar` (testing against a stub that does not sign).

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
