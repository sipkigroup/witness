# What leaves your machine

This page is the one full list. The README files repeat its short form. A test of the client (in our development tree, not in this
repository) reads the code that builds each request and fails when a field is sent that this page does not list.

**In short:** before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text
being written or replaced) to the hosted witness at <https://witness.sipkigroup.com> (operated by Sipki LLC), or to a witness you run
yourself (`DEUS_WITNESS_URL`). With it go: the working, project, home (`$HOME`, so your user name too) and temp (`$TMPDIR`) directory
paths; the Claude Code session id; answers to the witness's questions about paths named in the call (does it exist, its real path);
SHA-256 hashes, sizes and paths of project files the call could execute; the git branch of the project; masked values of git settings
that start programs; a digest of Claude Code's settings; and, for shell calls, a summary of Claude Code's sandbox settings with your
permission mode and the names (never the values) of the project's `.env` files and of token-like environment variables. Requests about
your calls carry your agent key (`Authorization`). Not sent: your conversation (prompts and replies), tool outputs, the contents of
files the agent reads, the values of other environment variables. The plugin's `uvx` downloads the client from PyPI. What the witness
keeps and for how long: <https://witness.sipkigroup.com/privacy.html>.

The details follow.

## Where requests go

- **The witness:** <https://witness.sipkigroup.com>, or the URL you set in `DEUS_WITNESS_URL` (it must be the one your key file was made
  for). HTTPS. The requests under `/v1/hook/`, `/v1/actions`, `/v1/salt`, `/v1/catalog` and `/v1/coverage` carry the agent key as
  `Authorization: Bearer <key>`: the key from `DEUS_WITNESS_KEY` or from the key file `deus-witness try` saved
  (`~/.config/deus-witness/agent-key.json`); `try` sends the previous trial key the same way when it replaces it. The witness sees your IP address, as any server does.
- **PyPI:** the plugin runs `uvx --from deus-witness==0.2.79 deus-witness-hook`. The first time (and whenever uv's cache does not hold
  that version) uv downloads the package and its dependencies, about 30 packages, from `pypi.org` and `files.pythonhosted.org`, uv's
  default index. PyPI sees your IP address and which versions you download. Whether uv contacts PyPI again on later runs depends on uv's
  cache; we have not measured it. With `pip install` into your own venv there is no download at hook time.
- Nothing else. The hook opens no other connection. When a call waits for you it may open the approval page of the same witness in
  your browser and show a notification on this computer.
- **What the witness passes on:** it time-stamps the hash of its journal checkpoint once a day with OpenTimestamps calendars (anchored
  in Bitcoin) and FreeTSA, and checks the Bitcoin anchor with mempool.space and blockstream.info: hashes only, nothing of a call.
  Push notifications go through your browser's push service (Apple, Google, Mozilla, Microsoft) with opaque ids only; Telegram, Slack
  or e-mail only if you set them up. The full list: <https://witness.sipkigroup.com/privacy.html>, "Third parties".

## Requests the client makes

| Request | When | What it carries |
|---|---|---|
| `POST /v1/hook/judge` | before every matched tool call (one to eight rounds while the witness asks for facts) | the body below |
| `GET /v1/hook/scanlist` | when the witness asks for the project walk | nothing (the witness answers with the signed list of files to hash) |
| `GET /v1/witness` | first use of a witness, or when its signature does not verify | nothing (the witness's public key, pinned on this computer) |
| `GET /v1/salt` | when the client needs the account's salt (then kept on this computer); at session start with a trial key | nothing |
| `GET /v1/actions/{id}` | while a call waits for your approval | the request id |
| `POST /v1/actions/{id}/present` | an approved call is about to run (the receipt is used once) | the request id |
| `POST /v1/actions/{id}/report` | after a call the witness allowed with no decision in auto mode | whether the call ran (`executed`: true or false) |
| `GET /v1/hook/status` | session start | the client version, the plugin version, the project path |
| `POST /v1/trial` | `deus-witness try` (`/deus-witness:try`) | the recommended rules drafted for your project: the project and temp paths, the command and domain lists; the client version |
| `GET /v1/trial/status`, `POST /v1/trial/retire` | `try` again: the previous trial key is checked, then withdrawn | nothing but that key |
| `POST /v1/hook/run`, `POST /v1/hook/run/start`, `GET /v1/hook/run/{id}` | only under `deus-witness run` (CI): the run's nonce and the session id | the Claude Code session id |
| `POST /v1/actions` | MCP proxy (`deus-witness -- <server>`) and the SDK: each tool call | the tool name and its full arguments |
| `POST /v1/catalog`, `POST /v1/coverage` | MCP proxy, once per run | the name, description and input schema of every tool of your MCP server; a coverage report that names MCP servers not behind the proxy |

`deus-witness audit` sends nothing and opens no connection.

## The judge request, field by field

`POST /v1/hook/judge` sends one JSON object. Fields marked "asked" are empty until the witness asks about a path of THIS call; the hook
answers only about paths inside the project, the session's folders and their parents, and paths built from the words of the call
(any other question is refused). The witness masks secrets in the tool input before it writes anything to disk (privacy.html).

| Field | What is sent | When |
|---|---|---|
| `v` | the format version (1) | always |
| `event` | the call as Claude Code gave it | always |
| `event.tool_name` | the tool name (`Bash`, `Write`, `mcp__...`) | always |
| `event.tool_input` | the full tool input: the whole command line, file paths, URLs, the text a Write writes, the old and new text of an Edit. A command line that prints environment variables (`env \| grep x`) is sent, and run, with their values masked | always |
| `event.cwd` | the working directory | always |
| `facts` | what the hook knows of this computer, below | always |
| `facts.home` | your home directory path (so your user name) | always |
| `facts.proc_cwd` | the folder the hook process runs in | always |
| `facts.env` | the values of four variables, below (no other variable's value is sent) | always |
| `facts.env.HOME` | `$HOME` | when set |
| `facts.env.TMPDIR` | `$TMPDIR` | when set |
| `facts.env.CLAUDE_PROJECT_DIR` | the project directory | when set |
| `facts.env.DEUS_WITNESS_EXEC_SCAN` | `0` when you switched the project walk off | when set |
| `facts.fs` | answers about paths | always |
| `facts.fs.realpath` | the real path (links resolved) of the working, project and home directories, and of paths the witness asks about | always; asked |
| `facts.fs.isdir` | is a path a directory | asked |
| `facts.fs.exists` | does a path exist | asked |
| `facts.fs.gitref` | for a git branch switch: which files of the repository it would change (paths) | asked |
| `facts.fs.samefile` | for a path that is a hard link of a credential file: the name of that file | asked |
| `facts.fs.archive` | for an archive the call extracts: the link entries inside it (kind, name, target; headers only) | asked |
| `facts.fs.shadow` | for a file the call writes outside the project: the path, SHA-256 and size of the copy the hook kept on THIS computer (the copy itself stays here, for `--undo`) | asked |
| `facts.exec` | the project walk: files the call could execute | when the witness asks, or at once when its cached list names the tool; `DEUS_WITNESS_EXEC_SCAN=0` switches it off |
| `facts.exec.root` | the project path | with the walk |
| `facts.exec.rev` | the version of the witness's file list | with the walk |
| `facts.exec.files` | relative paths and SHA-256 hashes of the project files the witness's list names (build and test files, scripts, venv and `node_modules/.bin` entries) | with the walk |
| `facts.exec.sizes` | their sizes in bytes | with the walk |
| `facts.exec.truncated` | the walk stopped early (time or file limit) | with the walk |
| `facts.exec.none` | there is no project folder to walk | with the walk |
| `facts.exec.git` | paths and SHA-256 hashes of git's own files of the project (config, config.worktree, info/attributes, hooks) | with the walk, in a git repository |
| `facts.exec.gitcfg` | the values of git settings that start programs (such as `credential.helper`, `core.sshCommand`, aliases) from the project's git config, masked: credentials in a URL, well-known token prefixes and the word after `password=`, `token=`, `Authorization:`, `Bearer` are replaced; the program path and flags stay. A secret written in another form could stay. Remote URLs are not sent | with the walk, in a git repository |
| `facts.exec.gitcfg_cut` | something in those files was cut or could not be read | with the walk |
| `facts.exec.hookspath` | `core.hooksPath` of your global or system git config, masked the same way | with the walk, when set |
| `facts.exec.preview` | the text of a project file the call executes that changed and that the witness could not read: the first 4096 characters, masked on this computer first, for the approval page | asked |
| `facts.sandbox` | a summary of Claude Code's settings for the sandbox, below | shell calls (`Bash`) |
| `facts.sandbox.v` | the format version | shell calls |
| `facts.sandbox.platform` | `darwin`, `linux`, `wsl2`, `wsl1`, or the system's own name (`win32`) | shell calls |
| `facts.sandbox.sources` | which settings layers were read (managed, user, project, local, `--settings`) and whether they could be | shell calls |
| `facts.sandbox.enabled` | `sandbox.enabled` | shell calls |
| `facts.sandbox.fail_if_unavailable` | `sandbox.failIfUnavailable` | shell calls |
| `facts.sandbox.allow_unsandboxed` | `sandbox.allowUnsandboxedCommands` | shell calls |
| `facts.sandbox.excluded` | `sandbox.excludedCommands` | shell calls |
| `facts.sandbox.ignore_violations` | whether `sandbox.ignoreViolations` is set | shell calls |
| `facts.sandbox.fs_disabled` | `sandbox.filesystem.disabled` | shell calls |
| `facts.sandbox.allow_git_config` | `sandbox.filesystem.allowGitConfig` | shell calls |
| `facts.sandbox.deny_read` | the denied read paths (sandbox `denyRead`, credential files, `Read(...)` deny rules), expanded | shell calls |
| `facts.sandbox.allow_read` | the allowed read paths (`allowRead`), expanded | shell calls |
| `facts.sandbox.domains` | the allowed network hosts (sandbox `allowedDomains`, `WebFetch(domain:...)` allow rules) | shell calls |
| `facts.sandbox.domains_user` | the same, from your user and managed settings only | shell calls |
| `facts.sandbox.unix_sockets` | `sandbox.network.allowUnixSockets` (paths) | shell calls |
| `facts.sandbox.all_unix_sockets` | `sandbox.network.allowAllUnixSockets` | shell calls |
| `facts.sandbox.mach_lookup` | `sandbox.network.allowMachLookup` (macOS service names) | shell calls |
| `facts.sandbox.local_binding` | `sandbox.network.allowLocalBinding` | shell calls |
| `facts.sandbox.strict_allowlist` | `sandbox.network.strictAllowlist` (user and managed settings) | shell calls |
| `facts.sandbox.managed_domains_only` | `allowManagedDomainsOnly` in managed settings | shell calls |
| `facts.sandbox.weaker` | the names of settings that weaken the sandbox and are on | shell calls |
| `facts.sandbox.env_scrub` | whether `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` is on | shell calls |
| `facts.sandbox.env_hidden` | whether the agent key is hidden from sandboxed commands (true / false) | shell calls |
| `facts.sandbox.disable_flag` | whether the call asks to run outside the sandbox (`dangerouslyDisableSandbox`) | shell calls |
| `facts.sandbox.env_files` | the paths of the `.env` and `.env.*` files in the project folder: names (never the values) | shell calls |
| `facts.sandbox.env_tokens` | the names (never the values) of environment variables that look like tokens (`GITHUB_TOKEN`, `*_API_KEY` ...) and that sandboxed commands can see | shell calls |
| `facts.sandbox.cred_files` | which config files hold a credential a sandboxed command could use, by file and kind (`~/.gitconfig: credential.helper`, `.npmrc: an auth token`); never the credential | shell calls |
| `facts.sandbox.permission_mode` | your Claude Code permission mode (`default`, `acceptEdits`, `auto`, `bypassPermissions` ...) | shell calls |
| `facts.sandbox.settings_digest` | a SHA-256 digest of the sandbox-related part of your settings | shell calls |
| `facts.sandbox.since_start` | which settings layers changed since the session started (names) | shell calls |
| `facts.sandbox.doubt` | what the hook could not read (for example: Claude Code was started with `--add-dir`) | shell calls |
| `facts.sandbox.linux` | Linux and WSL only, below | shell calls on Linux / WSL |
| `facts.sandbox.linux.kind` | `linux`, `wsl2` or `wsl1` | shell calls on Linux / WSL |
| `facts.sandbox.linux.bwrap` | is `bwrap` on PATH | shell calls on Linux / WSL |
| `facts.sandbox.linux.socat` | is `socat` on PATH | shell calls on Linux / WSL |
| `facts.sandbox.linux.arch` | the machine architecture (`x86_64`, `arm64`) | shell calls on Linux / WSL |
| `facts.sandbox.linux.interop` | can Windows programs be started from WSL | shell calls on WSL |
| `facts.sandbox.linux.win_homes` | the Windows home folders seen under `/mnt` (paths, so Windows user names) | shell calls on WSL |
| `facts.settings` | for other calls: the settings digest only | calls other than `Bash` |
| `facts.settings.settings_digest` | the same digest as above | calls other than `Bash` |
| `facts.settings.since_start` | the same as above | calls other than `Bash` |
| `facts.harness` | the agent-settings path the call touches (`.claude/`, `.mcp.json`, `.git/hooks`, `~/.claude`, the Deus Witness key files) | when the call touches one |
| `facts.harness_held` | that path is held by the strict sandbox (true) | when the call touches one |
| `facts.which` | where the Python tools the command names (`python3`, `pip`, `pytest` ...) resolve on your PATH (paths) | shell calls that name one |
| `facts.git_self` | the SHA-256 of your git `user.email`, only when the command line itself shows that address | shell calls with an `@` |
| `facts.git_head` | the git branch of the project (or "(detached)" and 12 hex of the commit) | in a git repository |
| `client` | the client, below | always |
| `client.name` | `deus-witness-hook` | always |
| `client.version` | the client version | always |
| `client.caps` | what this client can answer (`preview`, `final`, `tmpdir`) | always |
| `part` | which part of a multi-part call is asked again | a re-judge |
| `nonce` | a fresh random value for this call (192 bits) | always |
| `session_id` | the Claude Code session id | when Claude Code gives one |

## Not sent

- Your conversation: prompts, Claude's replies, tool outputs.
- The contents of the files the agent reads. A file's text leaves only inside the tool input of a Write or an Edit (the new text and,
  for an Edit, the text it replaces), and as `facts.exec.preview` above (a changed project file the call executes, masked, at most 4096
  characters, for the approval page).
- The values of environment variables, except `HOME`, `TMPDIR`, `CLAUDE_PROJECT_DIR`, `DEUS_WITNESS_EXEC_SCAN` and the agent key itself
  (`DEUS_WITNESS_KEY`, sent as `Authorization`). Of token-like variables and `.env` files only the names go.
- Git remote URLs and the contents of credential files.

The plugin needs uv; it runs `uvx --from deus-witness==0.2.79 deus-witness-hook` (a pinned PyPI package whose source is in this
repository under `python/`).
