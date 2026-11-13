# Deus Witness - Claude Code plugin

**What is different:** your passkey signs exactly what you saw and exactly the command that will run - unlike the approve buttons of apps such as Pushary and Happy. A dialog the agent rewords or fakes (Lies-in-the-Loop, Loopjacking) cannot get your signature on another command: the signature covers the hash of the screen you were shown and the hash of the exact arguments. Anyone can check the receipt offline, without us.

Every tool call Claude Code makes (Bash, Edit, Write, Read, Grep, Glob, WebFetch, WebSearch, MCP tools) goes to
[Deus Witness](https://witness.sipkigroup.com) before it runs. The witness checks it against the mandate you signed and answers
`allow`, `deny` or `defer` (wait for your approval: on the witness page in your browser, or on your phone: after the first passkey
touch the page offers "Get questions on your phone"; on iPhone only from Witness added to the Home Screen). A decision made against your mandate gets a signed receipt you can verify offline; a few automatic refusals (e.g. no mandate yet, a
rate limit) are kept only in the server database.

## What this plugin sends, and where

Before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text being written) to the witness server at <https://witness.sipkigroup.com> (operated by Sipki LLC), or to the witness you name in `DEUS_WITNESS_URL`. Along with it go the working directory, the project and home directory paths (`$HOME`, so your user name too) and `$TMPDIR`, answers to file-system questions the witness asks about paths named in the call (does it exist, its real path), SHA-256 hashes and paths of project files the call could execute, and, for shell calls, how Claude Code's sandbox is configured. Your conversation (prompts and replies) is not sent. Masked previews shrink to ~80 characters once the call is decided and to a hash after 30 days; a trial account you don't keep is erased after 7 days. Full details: <https://witness.sipkigroup.com/privacy.html>

The plugin needs uv; it runs `uvx --from deus-witness==0.2.69 deus-witness-hook` (a pinned PyPI package whose source is in this repository under `python/`).

## Install

First install uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`, then a new terminal): the plugin runs its client with `uvx`.

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
```

or in one step (Claude Code 2.1.275+): `/plugin install deus-witness --marketplace sipkigroup/witness`.
From the shell: `claude plugin marketplace add sipkigroup/witness && claude plugin install deus-witness@sipkigroup`.
The next Claude Code session starts with one line, "Deus Witness is not set up: run /deus-witness:try", until you do. The plugin never
runs `try` by itself. Plugin 0.2.65 shows no settings screen; an older one showed "Configure Deus Witness" - leave every field empty
and save. On a server or over SSH (no browser there): run `uvx --from deus-witness deus-witness try` in your own terminal; it prints the
link to open on your laptop or phone.

## Requirements (read this)

The plugin is a thin wrapper. The hook itself is the Python client `deus-witness` (PyPI, Apache-2.0, >= 0.2.34). The plugin finds it:

1. [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`) - then the plugin runs `uvx --from "deus-witness==0.2.69" deus-witness-hook`
   (first call downloads the client into the uv cache, about 30 packages). This is the way we test.
2. `deus-witness-hook` on your PATH - `pip install "deus-witness==0.2.69"`, only with Python 3.10+ in a venv (the stock macOS Python 3.9 and
   PEP 668 system Pythons refuse it). Put that venv OUTSIDE the project: the agent may write inside the project, so the plugin does not
   use a `deus-witness-hook` (or any program) found on PATH inside the project - it falls back to uvx, or blocks the call without uv.

Requirements: Claude Code 2.1.295+ (it honours `"onFailure": "block"`) and uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`); `python3` and `bash`; macOS, Linux, WSL.

## Set up in 2 minutes (trial, no sign-up form)

In Claude Code: `/deus-witness:try` (or in your own terminal: `uvx --from "deus-witness==0.2.69" deus-witness try`).
It prints what the hook sends to the witness, saves a trial agent key to `~/.config/deus-witness/agent-key.json` (mode 600; the plugin
picks it up at once) and opens a page in your browser. The first call of the agent that needs you waits; on that page ONE button asks
for two passkey touches (Touch ID / Windows Hello / phone): one makes your passkey, one signs the recommended rules for the project. The
call that waited is then decided by those rules at once: allowed, refused (e.g. a secret written to `.env`), or - if the rules say
"ask" (e.g. `git push`) - shown on the next screen for one more touch. Nothing is allowed before the first touch. Honest limit: until
that first touch, a program that controls your browser profile (or whoever holds the claim link) could claim the account first - an agent with a shell may be such a program; after the first touch only your passkey signs. The trial account is erased after 7 days unless you press "Keep this account" on that page.

Ran `/deus-witness:try` twice? The newer run replaces the older trial while it has no passkey yet: use the page that opened LAST (an
older page says it was replaced). A trial that already has your passkey is kept (`try` refuses to replace it; `--force` makes a new one).
Too many trials from one network (10 an hour): the message says when the next one is possible; a page already open keeps working.

### Quiet mode (fewer questions, macOS)

Witness asks least when Claude Code's own strict sandbox is on. In quiet mode the agent's commands:

- reach only the hosts you list. Quiet mode starts with npm, PyPI and GitHub downloads: `registry.npmjs.org`, `pypi.org`,
  `files.pythonhosted.org`, `github.com`, `codeload.github.com`, `objects.githubusercontent.com` and `raw.githubusercontent.com`.
  With these, `npm install`, `pip install` (including `git+https://github.com/...`) and `git pull` of a public repository work from
  the first try;
- cannot read your SSH and cloud keys, your login keychain, your browser cookies, or your editors' and CLIs' token stores;
- don't see your Witness agent key or your GitHub / npm / PyPI tokens (`GITHUB_TOKEN`, `NPM_TOKEN`, ...). These are hidden by name
  with Claude Code's `sandbox.credentials`.

With all of this in place, Witness asks only about what could leave your Mac or can't be undone.

**What stays the same:** your permission mode (`acceptEdits` stays `acceptEdits`), your other environment variables (your tests still
see `OPENAI_API_KEY`, `DATABASE_URL`, ...), your hooks and plugins.

**What changes:**

- A `git push`, `gh pr create` or `npm publish` that the agent runs can't use your login, because your keychain and tokens are closed
  to its commands. Witness asks you about it; run it yourself in your terminal.
- `git clone` and `git init` into the project fail, because Claude Code's sandbox protects `.git/config`. Run them yourself in your
  terminal.
- A host that isn't on the list is refused. Add your own in your terminal:
  `uvx --from "deus-witness==0.2.69" deus-witness-hook --setup-strict --host git.example.com`
  (a host name only: no `*`, no IP, no port).

**Turning it on:** `deus-witness try` in a terminal offers it once at the end (type yes: quiet from your first session); `/deus-witness:try`
asks you after the setup. Without quiet mode Witness asks about most commands (tests, installs, a virtualenv): measured on our friction
stand, ~40-110 questions on the first day of real work instead of 0-6. `/deus-witness:quiet` lists what changes in `~/.claude/settings.json`
in a few lines (the line-by-line change: `--quiet-offer --full`). If you say yes, Witness asks YOU to
approve it with your passkey; the agent can't switch it on or off by itself. Or, in your own terminal:
`uvx --from "deus-witness==0.2.69" deus-witness-hook --setup-strict`, which shows the change and asks you to type yes (a real terminal:
`echo yes |` and runs from a script or an agent are refused). Quiet mode keeps a backup next to the file,
`~/.claude/settings.json.bak-strict-<date>`, and starts with your next Claude Code session. To undo it, run
`uvx --from "deus-witness==0.2.69" deus-witness-hook --undo-strict` in your terminal: it restores the newest backup and keeps the
backup files (delete them when you no longer need them).

**Reminders:** if you said "later", from your second session on the session start reminds you at most once a week. To stop the
reminders, say no in `/deus-witness:quiet`, answer anything but yes to `deus-witness-hook --setup-strict` in the terminal, or run
`deus-witness-hook --quiet-no`. `DEUS_WITNESS_QUIET_HINT=0` silences them too.

**Linux and WSL2:** quiet mode works there too, with Claude Code's own Linux sandbox (bubblewrap). First install two packages: `sudo apt install bubblewrap socat` (Fedora / RHEL: `sudo dnf install bubblewrap socat`). Then turn it on as above (`/deus-witness:quiet`, or `deus-witness-hook --setup-strict` in your terminal): it checks the machine first and, if something is missing, says what to do and changes nothing. Ubuntu 24.04 blocks bubblewrap by default (AppArmor, `kernel.apparmor_restrict_unprivileged_userns`): the command prints the small AppArmor profile that allows it for bubblewrap only. WSL2: turn Windows interop off (`[interop]` `enabled=false` in `/etc/wsl.conf`, then `wsl --shutdown`), because a `.exe` started from Linux runs outside the sandbox; WSL1 has no sandbox. Containers are not supported: Azure Container Instances and similar (their `/proc/version` names Microsoft, so Claude Code takes them for WSL1, and `--setup-strict` says so and changes nothing, with or without `--weaker-nested`); in a Docker container that cannot mount `/proc`, `--setup-strict --weaker-nested` writes Claude Code's weaker sandbox if you ask for it, and Witness does not count it as quiet mode and keeps asking. What we checked (13.11, Debian 12 on Azure Container Instances, Claude Code 2.1.323): Claude Code's sandbox itself, run with two workarounds of our test bench that this tool does not apply (a substituted `/proc/version` and the weaker nested mode) - a test of the sandbox, not a path you can take. Ubuntu and WSL2 are not checked live yet.

## Configure (an existing account)

1. Sign up at <https://witness.sipkigroup.com/signup.html>, create an agent with the **claude-code** preset, copy the key (shown once).
2. Give it to Claude Code through the environment: `export DEUS_WITNESS_KEY=...` in the shell that starts Claude Code, or under `"env"`
   in `~/.claude/settings.json`. (Plugin 0.2.64 and older had a "Configure" screen; a key saved there is still read.)

| Variable | Default | What |
|---|---|---|
| `DEUS_WITNESS_KEY` | empty | Your agent key. Empty = the key saved by `/deus-witness:try`, if any; none = not set up |
| `DEUS_WITNESS_URL` | `https://witness.sipkigroup.com` | Witness server |
| `DEUS_WITNESS_STRICT` | `false` | `true`: while no key is set, every matched call is denied |

## What happens when

| State | Tool calls | You see |
|---|---|---|
| No key, `DEUS_WITNESS_STRICT` off | Run as without the plugin (**not witnessed**) | Session start ("Deus Witness is not set up: run /deus-witness:try") and the first call of each session |
| No key, `DEUS_WITNESS_STRICT` on | Denied | Session start + the deny reason |
| Key set | Decided by the witness; witness unreachable, client missing, crash or timeout = **blocked** (fail-closed); a read of a non-secret project file still runs (`offline.log`); a witness that does not connect in 3 s or answer in 8 s counts as unreachable, and for the next 60 s it is not asked again | The witness reason on every deny; while it is down, how to switch the plugin off |
| Owner approval pending (`defer`) | Notifies you at once (desktop notification, the approval page in your browser, your phone push / Telegram if set up), waits up to 45 s, then denied with the link: approve there and the agent reruns the same call | - |
| Trial account, nobody has touched the page yet | Every call, a read too, waits 45 s, then denied (`TRIAL_NOT_CLAIMED`); nothing runs | "finish the setup first": the trial page link, touch the passkey, then ask again |

How open your Claude Code is, with no account and nothing sent: `uvx deus-witness audit` in your project folder (grade A-F, read only).
Check your setup: `uvx --from "deus-witness==0.2.69" deus-witness-hook --doctor` - from 0.2.41 on it finds the plugin from a plain shell too (Claude Code's plugin registry and `enabledPlugins`) and the key file `try` saved; when no settings file says whether the plugin is enabled it says "CANNOT TELL" instead of guessing. Inside Claude Code the session-start message is the authoritative check.

CI and cron: `claude --bare` (and `CLAUDE_CODE_SIMPLE=1`) skips the hooks of plugins, so this plugin does not run and nothing says so; Claude Code's docs say `--bare` will become the default for `claude -p` in a future release. Run `uvx --from "deus-witness==0.2.69" deus-witness run -- claude -p "..."`: it refuses `--bare` before the run and exits non-zero after it when no Witness hook ran.

## Turn it off / remove it

Off for now: `claude plugin disable deus-witness@sipkigroup` in your own terminal, then restart Claude Code; back on: `claude plugin enable deus-witness@sipkigroup`. Remove: undo quiet mode first if you turned it on (`uvx --from "deus-witness==0.2.69" deus-witness-hook --undo-strict`), then `claude plugin uninstall deus-witness@sipkigroup` and `claude plugin marketplace remove sipkigroup`. What stays on disk: the agent key and pins in `~/.config/deus-witness` (`rm -rf ~/.config/deus-witness` if you will not come back) and the quiet-mode backups `~/.claude/settings.json.bak-strict-*`. A trial account has one passkey and no recovery codes: lost it - make a new trial (`deus-witness try --force` in your terminal).

## Testing with another HOME (CI, containers, a scratch folder)

The hook looks for traces of an earlier set-up (agent-key.json, witness.json, scanlist.json in `~/.config/deus-witness`,
`~/Library/Application Support/deus-witness`, `~/.deus-witness`) in your **real** home folder, taken from the system's user database
(`dscl` on macOS, `getent` on Linux), not from `$HOME`. This is on purpose: a project's `.claude/settings.json` can set `"env"` for hooks,
and a `HOME` (or `DEUS_WITNESS_HOME`) pointing at an empty folder must not turn a set-up witness into "not set up, calls run
unwitnessed". So on a machine where Witness was set up, a run with a different `HOME` and no key in it blocks every call with "the
agent key is MISSING (the witness was set up on this machine: <path>)". To test in a scratch `HOME`, run `deus-witness try` with that
`HOME` first (its key is then found there), or test as another user / on a machine (CI runner, container) where Witness was never set up.

## MCP servers

The plugin does not add an MCP server: `deus-witness-mcp` is a proxy in front of *your* MCP server, so it needs your server's command.
Put it in your own `.mcp.json`: `"command": "uvx", "args": ["--from", "deus-witness==0.2.69", "deus-witness-mcp", "--", "<your server command>", "..."]`.
MCP tool calls are already covered by the hook (`mcp__.*` in the matcher).

## Honest limits

- The plugin cannot protect against someone who can edit your Claude Code settings or disable the plugin; it guards the agent, not the machine owner.
- A tool or route outside the matcher is not witnessed.
- Other hooks that rewrite tool calls (tested: rtk 1.2.0; everything-claude-code 2.2.3 found no conflict on stdin): Claude Code runs hooks in parallel and takes the rewrite of the one that finishes last. From 0.2.69 a call Witness approved is pinned to the input it judged, which normally runs, and a PostToolUse check tells you if a different call ran; a hook that finishes later than Witness can still win, and the check only reports it after the fact. rtk no longer shortens the output of calls Witness approved; calls Witness did not decide, and `DEUS_WITNESS_HOOK_ALLOW=neutral`, are not pinned. The check adds about 0.1-0.2 s to each tool call. Hooks of other plugins run outside Witness.
- Early (0.x). See the repository README.

Source: <https://github.com/sipkigroup/witness> (`plugins/deus-witness`). License: Apache-2.0. Service: run by Sipki LLC.
