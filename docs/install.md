# Install and set up Deus Witness

Short version: the [README](../README.md#install-3-lines-in-claude-code). This page has the details.

## Requirements

The plugin is a thin wrapper. The hook itself is the Python client `deus-witness` (PyPI, Apache-2.0, >= 0.2.34). The plugin finds it:

1. [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`) - then the plugin runs `uvx --from "deus-witness==0.2.73" deus-witness-hook`
   (first call downloads the client into the uv cache, about 30 packages). This is the way we test.
2. `deus-witness-hook` on your PATH - `pip install "deus-witness==0.2.73"`, only with Python 3.10+ in a venv (the stock macOS Python 3.9 and
   PEP 668 system Pythons refuse it). Put that venv OUTSIDE the project: the agent may write inside the project, so the plugin does not
   use a `deus-witness-hook` (or any program) found on PATH inside the project - it falls back to uvx, or blocks the call without uv.

Requirements: Claude Code 2.1.295+ (it honours `"onFailure": "block"`) and uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`); `python3` and `bash`; macOS, Linux, WSL.

## Install

Needs Claude Code 2.1.295+ and [uv](https://docs.astral.sh/uv/): `curl -LsSf https://astral.sh/uv/install.sh | sh`, then open a new
terminal (without uv, `try` stops with "uvx: command not found"). macOS, Linux, WSL.

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
/deus-witness:try
```

- `/plugin install` opens the plugin panel: pick a scope and install; if it says so, run `/reload-plugins`. Plugin 0.2.64 and older
  showed a "Configure Deus Witness" screen: leave every field empty and save.
- `try` makes a trial account (no sign-up form) and opens a page in your browser. That page asks for two passkey touches (one makes
  your passkey, one signs the recommended rules); then the call that waited is decided - allowed, refused, or shown to you for one more
  touch. **Until the first touch nothing runs:** a call waits up to 45 s, then it is refused with `TRIAL_NOT_CLAIMED` and the link to
  the trial page: finish there, then ask the agent to retry. After the first touch the page offers "Get questions on your phone" (Web
  Push; on iPhone only from Deus Witness added to the Home Screen).
- Skipped the third line? Every new session starts with "Deus Witness is not set up: run /deus-witness:try" (the plugin never runs it
  by itself). On a server or over SSH (no browser there): run `uvx --from deus-witness deus-witness try` in your own terminal; it
  prints the link to open on your laptop or phone.
- A trial account you do not keep is erased after 7 days. It has one passkey and no recovery codes: lost it - `/deus-witness:try`,
  and when it says the account already has your passkey, `uvx --from deus-witness deus-witness try --force` in your own terminal (10
  new trial accounts per hour per network).
- Without the plugin: `uvx --from deus-witness deus-witness try`. As an MCP proxy in front of any MCP server:
  `uvx deus-witness -- <your MCP server command>` (see `python/README.md`).

**Check your set-up (optional, no account, nothing sent):** in your own terminal, in your project folder, `uvx deus-witness audit`
(a fixed version: `uvx deus-witness==0.2.73 audit`). It reads your Claude Code settings and prints a grade (A-F) and what the agent
can do without asking you; it writes nothing and opens no network connection. Run it in the project folder, not in your home folder:
started in the home folder it judges a project in general and says so.

For fewer questions, run `/deus-witness:quiet` ([quiet-mode.md](quiet-mode.md)).

Other ways: in one step (Claude Code 2.1.275+): `/plugin install deus-witness --marketplace sipkigroup/witness`.
From the shell: `claude plugin marketplace add sipkigroup/witness && claude plugin install deus-witness@sipkigroup`.
The next Claude Code session starts with one line, "Deus Witness is not set up: run /deus-witness:try", until you do. The plugin never
runs `try` by itself. Plugin 0.2.65 shows no settings screen; an older one showed "Configure Deus Witness" - leave every field empty
and save. On a server or over SSH (no browser there): run `uvx --from deus-witness deus-witness try` in your own terminal; it prints the
link to open on your laptop or phone.

## Set up in 2 minutes (trial, no sign-up form)

In Claude Code: `/deus-witness:try` (or in your own terminal: `uvx --from "deus-witness==0.2.73" deus-witness try`).
It prints what the hook sends to the witness, saves a trial agent key to `~/.config/deus-witness/agent-key.json` (mode 600; the plugin
picks it up at once) and opens a page in your browser. The first call of the agent that needs you waits; on that page ONE button asks
for two passkey touches (Touch ID / Windows Hello / phone): one makes your passkey, one signs the recommended rules for the project. The
call that waited is then decided by those rules at once: allowed, refused (e.g. a secret written to `.env`), or - if the rules say
"ask" (e.g. `git push`) - shown on the next screen for one more touch. Nothing is allowed before the first touch. Honest limit: until
that first touch, a program that controls your browser profile (or whoever holds the claim link) could claim the account first - an agent with a shell may be such a program; after the first touch only your passkey signs. The trial account is erased after 7 days unless you press "Keep this account" on that page.

Ran `/deus-witness:try` twice? The newer run replaces the older trial while it has no passkey yet: use the page that opened LAST (an
older page says it was replaced). A trial that already has your passkey is kept (`try` refuses to replace it; `--force` makes a new one).
Too many trials from one network (10 an hour): the message says when the next one is possible; a page already open keeps working.

Quiet mode (fewer questions): [quiet-mode.md](quiet-mode.md).

## Configure (an existing account)

1. Sign up at <https://witness.sipkigroup.com/signup.html>, create an agent with the **claude-code** preset, copy the key (shown once).
2. Give it to Claude Code through the environment: `export DEUS_WITNESS_KEY=...` in the shell that starts Claude Code, or under `"env"`
   in `~/.claude/settings.json`. (Plugin 0.2.64 and older had a "Configure" screen; a key saved there is still read.)

| Variable | Default | What |
|---|---|---|
| `DEUS_WITNESS_KEY` | empty | Your agent key. Empty = the key saved by `/deus-witness:try`, if any; none = not set up |
| `DEUS_WITNESS_URL` | `https://witness.sipkigroup.com` | Deus Witness server |
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
Check your setup: `uvx --from "deus-witness==0.2.73" deus-witness-hook --doctor` - from 0.2.41 on it finds the plugin from a plain shell too (Claude Code's plugin registry and `enabledPlugins`) and the key file `try` saved; when no settings file says whether the plugin is enabled it says "CANNOT TELL" instead of guessing. Inside Claude Code the session-start message is the authoritative check.

CI and cron: `claude --bare` (and `CLAUDE_CODE_SIMPLE=1`) skips the hooks of plugins, so this plugin does not run and nothing says so; Claude Code's docs say `--bare` will become the default for `claude -p` in a future release. Run `uvx --from "deus-witness==0.2.73" deus-witness run -- claude -p "..."`: it refuses `--bare` before the run and exits non-zero after it when no Deus Witness hook ran.

## Testing with another HOME (CI, containers, a scratch folder)

The hook looks for traces of an earlier set-up (agent-key.json, witness.json, scanlist.json in `~/.config/deus-witness`,
`~/Library/Application Support/deus-witness`, `~/.deus-witness`) in your **real** home folder, taken from the system's user database
(`dscl` on macOS, `getent` on Linux), not from `$HOME`. This is on purpose: a project's `.claude/settings.json` can set `"env"` for hooks,
and a `HOME` (or `DEUS_WITNESS_HOME`) pointing at an empty folder must not turn a set-up witness into "not set up, calls run
unwitnessed". So on a machine where Deus Witness was set up, a run with a different `HOME` and no key in it blocks every call with "the
agent key is MISSING (the witness was set up on this machine: <path>)". To test in a scratch `HOME`, run `deus-witness try` with that
`HOME` first (its key is then found there), or test as another user / on a machine (CI runner, container) where Deus Witness was never set up.

## MCP servers

The plugin does not add an MCP server: `deus-witness-mcp` is a proxy in front of *your* MCP server, so it needs your server's command.
Put it in your own `.mcp.json`: `"command": "uvx", "args": ["--from", "deus-witness==0.2.73", "deus-witness-mcp", "--", "<your server command>", "..."]`.
MCP tool calls are already covered by the hook (`mcp__.*` in the matcher).

## Other hooks that rewrite tool calls

- Other hooks that rewrite tool calls (tested: rtk 1.2.0; everything-claude-code 2.2.3 found no conflict on stdin): Claude Code runs hooks in parallel and takes the rewrite of the one that finishes last. From 0.2.69 a call Deus Witness approved is pinned to the input it judged, which normally runs, and a PostToolUse check tells you if a different call ran; a hook that finishes later than Deus Witness can still win, and the check only reports it after the fact. rtk no longer shortens the output of calls Deus Witness approved; calls Deus Witness did not decide, and `DEUS_WITNESS_HOOK_ALLOW=neutral`, are not pinned. The check adds about 0.1-0.2 s to each tool call. Hooks of other plugins run outside Deus Witness.

## Remove

- Off for now (the witness is down, or you want to work without it): in your own terminal `claude plugin disable deus-witness@sipkigroup`, then restart Claude Code. Back on: `claude plugin enable deus-witness@sipkigroup`.
- Remove it: quiet mode first, if you turned it on (`uvx --from "deus-witness==0.2.73" deus-witness-hook --undo-strict`), then
  `claude plugin uninstall deus-witness@sipkigroup` and `claude plugin marketplace remove sipkigroup`. What stays on disk: the agent key
  and pins in `~/.config/deus-witness` (or `DEUS_WITNESS_HOME`) - `rm -rf ~/.config/deus-witness` if you will not come back - and the
  quiet-mode backups `~/.claude/settings.json.bak-strict-*`.
- The agent cannot do this for you: Deus Witness refuses such a line from the agent like any other change to its own settings.
