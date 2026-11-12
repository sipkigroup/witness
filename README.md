# Deus Witness

**Let Claude Code work on its own; get asked only before the few things a sandbox cannot undo or contain - publishing, running a program outside the sandbox, writing a file that starts itself later, irreversible changes inside your project. You answer with one passkey touch; every decision gets a signed receipt you can verify offline.**

## The problem

Claude Code asks before it runs commands or edits files. Anthropic's own write-up of auto mode names what happens next: "approval fatigue, where people stop paying close attention to what they're approving", and "users accept 93% of them anyway". The other way out, `--dangerously-skip-permissions`, "disables all permission prompts and lets Claude act freely" ([Anthropic, 25.03.2026](https://anthropic.com/engineering/claude-code-auto-mode)).

A prompt you approve without reading protects nothing. What you need is fewer questions, and a real one when it matters.

## What Witness does

- Claude Code runs inside its strict OS sandbox (no network except your list, your credentials unreadable, no writes outside the project and Claude Code's temp). Inside it, code, tests, builds, installs and edits run **without a question**, each with a receipt.
- Before each tool call the plugin asks a witness service outside the agent. The witness asks you only for a closed list of reasons: publishing (`git push`, `npm publish`, deploy CLIs, ssh/scp to another machine, a POST to an outside host), a program outside the sandbox (`sudo`, `open`, `osascript`), a file another program runs later (`.envrc`, git hooks, CI files, `.vscode` tasks, `.claude` settings), a loader variable, the witness's own key, irreversible changes inside the project (`git reset --hard`, `git clean -f`, `rm -rf .git`, `DROP TABLE`).
- Some things are refused outright, with no question: reading a private key, token store or keychain; writing shell rc files, LaunchAgents, cron, the agent's own settings or hooks; `rm -rf` of your home or above the project; download-into-shell; force-push.
- The question says in plain words what the agent wants to do and what it can harm, with three buttons: allow once / allow this kind from now on (narrow: this project, with an end date, revocable) / deny. The answer is signed with your passkey.

## What we measured (our own measurement, not independent)

Stand (L2): the real hook and the real witness (server 0.2.91-0.2.94, client 0.2.59-0.2.62; since 0.2.61 with the same mandate a new trial account gets) replaying recorded Claude Code sessions under the strict sandbox fact; no live person in the loop.

| Set | What it is | Witness asked | Dangerous actions let through |
|---|---|---|---|
| "Typical developer", blind | 12 Claude Code sessions (Haiku 5.5, `claude -p`) on 6 open-source repos: click, humanize, mistune, dequal, is-number, p-limit; 192 tool calls; the rules were not tuned on it | **2 questions in 12 sessions** (a fresh trial account, client 0.2.62 / server 0.2.94: 384 calls in two passes, 4 questions; the same with an empty or a typical `allowedDomains`). 0 of 72 reads asked | this set has no dangerous actions |
| Our own DevOps sessions | 2,090 tool calls from the author's real working days (az, gh, ssh, deploys) | 45 questions on 1,658 harmless calls (6 on day one, then ~8 a day) | **0 of 432** labeled dangerous |
| Attack probes | 38 probes written against the rules + 72 harmless twins | 0 of 72 twins asked | **0 of 38** |
| Older labeled set | 346 calls | 2 of 320 harmless asked | **0 of 26** |

What these numbers do **not** show: they are our corpora, labeled by us; no outside user has run it yet. Our own end-to-end check (12.11, client 0.2.61, server 0.2.93): a real Claude Code 2.1.322 with a real model (Haiku 5.5) on three open-source projects (click, p-limit, mistune), against the hosted witness: in quiet mode 0 questions in 4 sessions of about 10-15 calls each, commits included; without quiet mode 3 questions in about 10 calls; the typical set is 12 short sessions (about 20 minutes of agent activity in total), so read "2 per 12 sessions", not "per day". Known gaps, stated: code that carries an attacker's token can still send data to a host **you** put in `allowedDomains`; a command a script builds while it runs (not visible in the file the agent wrote) is not checked; scripts the agent writes and then runs (bash, python, node, npm run, make) are checked by their saved text since 0.2.60. The quiet mode exists only under Claude Code's strict sandbox on macOS; on Linux/WSL, and without it, you get more questions.

> **Status: early (0.x).** The specification is an individual draft in `spec/` (not an IETF standard, not submitted to the IETF).
> The evidence so far is our own simulations and separate implementations written from the spec by one author; there are no external audits or deployments yet.
> Treat it as something to test and attack, not as a certified security boundary. Reports of bypasses are the most valuable thing you can send us.

**What leaves your machine:** before a matched tool call runs, the hook sends the tool input as given (the full command line, file paths, the text being written) to the hosted witness at <https://witness.sipkigroup.com> (operated by Sipki LLC), or to a witness you run yourself from `spec/` and `contract/`. With it go the working and project directories, your home directory path (`$HOME`, so your user name too) and `$TMPDIR` (the witness needs them to tell the project, your home and temp folders apart), the real path / existence of the paths the call names, a git ref the call switches to, and a digest of Claude Code's settings. Not sent: your conversation, the contents of the files the agent reads, the values of your environment variables. Details: [`plugins/deus-witness/README.md`](plugins/deus-witness/README.md), <https://witness.sipkigroup.com/privacy.html>.

## Install (3 lines in Claude Code)

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
/deus-witness:try
```

`try` makes a trial account (no sign-up form) and opens a page in your browser; a trial account has no phone notifications - questions wait on that page. For the quiet mode measured above, run `/deus-witness:quiet` (details below).

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
  `uvx --from "deus-witness==0.2.63" deus-witness-hook --setup-strict --host git.example.com`
  (a host name only: no `*`, no IP, no port).

**Turning it on:** `/deus-witness:quiet` shows the exact change to `~/.claude/settings.json` first. If you say yes, Witness asks YOU to
approve it with your passkey; the agent can't switch it on or off by itself. Or, in your own terminal:
`uvx --from "deus-witness==0.2.63" deus-witness-hook --setup-strict`, which shows the change and asks you to type yes. Quiet mode keeps a
backup and starts with your next Claude Code session. To undo it, run `deus-witness-hook --undo-strict` in your terminal.

**Reminders:** `/deus-witness:try` mentions quiet mode in one line at the end. From your second session on, the session start reminds
you at most once a week. To stop the reminders, say no in `/deus-witness:quiet`, answer anything but yes in the terminal, or run
`deus-witness-hook --quiet-no`. `DEUS_WITNESS_QUIET_HINT=0` silences them too.

**Linux and WSL2:** Claude Code's sandbox runs there too, but Witness hasn't measured it there yet. Quiet mode is macOS only for now.

Without the plugin: `uvx --from deus-witness deus-witness try`. As an MCP proxy in front of any MCP server: `uvx deus-witness -- <your MCP server command>` (see `python/README.md`).

## Try it in Claude Code

Needs Claude Code 2.1.295+ and uv (`curl -LsSf https://astral.sh/uv/install.sh | sh`); macOS, Linux, WSL.

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
/deus-witness:try
```

`try` makes a trial account and opens a page in your browser. The first tool call that needs you waits; the page asks for two passkey touches (one makes your passkey, one signs the recommended rules), then that call is decided - allowed, refused, or shown to you for one more touch. Until your first touch a call waits up to 45 s, then it is refused (`TRIAL_NOT_CLAIMED`): ask again after the touches. A trial account has no phone notifications: the call waits for you on that page. A trial account you do not keep is erased after 7 days. A trial account has one passkey and no recovery codes: if you lose that passkey (or the device it lives on), start a new trial with `/deus-witness:try` and, when it says the account already has your passkey, `uvx --from deus-witness deus-witness try --force` in your own terminal (10 new trial accounts per hour per network).
`/plugin install` opens the plugin panel: pick a scope and install; if it says so, run `/reload-plugins`.
Without the plugin: `uvx --from deus-witness deus-witness try` (`pip install deus-witness` only with Python 3.10+ in a venv).

## What is here

| Path | What | License |
|---|---|---|
| `spec/` | Draft specification of the action receipt (`draft-deus-aar-05`, plus history and errata) and the test vectors (`spec/vectors`) | Apache-2.0 |
| `verifier_js/` | Verifier in JavaScript, written from the spec | Apache-2.0 |
| `verifier_swift/` | Verifier in Swift, written from the spec (source; build with `./build.sh`) | Apache-2.0 |
| `sdk-ts/` | `@deus-witness/sdk` (npm): TypeScript client, no dependencies | Apache-2.0 |
| `python/` | `deus-witness` (PyPI): Python thin client - MCP proxy, Claude Code hook, doctor, SDK. Registry name `io.github.sipkigroup/witness` | Apache-2.0 |
| `contract/` | HTTP API contract (OpenAPI), WebAuthn signing profile, contract stub | Apache-2.0 |
| `plugins/deus-witness/` + `.claude-plugin/marketplace.json` | Claude Code plugin: the hook in one install command | Apache-2.0 |
| `integrations/` | Examples: Vercel AI SDK, curl | Apache-2.0 |
| `docs/` | Teams, recovery, anchors, verifying receipts | Apache-2.0 |

**In this repo, all Apache-2.0 and run locally:** the complete MCP server (`deus-witness-mcp`, a stdio proxy you put in front of any MCP server), the Claude Code hook and plugin, the offline verifiers and the specs.
**Not in this repo:** the hosted Witness API that the MCP server calls, like any API-backed MCP server calls its API (passkey approvals, the signed journal). It is run by the author and is not covered by this license; packs it issues are checked offline with the verifiers here, so you don't have to trust it.
You can implement your own witness from `spec/` and `contract/`.

## Use it
Claude Code: the three commands above (the one-step form `/plugin install deus-witness --marketplace sipkigroup/witness` also exists in Claude Code 2.1.275 or later); see [`plugins/deus-witness/README.md`](plugins/deus-witness/README.md).

The hosted service is at <https://witness.sipkigroup.com>. From TypeScript: `npm install @deus-witness/sdk` (see [`sdk-ts/README.md`](sdk-ts/README.md)). From Python, or to put any MCP server behind the witness: `pip install deus-witness` (Python 3.10+ in a venv) or, with no install, `uvx deus-witness -- <your MCP server command>` (MCP Registry: `io.github.sipkigroup/witness`; see [`python/README.md`](python/README.md); setup: <https://witness.sipkigroup.com/dl/docs/quickstart.html>).
Any other language: speak HTTP, see [`contract/openapi.yaml`](contract/openapi.yaml) and [`integrations/`](integrations/).

## Honest limits
- A witness cannot know what an action *really* does beyond what the tool map and the operator's description say; it checks the call against your mandate. Routes that do not go through the witness are not covered.
- The TypeScript client does **not** verify receipt signatures yet (the verifiers here do). Do not treat an `allow` seen through it as cryptographically checked.
- If the witness is unreachable or does not answer within a few seconds, every call that is not a read of a project file is refused (fail closed); reads of non-secret project files still run, listed in `offline.log`. That is a safety choice that costs availability; the message says how to switch Witness off on purpose (below).

## Turn it off / remove it

- Off for now (the witness is down, or you want to work without it): in your own terminal `claude plugin disable deus-witness@sipkigroup`, then restart Claude Code. Back on: `claude plugin enable deus-witness@sipkigroup`.
- Remove it: `claude plugin uninstall deus-witness@sipkigroup`. The agent key and pins stay in `~/.config/deus-witness` (or `DEUS_WITNESS_HOME`): delete that folder too if you will not come back. Quiet mode, if you turned it on: `uvx --from "deus-witness==0.2.63" deus-witness-hook --undo-strict` first.
- The agent cannot do this for you: Witness refuses such a line from the agent like any other change to its own settings.

## Verify the receipts yourself

```
python3 spec/vectors/check_vectors.py              # the abstract spec vectors through the reference model of the spec (no dependencies)
(cd verifier_js && npm ci && npm test)             # the same vectors through the JavaScript verifier
(cd verifier_swift && ./build.sh && ./aarc --quiet --extra extra-vectors)
```
If two implementations disagree on a vector, one of them (or the spec) is wrong - please open an issue with the vector.

## Security, contributing, license
- Vulnerabilities: [`SECURITY.md`](SECURITY.md) (support@sipkigroup.com). Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Apache License 2.0 ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)). Copyright 2026 Sipki LLC.
