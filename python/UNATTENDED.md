# Agents without a person at the keyboard (GitHub Actions, cron, `claude -p`)

> Status (22.10.2026): a live run of real `claude -p` with the hook from PyPI against a local Witness server passed five scenarios (safe task, blocked send, approved while waiting, timeout, auto-freeze). A run from a real GitHub Actions schedule against the hosted service has **not** been done yet.

A background agent is where a witness matters most: nobody watches the terminal, and a call that should not run would run at 3 a.m.
With Deus Witness every tool call of the agent is judged against the mandate you signed with your passkey; what the mandate does not
cover waits for **you**, wherever you are, and is refused if you do not answer.

Files (copy them, nothing here is installed for you):

| File | What it is |
|---|---|
| `examples/unattended/settings.unattended.json` | `.claude/settings.json` for the project: the hook (fail-closed), a 10-minute wait for your answer, the second layer of `permissions.deny` |
| `examples/unattended/github-actions-witnessed-agent.yml` | a scheduled GitHub Actions job running `claude -p` under the witness |
| `examples/unattended/cron-claude-p.sh` | the same for cron on your own machine or server |

## 1. Before the first run
1. Dashboard, card **Agents**: create an agent with the preset `claude-code`, copy its key (`dwk_...`).
2. Sign its mandate (Quickstart, step 9.2: `deus-witness-hook --print-form /path/to/project`, Import from JSON, sign).
   For a background agent keep it narrow: the commands it really needs, the documentation hosts it reads, no publishing.
3. Dashboard, card **Other notification channels**: add Telegram (your own bot), Slack (an incoming webhook of a channel only you read)
   or e-mail, and press **Send a test**. The message holds only a link to the request; approving is done on that page with your passkey.
   iPhone / iPad: Web Push works only after you add Witness to the **Home Screen** (iOS 16.4+) and enable notifications there; Safari tabs
   get nothing. That is why a channel you already read is the recommended one for night runs.
4. Copy `settings.unattended.json` to `<project>/.claude/settings.json` and commit it. The keys never go into that file.

## 2. GitHub Actions
- Repository secrets: `ANTHROPIC_API_KEY` and `DEUS_WITNESS_KEY`. The workflow reads them into the job's environment only.
- The job runs `deus-witness-hook --doctor` first and stops if the hook is not fail-closed: a broken install never means "the agent runs unwatched".
- `permissions: contents: read` and `persist-credentials: false`: the agent cannot push with the job's token. Give it more only knowingly,
  and then list `git push` in the mandate as a command that needs you.
- Do not add `--dangerously-skip-permissions`: calls the witness does not judge (class `pass`) would then run without any rule.

## 3. cron with `claude -p`
`cron-claude-p.sh /path/to/project` reads both keys from files only you can read (`chmod 600`), checks the hook with `--doctor`, runs one
`claude -p` and keeps the JSON answer. Put it into `crontab -e` (example line in the script).

### Things we learned in the live run
- `claude -p --output-format json` exits 0 even when calls were refused. Both templates count `permission_denials` and fail (exit 3), so cron mail or the red job tells you.
- To test the barrier, give the agent a neutral task. A prompt that openly asks to leak a secret is often refused by the model itself before the hook sees anything; that proves nothing about the witness.
- A call that waited for you and got no answer stays pending for 15 minutes, also into the next run. Several of those in a row count as a flood (section 5).

## 4. What happens to a call that needs you
- The hook waits up to `DEUS_WITNESS_HOOK_WAIT` = 600 s for your answer (the hook's own timeout 610 s, Claude Code's `timeout` 620 s,
  in this order). You get the link, open it, approve with your passkey: the call runs in the same turn.
- No answer in time: the call is refused (`DEUS_WITNESS_HOOK_ON_DEFER=deny`) and the agent is told why. It may try another way or stop;
  the step is NOT done. Approving later lets the same call through once if the agent repeats it while the request is still open (15 min).
- Nobody at the terminal can approve in your place: `ask` is not used here on purpose.

## 5. A flood of questions
An agent that keeps asking after the witness refused to queue more questions (`APPROVAL_RATE`) is **frozen** automatically after
10 such refusals in 10 minutes. Frozen means:
its waiting requests are cancelled and every new call is refused (`AGENT_FROZEN`). Your channels get a message. On the dashboard the agent
card says "frozen" and has an **Unfreeze** button (owner only, passkey). You can also freeze an agent yourself from its card or from an
approval page.

## 6. What this does not cover
- The witness judges the calls Claude Code makes (the shell line, the file edits, the web requests). It does not see what a program does
  inside: a script or a test the agent wrote can read files and talk to the network by itself. The witness asks about running a file the
  agent wrote while it has seen a secret, and asks about the network hosts it can read from the line; for a hard boundary also run the
  agent in a sandbox without network access except the hosts it needs (Claude Code's sandbox, a container with an egress allowlist).
- If the witness cannot be reached, calls are blocked (fail-closed), reads included: a night run then stops instead of running unwatched.
