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
- For a call the job makes every run (the same report, the same command line), approve it once **for the next runs** (section 4): the
  next run then does that step without a new question.

## 4. What happens to a call that needs you
- The hook waits up to `DEUS_WITNESS_HOOK_WAIT` = 600 s for your answer (the hook's own timeout 610 s, Claude Code's `timeout` 620 s,
  in this order). You get the link, open it, approve with your passkey: the call runs in the same turn.
- No answer in time: the call is refused (`DEUS_WITNESS_HOOK_ON_DEFER=deny`) and the agent is told why. It may try another way or stop;
  the step is NOT done. Approving later lets the same call through once if the agent repeats it while the request is still open (15 min);
  for Claude Code's shell that needs the hook deus-witness 0.2.24 or newer (an older hook sends Claude Code's free-text `description`,
  which differs on every try, so the repeat is a different call and is asked again).
  Nothing re-runs the job for you: neither Witness nor the templates retry.
- Nobody at the terminal can approve in your place: `ask` is not used here on purpose.

### Approving a call for the next runs (0.2.29)
A job on a schedule usually runs again long after the 15 minutes. So when you approve, you can tick
**"Also approve this exact call for this agent's later runs"** and choose **1, 3 or 10 more times** within **1, 24 or 72 hours**
(nothing is ticked by default: an approval is for this request only). Then the same call of the same agent, with exactly the same
arguments and under the same mandate, runs in the next runs without asking you, until those uses are spent or that time passes.
- **The morning after.** The night run asked at 03:00, nobody answered, the request expired. The link still opens for 24 hours after
  that: the request itself can no longer be approved (that call was not run), but you can approve the same call for the agent's
  next runs. The next scheduled run then does that step.
- **One passkey prompt** signs it. The page shows what you sign: how many more times, until when, which agent and tool. Every receipt
  it lets through names your signature, like any approval.
- **What it never covers.** Any other call (a different file, text, amount, recipient or command line) is asked as usual. A call the
  mandate refuses stays refused. Not offered for dangerous commands, for a command whose executed files changed since you confirmed
  them (approving the arguments says nothing about the file contents), for items held because the agent saw a secret or sends data
  to a public host, or on a team account. A new or revoked mandate, a removed passkey or a frozen agent ends it. If the agent read a
  secret in that run, its outgoing call is asked again.
- **A shell command approves the line, not the file it runs** (0.2.30). For `bash nightly.sh` or `python3 run.py` the arguments are
  the command line; what is in `nightly.sh` is not part of them. So the approval for later runs of a command **ends** (status
  "ended: the agent changed a file this command runs", and you are asked again) as soon as the witness lets the agent write a file
  that command may run: the script it names, a source file of its language (a `.py` for `python3`/`pytest`, a `.js` for `node`/`npm`),
  or any script or source file when the line runs project code. If that happened between the question and your answer, it is not
  offered at all. Honest limit: a change the witness does not see as a write (a program you or a project permission let run that
  rewrites the script, a person's edit, `git checkout`) is not detected for a plain script. The configuration files that build and
  test tools execute are compared by their digests, as before.
- **You are told of every use.** Each call that runs under it sends a short note to your channels (Telegram, Slack, e-mail: at most
  one in 10 minutes, "N calls ran without a question"; no arguments in it), and so does an approval that ended because a file changed.
- **See and revoke.** Page *Permissions*, card *Approvals for later runs*: the call, the agent, how many uses are left, the time
  limit; **Revoke** takes one click. Honest limit: a revocation is kept by the service; the time limit and the number of uses are
  part of what you signed.
- **Needs the hook deus-witness 0.2.24 or newer** for Claude Code's shell (`Bash`) (`pip install -U "deus-witness>=0.2.24"`). Claude Code writes a new free-text label
  (`description`) for every shell command in every run; older hooks send it as part of the call, so two runs never make "the same
  call". The new hook leaves that label out (Claude Code only shows it; it never runs).
- The same call made again **does** run: if a prompt injection makes the agent repeat exactly that call, it runs up to the number of
  times you chose. Choose the smallest number and time that fit your schedule.

## 5. A flood of questions
An agent that keeps asking after the witness refused to queue more questions (`APPROVAL_RATE`) is **frozen** automatically after
10 such refusals (of different requests) in 10 minutes. Frozen means:
its waiting requests are cancelled and every new call is refused (`AGENT_FROZEN`). Your channels get a message. On the dashboard the agent
card says "frozen" and has an **Unfreeze** button (owner only, passkey). You can also freeze an agent yourself from its card or from an
approval page.

Unanswered requests outlive the run that asked them. A request waits for you up to its time limit (15 minutes by default) even after
`claude -p` has exited, and it keeps its place in the agent's queue (`max_pending`, 5 by default; `max_defers_hour`, 20). If the next run
starts while the queue is full, its first call that needs you is refused with `APPROVAL_RATE`, and the refusal says how many requests are
waiting and when a place frees. This is on purpose: the witness does not know where one run ends and the next begins, so restarting an
agent never earns it more questions to you. Answer or let the old requests time out, or space your runs further apart than the time limit.
Only refusals of **different** requests count toward the automatic freeze: a run that retries the same refused call does not freeze the
agent, it asks you nothing new.

## 6. What this does not cover
- The witness judges the calls Claude Code makes (the shell line, the file edits, the web requests). It does not see what a program does
  inside: a script or a test the agent wrote can read files and talk to the network by itself. The witness asks about running a file the
  agent wrote while it has seen a secret, and asks about the network hosts it can read from the line; for a hard boundary also run the
  agent in a sandbox without network access except the hosts it needs (Claude Code's sandbox, a container with an egress allowlist).
- If the witness cannot be reached, calls are blocked (fail-closed), reads included: a night run then stops instead of running unwatched.
