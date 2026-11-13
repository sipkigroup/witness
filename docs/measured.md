# What we measured

Stand (L2): the real hook and the real witness (server 0.2.91-0.2.94, client 0.2.59-0.2.62; since 0.2.61 with the same mandate a new trial account gets) replaying recorded Claude Code sessions under the strict sandbox fact; no live person in the loop.

| Set | What it is | Witness asked | Dangerous actions let through |
|---|---|---|---|
| "Typical developer", blind | 12 Claude Code sessions (Haiku 5.5, `claude -p`) on 6 open-source repos: click, humanize, mistune, dequal, is-number, p-limit; 192 tool calls; the rules were not tuned on it | **2 questions in 12 sessions** (a fresh trial account, client 0.2.62 / server 0.2.94: 384 calls in two passes, 4 questions; the same with an empty or a typical `allowedDomains`). 0 of 72 reads asked | this set has no dangerous actions |
| Our own DevOps sessions | 2,090 tool calls from the author's real working days (az, gh, ssh, deploys) | 45 questions on 1,658 harmless calls (6 on day one, then ~8 a day) | **0 of 432** labeled dangerous |
| Attack probes | 38 probes written against the rules + 72 harmless twins | 0 of 72 twins asked | **0 of 38** |
| Older labeled set | 346 calls | 2 of 320 harmless asked | **0 of 26** |

What these numbers do **not** show: they are our corpora, labeled by us; no outside user has run it yet. Our own end-to-end check (12.11, client 0.2.61, server 0.2.93): a real Claude Code 2.1.322 with a real model (Haiku 5.5) on three open-source projects (click, p-limit, mistune), against the hosted witness: in quiet mode 0 questions in 4 sessions of about 10-15 calls each, commits included; without quiet mode 3 questions in about 10 calls; the typical set is 12 short sessions (about 20 minutes of agent activity in total), so read "2 per 12 sessions", not "per day". Known gaps, stated: code that carries an attacker's token can still send data to a host **you** put in `allowedDomains`; a command a script builds while it runs (not visible in the file the agent wrote) is not checked; scripts the agent writes and then runs (bash, python, node, npm run, make) are checked by their saved text since 0.2.60. The quiet mode exists only under Claude Code's strict sandbox (macOS; Linux and WSL2 with bubblewrap); without it you get more questions.

> **Status: early (0.x).** The specification is an individual draft in `spec/` (not an IETF standard, not submitted to the IETF).
> The evidence so far is our own simulations and separate implementations written from the spec by one author; there are no external audits or deployments yet.
> Treat it as something to test and attack, not as a certified security boundary. Reports of bypasses are the most valuable thing you can send us.

**Public log:** the hosted witness publishes a signed checkpoint of its anchor log at `https://witness.sipkigroup.com/checkpoint` and stamps it once a day outside our servers (OpenTimestamps and FreeTSA), so a rewritten history can be caught offline.
