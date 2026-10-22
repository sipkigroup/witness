#!/bin/sh
# Example (not published): a nightly Claude Code agent on your own machine or server, every tool call judged by Deus Witness.
# crontab -e:   17 3 * * 1-5  /path/to/cron-claude-p.sh /path/to/project >> "$HOME/witnessed-agent.log" 2>&1
# Needs: claude (Claude Code), deus-witness (pip install deus-witness), <project>/.claude/settings.json = settings.unattended.json.
# Keys: DEUS_WITNESS_KEY and ANTHROPIC_API_KEY from files only you can read (chmod 600), never in this script or in crontab.
set -eu
PROJECT=${1:?usage: cron-claude-p.sh /path/to/project}
cd "$PROJECT"
DEUS_WITNESS_KEY=$(cat "$HOME/.config/deus-witness/agent.key")
ANTHROPIC_API_KEY=$(cat "$HOME/.config/deus-witness/anthropic.key")
export DEUS_WITNESS_KEY ANTHROPIC_API_KEY
export DEUS_WITNESS_URL=${DEUS_WITNESS_URL:-https://witness.sipkigroup.com}
# a call that needs you waits up to 10 min (link in Telegram / Slack / e-mail), then it is refused; the person at this terminal never decides
export DEUS_WITNESS_HOOK_ON_DEFER=deny DEUS_WITNESS_HOOK_WAIT=600 DEUS_WITNESS_HOOK_TIMEOUT=610
# cron has a short PATH
PATH="$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
# 1. fail-closed or nothing: the agent does not start when the hook can be bypassed
deus-witness-hook --doctor "$PWD" | tee /dev/stderr | grep -q "OK: fail-closed"
# 2. one run in print mode; its answer is kept next to the log
STAMP=$(date +%Y%m%d-%H%M)
claude -p "Run the test suite, fix what fails, and write a short summary to SUMMARY.md. Do not push." \
  --output-format json > "$HOME/witnessed-agent-$STAMP.json"
# 3. claude -p exits 0 even when the witness refused calls: count them and fail loudly, so cron mail / your monitor sees it
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("permission_denials") or []))' "$HOME/witnessed-agent-$STAMP.json")
if [ "$N" != 0 ]; then echo "BLOCKED $STAMP: $N call(s) refused by the witness or Claude Code, see witnessed-agent-$STAMP.json"; exit 3; fi
echo "done $STAMP"
