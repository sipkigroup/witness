#!/usr/bin/env bash
# Deus Witness plugin for Claude Code: runs the PyPI client `deus-witness-hook` (>= 0.2.27) for the plugin's hooks.
#
#   deus-witness-hook.sh             PreToolUse: the witness decides the call (stdin = the event, stdout = the decision)
#   deus-witness-hook.sh --session-start   SessionStart: warns when the hook can be bypassed or is not configured
#
# Where the client comes from, in this order:
#   1. `deus-witness-hook` on PATH (pip install "deus-witness>=0.2.27")
#   2. `uvx --from "deus-witness>=0.2.27" deus-witness-hook` (needs uv: https://docs.astral.sh/uv/)
#
# Not configured (no agent key) = the plugin does nothing and says so at session start: tool calls run as without the
# plugin (fail-open), unless the plugin option `strict` is on - then every matched call is denied until the key is set.
# Configured (a key is set) = fail-closed: a missing client, a crash or a timeout blocks the call
# (`|| exit 2` and "onFailure": "block" in hooks.json).
set -u

SPEC="deus-witness>=0.2.27"
SIGNUP="https://witness.sipkigroup.com/signup.html"

# Plugin options (userConfig) arrive as CLAUDE_PLUGIN_OPTION_<KEY>; a variable already set in the environment wins.
export DEUS_WITNESS_KEY="${DEUS_WITNESS_KEY:-${CLAUDE_PLUGIN_OPTION_AGENT_KEY:-}}"
export DEUS_WITNESS_URL="${DEUS_WITNESS_URL:-${CLAUDE_PLUGIN_OPTION_WITNESS_URL:-https://witness.sipkigroup.com}}"
export DEUS_WITNESS_HOOK_TIMEOUT="${DEUS_WITNESS_HOOK_TIMEOUT:-610}"   # hooks.json "timeout" is 620: 5+ s above this
export DEUS_WITNESS_HOOK_WAIT="${DEUS_WITNESS_HOOK_WAIT:-600}"         # wait for the owner's approval in Witness
export DEUS_WITNESS_HOOK_ON_DEFER="${DEUS_WITNESS_HOOK_ON_DEFER:-deny}"
STRICT="${CLAUDE_PLUGIN_OPTION_STRICT:-false}"
[ -n "$DEUS_WITNESS_KEY" ] || unset DEUS_WITNESS_KEY

mode="${1:-pretool}"

runner=()
if command -v deus-witness-hook >/dev/null 2>&1; then
  runner=(deus-witness-hook)
elif command -v uvx >/dev/null 2>&1; then
  runner=(uvx --quiet --from "$SPEC" deus-witness-hook)
fi

say_session() {   # $1 = message for the user at session start
  python3 -c 'import json,sys; m=sys.argv[1]; print(json.dumps({"systemMessage": m, "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "Deus Witness warning for the user: " + m}}))' "$1" 2>/dev/null \
    || printf '{"systemMessage": "Deus Witness plugin: see the plugin README"}\n'
}

deny() {          # $1 = reason; a PreToolUse deny on stdout, exit 0
  python3 -c 'import json,sys; print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": sys.argv[1]}}))' "$1" 2>/dev/null \
    || exit 2
  exit 0
}

if [ "$mode" = "--session-start" ]; then
  cat >/dev/null
  if [ -z "${DEUS_WITNESS_KEY:-}" ]; then
    if [ "$STRICT" = "true" ]; then
      say_session "DEUS WITNESS plugin: no agent key - every matched tool call is DENIED (strict). Set the key: /plugin -> deus-witness -> Configure (agent_key), or export DEUS_WITNESS_KEY. Get one: $SIGNUP"
    else
      say_session "DEUS WITNESS plugin is installed but NOT configured: tool calls are NOT witnessed (fail-open). Set the agent key: /plugin -> deus-witness -> Configure (agent_key), or export DEUS_WITNESS_KEY. Get one: $SIGNUP . Check: uvx --from \"$SPEC\" deus-witness-hook --doctor"
    fi
    exit 0
  fi
  if [ ${#runner[@]} -eq 0 ]; then
    say_session "DEUS WITNESS plugin: the client is missing - every matched tool call is BLOCKED. Install uv (https://docs.astral.sh/uv/) or: pip install \"$SPEC\""
    exit 0
  fi
  exec "${runner[@]}" --session-start </dev/null
fi

# PreToolUse
if [ -z "${DEUS_WITNESS_KEY:-}" ]; then
  if [ "$STRICT" = "true" ]; then
    cat >/dev/null
    deny "Blocked by Deus Witness (strict, no agent key). Set agent_key in /plugin -> deus-witness -> Configure, or DEUS_WITNESS_KEY. Get one: $SIGNUP"
  fi
  cat >/dev/null
  echo "[deus-witness] not configured (no agent key): call not witnessed" >&2
  exit 0
fi
if [ ${#runner[@]} -eq 0 ]; then
  cat >/dev/null
  deny "Blocked by Deus Witness: the client is not installed. Install uv (https://docs.astral.sh/uv/) or run: pip install \"$SPEC\""
fi
exec "${runner[@]}"
