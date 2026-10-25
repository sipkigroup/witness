#!/usr/bin/env bash
# Deus Witness plugin for Claude Code: runs the PyPI client `deus-witness-hook` (>= 0.2.32) for the plugin's hooks.
#
#   deus-witness-hook.sh             PreToolUse: the witness decides the call (stdin = the event, stdout = the decision)
#   deus-witness-hook.sh --session-start   SessionStart: warns when the hook can be bypassed or is not configured
#
# Where the client comes from, in this order:
#   1. `deus-witness-hook` on PATH (pip install "deus-witness>=0.2.32")
#   2. `uvx --from "deus-witness>=0.2.32" deus-witness-hook` (needs uv: https://docs.astral.sh/uv/)
#
# The agent key: DEUS_WITNESS_KEY, else the plugin option agent_key, else the key file `deus-witness try` saved
# (${DEUS_WITNESS_HOME:-~/.config/deus-witness}/agent-key.json; the client reads it itself).
# Not configured (no key anywhere) = calls are not witnessed yet, and the plugin SAYS so: at session start, and once per session on
# the first tool call ("run /deus-witness:try": a trial account, two passkey touches, no sign-up form). With the plugin option
# `strict` on, every matched call is denied until a key is set.
# Configured (a key is set) = fail-closed: a missing client, a crash or a timeout blocks the call
# (`|| exit 2` and "onFailure": "block" in hooks.json).
set -u

SPEC="deus-witness>=0.2.32"
SIGNUP="https://witness.sipkigroup.com/signup.html"
TRY="/deus-witness:try (or in your terminal: uvx --from \"$SPEC\" deus-witness try)"

# Plugin options (userConfig) arrive as CLAUDE_PLUGIN_OPTION_<KEY>; a variable already set in the environment wins.
export DEUS_WITNESS_KEY="${DEUS_WITNESS_KEY:-${CLAUDE_PLUGIN_OPTION_AGENT_KEY:-}}"
export DEUS_WITNESS_URL="${DEUS_WITNESS_URL:-${CLAUDE_PLUGIN_OPTION_WITNESS_URL:-https://witness.sipkigroup.com}}"
export DEUS_WITNESS_HOOK_TIMEOUT="${DEUS_WITNESS_HOOK_TIMEOUT:-610}"   # hooks.json "timeout" is 620: 5+ s above this
export DEUS_WITNESS_HOOK_WAIT="${DEUS_WITNESS_HOOK_WAIT:-600}"         # wait for the owner's approval in Witness
export DEUS_WITNESS_HOOK_ON_DEFER="${DEUS_WITNESS_HOOK_ON_DEFER:-deny}"
STRICT="${CLAUDE_PLUGIN_OPTION_STRICT:-false}"
[ -n "$DEUS_WITNESS_KEY" ] || unset DEUS_WITNESS_KEY
KEYFILE="${DEUS_WITNESS_KEY_FILE:-${DEUS_WITNESS_HOME:-$HOME/.config/deus-witness}/agent-key.json}"
configured=""
if [ -n "${DEUS_WITNESS_KEY:-}" ] || [ -s "$KEYFILE" ]; then configured=1; fi

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
  if [ -z "$configured" ]; then
    if [ "$STRICT" = "true" ]; then
      say_session "DEUS WITNESS plugin: no agent key - every matched tool call is DENIED (strict). Set up in 2 minutes: $TRY . Have an account? /plugin -> deus-witness -> Configure (agent_key), or export DEUS_WITNESS_KEY."
    else
      say_session "DEUS WITNESS plugin is installed but NOT set up: tool calls are NOT witnessed yet. Set up in 2 minutes, no sign-up form: $TRY - then two passkey touches (Touch ID / Windows Hello / phone) in the page it opens. Have an account? /plugin -> deus-witness -> Configure (agent_key)."
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
if [ -z "$configured" ]; then
  if [ "$STRICT" = "true" ]; then
    cat >/dev/null
    deny "Blocked by Deus Witness (strict, no agent key). Set up: $TRY, or set agent_key in /plugin -> deus-witness -> Configure, or DEUS_WITNESS_KEY."
  fi
  # not set up: the call runs as without the plugin, but the person is told once per session (not silently fail-open)
  python3 -c '
import json, os, re, sys, tempfile
try:
    ev = json.loads(sys.stdin.read(1 << 20) or "{}")
except ValueError:
    ev = {}
sid = re.sub(r"[^A-Za-z0-9_-]", "", str(ev.get("session_id") or "nosession"))[:80] or "nosession"
mark = os.path.join(tempfile.gettempdir(), "deus-witness-unset-%s-%d" % (sid, os.getuid() if hasattr(os, "getuid") else 0))
if not os.path.exists(mark):
    open(mark, "w").close()
    print(json.dumps({"systemMessage": "Deus Witness is installed but not set up: this and the following tool calls are NOT witnessed. Set up in 2 minutes: " + sys.argv[1]}))
' "$TRY" 2>/dev/null || cat >/dev/null
  echo "[deus-witness] not set up (no agent key): call not witnessed" >&2
  exit 0
fi
if [ ${#runner[@]} -eq 0 ]; then
  cat >/dev/null
  deny "Blocked by Deus Witness: the client is not installed. Install uv (https://docs.astral.sh/uv/) or run: pip install \"$SPEC\""
fi
exec "${runner[@]}"
