#!/usr/bin/env bash
# Deus Witness plugin for Claude Code: runs the PyPI client `deus-witness-hook` (>= 0.2.34) for the plugin's hooks.
#
#   deus-witness-hook.sh             PreToolUse: the witness decides the call (stdin = the event, stdout = the decision)
#   deus-witness-hook.sh --session-start   SessionStart: warns when the hook can be bypassed or is not configured
#
# Where the client comes from, in this order:
#   1. `deus-witness-hook` on PATH (pip install "deus-witness==0.2.47"; Python 3.10+ in a venv OUTSIDE the project: one found inside
#      the project, as found or resolved, is not used - the agent may write there)
#   2. `uvx --from "deus-witness==0.2.47" deus-witness-hook` (needs uv: https://docs.astral.sh/uv/)
#
# The agent key: DEUS_WITNESS_KEY, else the plugin option agent_key, else the key file `deus-witness try` saved
# (${DEUS_WITNESS_HOME:-~/.config/deus-witness}/agent-key.json; the client reads it itself).
# Not configured (no key anywhere) = calls are not witnessed yet, and the plugin SAYS so: at session start, and once per session on
# the first tool call ("run /deus-witness:try": a trial account, two passkey touches, no sign-up form). With the plugin option
# `strict` on, every matched call is denied until a key is set.
# Configured (a key is set) = fail-closed: a missing client, a crash or a timeout blocks the call
# (`|| exit 2` and "onFailure": "block" in hooks.json).
set -u

SPEC="deus-witness==0.2.47"
SIGNUP="https://witness.sipkigroup.com/signup.html"
TRY="/deus-witness:try (or in your terminal: uvx --from \"deus-witness==0.2.47\" deus-witness try)"

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

# The agent may write inside the project, so nothing this script runs may come from there: a project .venv activated before `claude`,
# direnv `PATH_add bin`, a relative PATH entry. Those PATH entries are dropped (as given and resolved) before ANY command is looked up -
# the client, uvx, and python3 / head / sed below. A client found elsewhere that resolves (symlink) or whose interpreter points into the
# project is not used either. (A project that is the home directory itself is not filtered: the agent can write all of it anyway.)
roots=()
for d in "${CLAUDE_PROJECT_DIR:-}" "$PWD"; do
  [ -n "$d" ] && [ "${d%/}" != "${HOME%/}" ] || continue
  roots+=("${d%/}" "$(cd -P "$d" 2>/dev/null && pwd -P)")
done
in_project() {    # $1 = absolute path
  local r
  for r in ${roots[@]+"${roots[@]}"}; do
    [ -n "$r" ] || continue
    case "${1%/}/" in "${r%/}/"*) return 0 ;; esac
  done
  return 1
}
safe=""
dropped=""
IFS=: read -r -a path_entries <<<"${PATH:-}"
for e in ${path_entries[@]+"${path_entries[@]}"}; do
  case "$e" in
    /*) rp="$(cd -P "$e" 2>/dev/null && pwd -P)"
        if in_project "$e" || { [ -n "$rp" ] && in_project "$rp"; }; then dropped="$dropped $e"; else safe="${safe:+$safe:}$e"; fi ;;
    *) [ "${#roots[@]}" -eq 0 ] && safe="${safe:+$safe:}$e" || dropped="$dropped ${e:-.}" ;;     # "" or relative = the cwd
  esac
done
export PATH="$safe"
runner=()
inproj=""
found="$(command -v deus-witness-hook 2>/dev/null)"
if [ -n "$found" ]; then
  rfound="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$found" 2>/dev/null || realpath "$found" 2>/dev/null || printf '%s' "$found")"
  interp="$(head -n 1 "$rfound" 2>/dev/null | sed -n 's/^#![[:space:]]*\([^[:space:]]*\).*/\1/p')"
  if in_project "$found" || in_project "$rfound" || { case "$interp" in /*) in_project "$interp" ;; *) false ;; esac; }; then
    inproj="$found"
  else
    runner=("$found")
  fi
elif [ -n "$dropped" ]; then
  for e in $dropped; do
    case "$e" in /*) [ -x "$e/deus-witness-hook" ] && inproj="$e/deus-witness-hook" && break ;; esac
    [ -x "$PWD/$e/deus-witness-hook" ] && inproj="$PWD/$e/deus-witness-hook" && break
  done
fi
if [ ${#runner[@]} -eq 0 ] && command -v uvx >/dev/null 2>&1; then
  runner=(uvx --quiet --from "deus-witness==0.2.47" deus-witness-hook)   # literal pin: the directory validator must see it
fi
INPROJ_MSG="the deus-witness-hook on PATH ($inproj) is inside the project (or resolves there), where the agent may write, so it is not used. Install uv (https://docs.astral.sh/uv/), or install the client outside the project (a venv elsewhere)"

# 0.2.41: under `deus-witness run -- claude ...` (CI, cron) leave an empty mark that this hook ran, so that a run where Claude Code
# started no hook (`claude --bare`, CLAUDE_CODE_SIMPLE) fails loudly instead of passing unchecked. Only into the directory
# `deus-witness run` made (absolute, not a symlink) and only with its well-formed run id; never blocks, never prints.
rid="${DEUS_WITNESS_RUN_ID:-}"
rdir="${DEUS_WITNESS_RUN_DIR:-}"
case "$mode" in --session-start) rmode=session-start ;; *) rmode=pretool ;; esac
case "$rid" in *[!0-9a-f]*) rid="" ;; esac
case "$rdir" in /*) ;; *) rdir="" ;; esac
if [ "${#rid}" -eq 32 ] && [ -n "$rdir" ] && [ -d "$rdir" ] && [ ! -L "$rdir" ]; then
  if [ -z "$configured" ]; then rstate=unset; elif [ ${#runner[@]} -eq 0 ]; then rstate=blocked; else rstate=on; fi
  { : >"$rdir/$rid.plugin-$rmode-$rstate.$$"; } 2>/dev/null || true
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

# Before `try` (no key yet): say now what would stop it later - no uv / no client, or a Claude Code too old for "onFailure": "block".
preflight() {
  local p="" v a b c
  if [ ${#runner[@]} -eq 0 ] && [ -n "$inproj" ]; then
    p="$p Note: $INPROJ_MSG."
  elif [ ${#runner[@]} -eq 0 ]; then
    p="$p First install uv (https://docs.astral.sh/uv/): without it /deus-witness:try cannot run (or: pip install \"deus-witness==0.2.47\" with Python 3.10+ in a venv)."
  fi
  v="$("${CLAUDE_CODE_EXECPATH:-claude}" --version 2>/dev/null </dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ -n "$v" ]; then
    IFS=. read -r a b c <<<"$v"
    if [ "$a" -lt 2 ] || { [ "$a" -eq 2 ] && { [ "$b" -lt 1 ] || { [ "$b" -eq 1 ] && [ "$c" -lt 295 ]; }; }; }; then
      p="$p Claude Code $v is older than 2.1.295: it ignores \"onFailure\": \"block\", so a crash or timeout of the hook would let a call run - update Claude Code first (npm i -g @anthropic-ai/claude-code)."
    fi
  fi
  printf '%s' "$p"
}

if [ "$mode" = "--session-start" ]; then
  cat >/dev/null
  if [ -z "$configured" ]; then
    pre="$(preflight)"
    if [ "$STRICT" = "true" ]; then
      say_session "DEUS WITNESS plugin: no agent key - every matched tool call is DENIED (strict). Set up in 2 minutes: $TRY . Have an account? /plugin -> deus-witness -> Configure (agent_key), or export DEUS_WITNESS_KEY.$pre"
    else
      say_session "DEUS WITNESS plugin is installed but NOT set up: tool calls are NOT witnessed yet. Set up in 2 minutes, no sign-up form: $TRY - then two passkey touches (Touch ID / Windows Hello / phone) in the page it opens. Have an account? /plugin -> deus-witness -> Configure (agent_key).$pre"
    fi
    exit 0
  fi
  if [ ${#runner[@]} -eq 0 ] && [ -n "$inproj" ]; then
    say_session "DEUS WITNESS plugin: every matched tool call is BLOCKED: $INPROJ_MSG."
    exit 0
  fi
  if [ ${#runner[@]} -eq 0 ]; then
    say_session "DEUS WITNESS plugin: the client is missing - every matched tool call is BLOCKED. Install uv (https://docs.astral.sh/uv/) or: pip install \"deus-witness==0.2.47\" (Python 3.10+ in a venv)"
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
    ev = json.loads(sys.stdin.read(1048576) or "{}")
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
if [ ${#runner[@]} -eq 0 ] && [ -n "$inproj" ]; then
  cat >/dev/null
  deny "Blocked by Deus Witness: $INPROJ_MSG."
fi
if [ ${#runner[@]} -eq 0 ]; then
  cat >/dev/null
  deny "Blocked by Deus Witness: the client is not installed. Install uv (https://docs.astral.sh/uv/) or run: pip install \"deus-witness==0.2.47\" (Python 3.10+ in a venv)"
fi
exec "${runner[@]}"
