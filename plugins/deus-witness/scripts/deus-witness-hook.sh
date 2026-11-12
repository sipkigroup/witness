#!/usr/bin/env bash
# Deus Witness plugin for Claude Code: runs the PyPI client `deus-witness-hook` (>= 0.2.34) for the plugin's hooks.
#
#   deus-witness-hook.sh             PreToolUse: the witness decides the call (stdin = the event, stdout = the decision)
#   deus-witness-hook.sh --session-start   SessionStart: warns when the hook can be bypassed or is not configured
#
# Where the client comes from, in this order:
#   1. `deus-witness-hook` on PATH (pip install "deus-witness==0.2.63"; Python 3.10+ in a venv OUTSIDE the project: one found inside
#      the project, as found or resolved, is not used - the agent may write there)
#   2. `uvx --from "deus-witness==0.2.63" deus-witness-hook` (needs uv: https://docs.astral.sh/uv/)
#
# The agent key: DEUS_WITNESS_KEY, else the plugin option agent_key, else the key file `deus-witness try` saved
# (${DEUS_WITNESS_HOME:-~/.config/deus-witness}/agent-key.json, or a fallback place - see below; the client reads it itself).
# Not configured (no key anywhere) = calls are not witnessed yet, and the plugin SAYS so: at session start, and once per session on
# the first tool call ("run /deus-witness:try": a trial account, two passkey touches, no sign-up form). With the plugin option
# `strict` on, every matched call is denied until a key is set.
# Configured (a key is set) = fail-closed: a missing client, a crash or a timeout blocks the call
# (`|| exit 2` and "onFailure": "block" in hooks.json).
set -u

SPEC="deus-witness==0.2.63"
SIGNUP="https://witness.sipkigroup.com/signup.html"
TRY="/deus-witness:try (or in your terminal: uvx --from \"deus-witness==0.2.63\" deus-witness try)"

# Plugin options (userConfig) arrive as CLAUDE_PLUGIN_OPTION_<KEY>; a variable already set in the environment wins.
export DEUS_WITNESS_KEY="${DEUS_WITNESS_KEY:-${CLAUDE_PLUGIN_OPTION_AGENT_KEY:-}}"
export DEUS_WITNESS_URL="${DEUS_WITNESS_URL:-${CLAUDE_PLUGIN_OPTION_WITNESS_URL:-https://witness.sipkigroup.com}}"
# 0.2.57 (friction 03.11): wait 45 s, not 600. Claude Code shows nothing while a hook runs; the client notifies at once (desktop notification,
# the approval page in the browser) and the refusal says where to approve. A later approval still works: the request stays open in Witness
# and the agent reruns the same call.
export DEUS_WITNESS_HOOK_TIMEOUT="${DEUS_WITNESS_HOOK_TIMEOUT:-55}"    # hooks.json "timeout" is 65: 5+ s above this
export DEUS_WITNESS_HOOK_WAIT="${DEUS_WITNESS_HOOK_WAIT:-45}"          # wait for the owner's approval in Witness
export DEUS_WITNESS_HOOK_ON_DEFER="${DEUS_WITNESS_HOOK_ON_DEFER:-deny}"
STRICT="${CLAUDE_PLUGIN_OPTION_STRICT:-false}"
[ -n "$DEUS_WITNESS_KEY" ] || unset DEUS_WITNESS_KEY
# 0.2.50 (N22): the key file is looked for where `deus-witness try` (0.2.50+) may save it, in its order: DEUS_WITNESS_KEY_FILE; else
# DEUS_WITNESS_HOME; else $XDG_CONFIG_HOME/deus-witness, ~/.config/deus-witness, ~/Library/Application Support/deus-witness (macOS),
# ~/.deus-witness (a ~/.config owned by root after `sudo npm` / `sudo brew` sends the key to the next place).
if [ -n "${DEUS_WITNESS_KEY_FILE:-}" ]; then
  keyfiles=("$DEUS_WITNESS_KEY_FILE")
elif [ -n "${DEUS_WITNESS_HOME:-}" ]; then
  keyfiles=("$DEUS_WITNESS_HOME/agent-key.json")
else
  keyfiles=()
  case "${XDG_CONFIG_HOME:-}" in /*) keyfiles+=("$XDG_CONFIG_HOME/deus-witness/agent-key.json") ;; esac
  keyfiles+=("$HOME/.config/deus-witness/agent-key.json" "$HOME/Library/Application Support/deus-witness/agent-key.json" "$HOME/.deus-witness/agent-key.json")
fi
configured=""
[ -n "${DEUS_WITNESS_KEY:-}" ] && configured=1
for KEYFILE in "${keyfiles[@]}"; do
  [ -s "$KEYFILE" ] && { configured=1; break; }
done
# 0.2.50 (N22): `deus-witness try` leaves this mark when it starts and removes it once the key is saved. A mark and no key = a `try` that
# did not finish (no place to save the key, the witness unreachable, interrupted): calls are then REFUSED with a loud message - the person
# asked for the witness, so nothing runs unwitnessed by surprise. Removing the mark (the message names it) goes back to "not set up".
# 0.2.61 (r0263, L3 12.11): one mark per place of the KEY (DEUS_WITNESS_HOME when set), not per home: a mark an interrupted `try` left for
# another setup with the same HOME blocked this one (the client's trial.try_mark builds the same name).
TRYMARK="${TMPDIR:-/tmp}"
TRYWHO="${DEUS_WITNESS_HOME:-$HOME}"
TRYMARK="${TRYMARK%/}/deus-witness-try-$(id -u 2>/dev/null || echo u)${TRYWHO//[^A-Za-z0-9]/_}"
trybroken=""
if [ -z "$configured" ] && [ -f "$TRYMARK" ]; then trybroken=1; fi
# 0.2.62 (r0264, L3 12.11): under `claude --plugin-dir X` the plugin is not in installed_plugins.json and `try` said "the hook is NOT
# installed" (the model then sent the person to the marketplace). This launcher IS running for the try line: it says so in a mark next
# to try's own (the client's trial.hook_seen_mark / hook_seen read it; a configured client writes it itself). $1 = the event JSON.
seen_try() {
  python3 -c '
import json, os, re, sys, time
try:
    ev = json.loads(sys.argv[1] or "{}")
except ValueError:
    sys.exit(0)
c = (ev.get("tool_input") or {}).get("command") if ev.get("tool_name") == "Bash" and isinstance(ev.get("tool_input"), dict) else None
rx = r"(?:uvx(?: --quiet)? --from (?:\"deus-witness==[0-9][0-9.]*\"|\x27deus-witness==[0-9][0-9.]*\x27|deus-witness==[0-9][0-9.]*|deus-witness) )?deus-witness try"
if not (isinstance(c, str) and re.fullmatch(rx, c.strip())):
    sys.exit(0)
p = os.environ.get("CLAUDE_PROJECT_DIR") or ev.get("cwd") or os.getcwd()
with open(sys.argv[2], "w") as f:
    json.dump({"t": int(time.time()), "project": os.path.realpath(p), "plugin_root": os.environ.get("CLAUDE_PLUGIN_ROOT") or None}, f)
' "$1" "$TRYMARK.hook" 2>/dev/null || true
}
# 0.2.57 (QA 03.11, D7/D15): "not set up" (calls run unwitnessed, said once) only on a machine where the witness was never set up and nothing
# points elsewhere. A project's .claude/settings.json can set "env" for hooks, so DEUS_WITNESS_KEY_FILE / DEUS_WITNESS_HOME pointing at
# nothing, a key file of 0 bytes, or no key while a DEFAULT place of the REAL home (not one the environment names) shows the witness was set
# up (agent-key.json, the pinned witness key witness.json, scanlist.json) = the key is MISSING: every call is REFUSED, loudly.
# (absolute programs only: PATH is not filtered yet here)
REALHOME="$(/usr/bin/dscl . -read "/Users/$(/usr/bin/id -un 2>/dev/null)" NFSHomeDirectory 2>/dev/null | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')"
[ -n "$REALHOME" ] || REALHOME="$( { /usr/bin/getent passwd "$(/usr/bin/id -u 2>/dev/null)" || /bin/getent passwd "$(/usr/bin/id -u 2>/dev/null)"; } 2>/dev/null | /usr/bin/cut -d: -f6)"
[ -n "$REALHOME" ] || REALHOME="${HOME:-}"
lost=""
if [ -z "$configured" ] && [ -z "$trybroken" ]; then
  for d in "$REALHOME/.config/deus-witness" "$REALHOME/Library/Application Support/deus-witness" "$REALHOME/.deus-witness"; do
    for f in agent-key.json witness.json scanlist.json; do
      [ -e "$d/$f" ] && lost="the witness was set up on this machine: $d/$f"
    done
  done
  for KEYFILE in "${keyfiles[@]}"; do
    [ -e "$KEYFILE" ] && [ ! -s "$KEYFILE" ] && lost="the key file $KEYFILE is empty"
  done
  [ -n "${DEUS_WITNESS_HOME:-}" ] && lost="DEUS_WITNESS_HOME names $DEUS_WITNESS_HOME, where there is no agent key"
  [ -n "${DEUS_WITNESS_KEY_FILE:-}" ] && lost="DEUS_WITNESS_KEY_FILE names $DEUS_WITNESS_KEY_FILE, which holds no agent key"
fi
LOST_MSG="DEUS WITNESS: the agent key is MISSING ($lost), so every tool call is BLOCKED instead of running unwitnessed. If a project's .claude/settings.json (or settings.local.json) sets DEUS_WITNESS_* in \"env\", remove it. Set up again: $TRY . To stop the witness on purpose: in your own terminal, claude plugin disable deus-witness@sipkigroup"
# 0.2.57 (QA D9): the client compares its version and the plugin's at session start (an old plugin pins an old client and nobody notices)
export DEUS_WITNESS_PLUGIN_VERSION="${SPEC#deus-witness==}"
BROKEN_MSG="DEUS WITNESS IS NOT WORKING: \`deus-witness try\` was started but saved no agent key (its last lines say why), so this call is BLOCKED instead of running unwitnessed. Run $TRY again: it is the one line that still runs. To use Claude Code without the witness instead: rm \"$TRYMARK\""

mode="${1:-pretool}"

# The agent may write inside the project, so nothing this script runs may come from there: a project .venv activated before `claude`,
# direnv `PATH_add bin`, a relative PATH entry. Those PATH entries are dropped (as given and resolved) before ANY command is looked up -
# the client, uvx, and python3 / head / sed below. A client found elsewhere that resolves (symlink) or whose interpreter points into the
# project is not used either. (A project that is the home directory itself is not filtered: the agent can write all of it anyway.)
# 0.2.57: the PATH Claude Code runs Bash commands with, before the filter below (the client resolves `python3` on it: does a line run the
# project's .venv? server 0.2.89 asks EXEC_CHANGED about a changed venv file only then). Read only; never used to find a program here.
export DEUS_WITNESS_CALLER_PATH="${DEUS_WITNESS_CALLER_PATH:-${PATH:-}}"
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
  runner=(uvx --quiet --from "deus-witness==0.2.63" deus-witness-hook)   # literal pin: the directory validator must see it
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
    p="$p First install uv (https://docs.astral.sh/uv/): without it /deus-witness:try cannot run (or: pip install \"deus-witness==0.2.63\" with Python 3.10+ in a venv)."
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
  if [ -n "$trybroken" ]; then
    say_session "$BROKEN_MSG"
    exit 0
  fi
  if [ -n "$lost" ]; then
    say_session "$LOST_MSG"
    exit 0
  fi
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
    say_session "DEUS WITNESS plugin: the client is missing - every matched tool call is BLOCKED. Install uv (https://docs.astral.sh/uv/) or: pip install \"deus-witness==0.2.63\" (Python 3.10+ in a venv)"
    exit 0
  fi
  exec "${runner[@]}" --session-start </dev/null
fi

# PreToolUse
# 0.2.61 (r0263, L3 З2): a broken `try` or a missing key refuses every call -- but the way out runs: exactly the lines /deus-witness:try
# runs (no other words). Read once; given to the client or the checks below as it was.
ev=""
if [ -n "$trybroken" ] || [ -n "$lost" ]; then
  ev="$(head -c 1048576)"
  if printf '%s' "$ev" | python3 -c '
import json, re, sys
try:
    ev = json.loads(sys.stdin.read() or "{}")
except ValueError:
    sys.exit(1)
c = (ev.get("tool_input") or {}).get("command") if ev.get("tool_name") == "Bash" and isinstance(ev.get("tool_input"), dict) else None
rx = r"(?:uvx(?: --quiet)? --from (?:\"deus-witness==[0-9][0-9.]*\"|\x27deus-witness==[0-9][0-9.]*\x27|deus-witness==[0-9][0-9.]*|deus-witness) )?deus-witness try"
sys.exit(0 if isinstance(c, str) and re.fullmatch(rx, c.strip()) else 1)' 2>/dev/null; then
    seen_try "$ev"
    exit 0
  fi
fi
if [ -n "$trybroken" ]; then
  python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.argv[1], "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": sys.argv[1]}}))' "$BROKEN_MSG" 2>/dev/null \
    || { echo "$BROKEN_MSG" >&2; exit 2; }
  exit 0
fi
if [ -n "$lost" ]; then
  cat >/dev/null
  python3 -c 'import json,sys; print(json.dumps({"systemMessage": sys.argv[1], "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": sys.argv[1]}}))' "$LOST_MSG" 2>/dev/null \
    || { echo "$LOST_MSG" >&2; exit 2; }
  exit 0
fi
if [ -z "$configured" ]; then
  if [ "$STRICT" = "true" ]; then
    cat >/dev/null
    deny "Blocked by Deus Witness (strict, no agent key). Set up: $TRY, or set agent_key in /plugin -> deus-witness -> Configure, or DEUS_WITNESS_KEY."
  fi
  # not set up: the call runs as without the plugin, but the person is told once per session (not silently fail-open)
  ev="$(head -c 1048576)"
  seen_try "$ev"
  printf '%s' "$ev" | python3 -c '
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
  deny "Blocked by Deus Witness: the client is not installed. Install uv (https://docs.astral.sh/uv/) or run: pip install \"deus-witness==0.2.63\" (Python 3.10+ in a venv). To work without Witness, the user runs in their own terminal: claude plugin disable deus-witness@sipkigroup (back on: claude plugin enable deus-witness@sipkigroup)"
fi
exec "${runner[@]}"
