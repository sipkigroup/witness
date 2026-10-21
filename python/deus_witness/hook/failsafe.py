"""Is the hook a boundary or only advice? Checks the Claude Code version and the hook entry in settings.json.

Claude Code runs a PreToolUse hook and blocks the call only on exit 2 or an explicit `deny`. Every other failure of the hook
(it could not start, it timed out, it exited 1, it printed bad JSON) lets the call run - unless the hook entry carries
`"onFailure": "block"`, which Claude Code honours from 2.1.295 on. Older versions drop the key silently (the hook schema is
a plain object, unknown keys are stripped) - so the same settings.json is fail-closed on 2.1.295+ and fail-open below.
Checked 19.10.2026 in the published binaries: `onFailure` is absent from 2.1.294 and present in 2.1.295, 2.1.296, 2.1.299,
2.1.303 ("blocking because onFailure is \"block\""); permissionDecision `defer` is honoured in print mode only
("defer is print-mode only"; interactive sessions ignore it).

  deus-witness-hook --doctor [PROJECT_DIR]   human report, exit 1 if the hook can be bypassed
  deus-witness-hook --session-start          SessionStart hook: prints {"systemMessage": ...} when the hook can be bypassed
"""
from __future__ import annotations

import json
import os
import re
import subprocess

MIN_CC = (2, 1, 295)                       # first Claude Code with "onFailure": "block" for command hooks
MARGIN_S = 5.0                             # our own decision must be printed this long before Claude Code cancels the hook
DEFAULT_CC_TIMEOUT_S = 600.0               # Claude Code's timeout for a command hook without "timeout"
BUILTIN = ("Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read", "WebFetch")
# 0.2.12 (R7-06): built-in tools that read files or send data out. Outside the matcher they bypass the witness: `Grep` with pattern "." on .env
# prints the secret that Read / `cat` would ask about, `WebSearch` sends its query out. Missing ones are a problem, not a note.
READERS = ("Grep", "Glob", "WebSearch")
OPTIONAL = ("NotebookRead", "LS", "ReadMcpResourceTool", "ListMcpResourcesTool")     # older or rarer tools: a note
MATCHER = "Bash|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Read|Grep|Glob|LS|WebFetch|WebSearch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*"


def parse_version(text: str | None):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def claude_version(env=None, runner=subprocess.run):
    """-> (version tuple or None, how it was found). Never raises."""
    # The binary that runs us first: CLAUDE_CODE_VERSION can disagree with it (seen 19.10.2026: env 2.1.42, binary 2.1.303).
    e = os.environ if env is None else env
    tried = []
    for exe in [e.get("CLAUDE_CODE_EXECPATH"), "claude"]:
        if not exe:
            continue
        try:
            r = runner([exe, "--version"], capture_output=True, timeout=5, env=dict(e), stdin=subprocess.DEVNULL)
            v = parse_version(r.stdout.decode("utf-8", "replace"))
            if v:
                return v, "%s --version" % exe
            tried.append("%s --version: no version in its output" % exe)
        except Exception as x:   # noqa: BLE001  missing binary, timeout, ...
            tried.append("%s --version failed (%s)" % (exe, type(x).__name__))
    v = parse_version(e.get("CLAUDE_CODE_VERSION"))
    if v:
        return v, "CLAUDE_CODE_VERSION (binary not found)"
    return None, "; ".join(tried) or "no claude binary"


def _num(v, default):
    try:
        return float(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


def settings_files(project_dir: str | None, env=None):
    e = os.environ if env is None else env
    home = e.get("HOME") or os.path.expanduser("~")
    out = []
    if project_dir:
        out += [os.path.join(project_dir, ".claude", "settings.json"), os.path.join(project_dir, ".claude", "settings.local.json")]
    out.append(os.path.join(home, ".claude", "settings.json"))
    return out


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def find_entries(project_dir, env=None):
    """-> [(file, matcher, hook dict)] for every PreToolUse command hook that runs deus-witness-hook, and the merged env."""
    found, merged_env = [], {}
    for p in reversed(settings_files(project_dir, env)):      # user < project < local, as Claude Code merges env
        d = _load(p)
        if not d:
            continue
        if isinstance(d.get("env"), dict):
            merged_env.update({k: str(v) for k, v in d["env"].items()})
        for grp in ((d.get("hooks") or {}).get("PreToolUse") or []):
            if not isinstance(grp, dict):
                continue
            for h in grp.get("hooks") or []:
                if isinstance(h, dict) and h.get("type") == "command" and "deus-witness-hook" in str(h.get("command", "")) \
                        and "--session-start" not in str(h.get("command", "")):
                    found.append((p, str(grp.get("matcher", "")), h))
    return found, merged_env


def check(project_dir=None, env=None, runner=subprocess.run):
    """-> {"version": ..., "problems": [...], "notes": [...]}. A problem = some failure of the hook lets the tool call run."""
    e = dict(os.environ if env is None else env)
    problems, notes = [], []
    ver, how = claude_version(e, runner)
    if ver is None:
        problems.append("cannot read the Claude Code version (%s): Claude Code below %s ignores \"onFailure\": \"block\"; "
                        "there a crash or a timeout of the hook lets the call run" % (how, ".".join(map(str, MIN_CC))))
    elif ver < MIN_CC:
        problems.append("Claude Code %s is older than %s: it ignores \"onFailure\": \"block\". A hook that times out or crashes "
                        "outside `|| exit 2` lets the call run. Update Claude Code (npm i -g @anthropic-ai/claude-code)"
                        % (".".join(map(str, ver)), ".".join(map(str, MIN_CC))))
    entries, senv = find_entries(project_dir, e)
    for k, v in senv.items():
        e.setdefault(k, v)                                    # the shell's own env wins, as in Claude Code
    if not entries:
        problems.append("no PreToolUse hook running deus-witness-hook in %s" % ", ".join(settings_files(project_dir, e)))
    hook_timeout = _num(e.get("DEUS_WITNESS_HOOK_TIMEOUT"), 20.0)
    wait = _num(e.get("DEUS_WITNESS_HOOK_WAIT"), 0.0)
    for path, matcher, h in entries:
        where = "%s (matcher %r)" % (path, matcher)
        if h.get("onFailure") != "block":
            problems.append("%s: no \"onFailure\": \"block\" - Claude Code runs the call when the hook fails or times out" % where)
        if "|| exit 2" not in str(h.get("command", "")):
            problems.append("%s: command without `|| exit 2` - a missing or broken hook exits 127/1 = the call runs "
                            "(on Claude Code below %s)" % (where, ".".join(map(str, MIN_CC))))
        cc_timeout = _num(h.get("timeout"), DEFAULT_CC_TIMEOUT_S)
        if cc_timeout < hook_timeout + MARGIN_S:
            problems.append("%s: \"timeout\" %.0f s is not above DEUS_WITNESS_HOOK_TIMEOUT %.0f s + %.0f s - Claude Code cancels the "
                            "hook before it answers" % (where, cc_timeout, hook_timeout, MARGIN_S))
        try:
            missing = [t for t in BUILTIN + READERS + OPTIONAL if not re.fullmatch(matcher, t)]
        except re.error:
            missing = list(BUILTIN + READERS + OPTIONAL)
        if [t for t in missing if t in BUILTIN]:
            notes.append("%s does not cover %s: those calls never reach the witness" % (where, ", ".join(t for t in missing if t in BUILTIN)))
        if [t for t in missing if t in READERS]:
            problems.append("%s does not cover %s: they read files or send data without the witness (Grep on .env prints the secret "
                            "that Read asks about; WebSearch sends its query out). Use the matcher %s"
                            % (where, ", ".join(t for t in missing if t in READERS), MATCHER))
        if [t for t in missing if t in OPTIONAL]:
            notes.append("%s does not cover %s (older or MCP-resource tools that read data)" % (where, ", ".join(t for t in missing if t in OPTIONAL)))
    if wait > max(0.0, hook_timeout - MARGIN_S):
        notes.append("DEUS_WITNESS_HOOK_WAIT %.0f s is cut to %.0f s (DEUS_WITNESS_HOOK_TIMEOUT %.0f s - %.0f s)"
                     % (wait, max(0.0, hook_timeout - MARGIN_S), hook_timeout, MARGIN_S))
    if e.get("DEUS_WITNESS_HOOK_ON_DEFER") == "defer":
        notes.append("DEUS_WITNESS_HOOK_ON_DEFER=defer works only in print mode (claude -p, Agent SDK); an interactive session "
                     "ignores `defer` and goes on with its own permission rules - use ask or deny there")
    return {"version": ".".join(map(str, ver)) if ver else None, "version_source": how, "problems": problems, "notes": notes}


BANNER = "DEUS WITNESS: THIS HOOK CAN BE BYPASSED (fail-open)."


def report_text(r) -> str:
    lines = ["Claude Code: %s (%s)" % (r["version"] or "unknown", r["version_source"])]
    if r["problems"]:
        lines += ["", "!" * 72, "!! " + BANNER, "!" * 72] + ["  - " + p for p in r["problems"]]
    else:
        lines.append("OK: fail-closed (onFailure block, || exit 2, timeouts in order)")
    lines += ["  note: " + n for n in r["notes"]]
    return "\n".join(lines)


def session_start_output(r):
    """SessionStart hook output: a warning shown to the person (systemMessage) and told to the model, or nothing."""
    if not r["problems"]:
        return None
    msg = BANNER + " " + " | ".join(r["problems"]) + " Run `deus-witness-hook --doctor` for details."
    return {"systemMessage": msg,
            "hookSpecificOutput": {"hookEventName": "SessionStart",
                                   "additionalContext": "Deus Witness warning for the user: " + msg}}
