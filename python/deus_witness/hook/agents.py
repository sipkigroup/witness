"""0.2.81 (r0353, poligon-lyudi/drugie-agenty/OTCHET-2026-11-19.md): the same hook for other coding agents than Claude Code.

Measured 18-19.11 (L2, each agent's OFFICIAL interception, probe "create probe.txt"):
  - Goose 1.60: the Claude Code answer (`hookSpecificOutput.permissionDecision: deny`, exit 0) is IGNORED -- the file was created. Goose
    blocks on `{"decision": "block", "reason": ..}` or exit 2. A hook that fails with the default on_failure lets the call run.
  - OpenHands 1.16 (SDK 1.21): blocks on exit 2 or a top-level `{"decision": "deny"}`; `hookSpecificOutput` is not read; an error or a
    timeout of the hook = the call runs.
  - Codex CLI 0.170: understands the Claude Code answer (deny blocks); a hook that crashes (exit 1) or is not trusted = the call runs.
    Its file edits may come as the tool `apply_patch` (or a shell line `apply_patch <<EOF`): judged as the writes they are.

So the hook speaks each agent's own language: `--agent goose|openhands|codex|claude-code` (or DEUS_WITNESS_AGENT), else detected from
the event (Goose: "event" + "tool_call_id"; OpenHands: "event_type"; Codex: "turn_id"; anything else: Claude Code). The event is
translated into the Claude Code form the witness judges (tool names, tool_input keys, the project folder), and the answer back into the
form that agent BLOCKS on. A question of the witness ("ask") is a block for an agent with no question of its own (Goose, OpenHands,
Codex): the person answers in Witness and the agent repeats the call. The hook's own failure is a block in every agent's language
(fail-closed): the agent that lets a crashed hook through still gets a deny it understands.
"""
from __future__ import annotations

import json
import os
import re

AGENTS = ("claude-code", "codex", "goose", "openhands")
NO_EFFECT = {"think", "finish", "task_tracker", "todo_write", "TodoWrite", "update_plan", "think_tool"}


def detect(ev, flag=None, env=None):
    e = os.environ if env is None else env
    for v in (flag, e.get("DEUS_WITNESS_AGENT")):
        if isinstance(v, str) and v.strip().lower() in AGENTS:
            return v.strip().lower()
    if not isinstance(ev, dict):
        return "claude-code"
    if "event_type" in ev and "hook_event_name" not in ev:
        return "openhands"
    if "event" in ev and "hook_event_name" not in ev and ("tool_call_id" in ev or "matcher_context" in ev):
        return "goose"
    if "turn_id" in ev:
        return "codex"
    return "claude-code"


def _editor(tool, inp, cwd):
    """Goose text_editor / OpenHands file_editor (str_replace_editor) -> (claude tool, claude input), or None"""
    cmd = str(inp.get("command") or "")
    p = inp.get("path") or inp.get("file_path")
    if not isinstance(p, str) or not p:
        return None
    if cmd in ("write", "create"):
        return "Write", {"file_path": p, "content": inp.get("file_text") if isinstance(inp.get("file_text"), str) else str(inp.get("content") or "")}
    if cmd == "str_replace":
        return "Edit", {"file_path": p, "old_string": str(inp.get("old_str") or ""), "new_string": str(inp.get("new_str") or "")}
    if cmd == "insert":
        return "Edit", {"file_path": p, "old_string": "", "new_string": str(inp.get("new_str") or inp.get("text") or "")}
    if cmd in ("undo_edit",):
        return "Edit", {"file_path": p, "old_string": "", "new_string": "(undo of the last edit)"}
    if cmd == "view":
        return "Read", {"file_path": p}
    return None


_PATCH = re.compile(r"\*\*\* Begin Patch\n(.*?)(?:\*\*\* End Patch|\Z)", re.S)


def patch_parts(text):
    """Codex apply_patch text -> [(claude tool, claude input)] (Add File -> Write, Update File -> Edit, Delete -> rm, Move to -> mv)."""
    m = _PATCH.search(text or "")
    if not m:
        return []
    parts, cur = [], None

    def flush():
        if cur is None:
            return
        k, p, old, new, mv = cur
        if k == "add":
            parts.append(("Write", {"file_path": p, "content": "\n".join(new) + ("\n" if new else "")}))
        elif k == "update":
            parts.append(("Edit", {"file_path": p, "old_string": "\n".join(old), "new_string": "\n".join(new)}))
            if mv:
                parts.append(("Bash", {"command": "mv -- '%s' '%s'" % (p.replace("'", "'\\''"), mv.replace("'", "'\\''"))}))
        elif k == "delete":
            parts.append(("Bash", {"command": "rm -- '%s'" % p.replace("'", "'\\''")}))
    for ln in m.group(1).split("\n"):
        h = re.match(r"\*\*\* (Add|Update|Delete) File: (.+)$", ln)
        if h:
            flush()
            cur = [h.group(1).lower(), h.group(2).strip(), [], [], None]
            continue
        if cur is None:
            continue
        mv = re.match(r"\*\*\* Move to: (.+)$", ln)
        if mv:
            cur[4] = mv.group(1).strip()
        elif ln.startswith("@@") or ln.startswith("*** End of File"):
            continue
        elif ln.startswith("+"):
            cur[3].append(ln[1:])
        elif ln.startswith("-"):
            cur[2].append(ln[1:])
        elif ln.startswith(" "):
            cur[2].append(ln[1:])
            cur[3].append(ln[1:])
    flush()
    return parts


def _patch_text(inp):
    if isinstance(inp, str):
        return inp if "*** Begin Patch" in inp else None
    if isinstance(inp, dict):
        for k in ("command", "patch", "input", "content"):
            v = inp.get(k)
            if isinstance(v, str) and "*** Begin Patch" in v:
                return v
            if isinstance(v, list) and any(isinstance(x, str) and "*** Begin Patch" in x for x in v):
                return next(x for x in v if isinstance(x, str) and "*** Begin Patch" in x)
    return None


def normalize(ev, agent, env=None):
    """-> (events, env_updates): the Claude Code PreToolUse events the witness judges for this call ([] = nothing to judge: no effect;
    None = not a PreToolUse event), and environment the hook reads (the project folder) when the agent gives it another way."""
    e = os.environ if env is None else env
    if not isinstance(ev, dict):
        return [ev], {}
    upd = {}
    if agent == "claude-code":
        return [ev], upd
    if agent == "openhands":
        name = ev.get("event_type")
        cwd = ev.get("working_dir") or e.get("OPENHANDS_PROJECT_DIR") or os.getcwd()
        if not e.get("CLAUDE_PROJECT_DIR") and (e.get("OPENHANDS_PROJECT_DIR") or ev.get("working_dir")):
            upd["CLAUDE_PROJECT_DIR"] = e.get("OPENHANDS_PROJECT_DIR") or ev.get("working_dir")
    elif agent == "goose":
        name = ev.get("event")
        cwd = ev.get("cwd") or os.getcwd()
    else:
        name = ev.get("hook_event_name")
        cwd = ev.get("cwd") or os.getcwd()
    if not e.get("CLAUDE_PROJECT_DIR") and "CLAUDE_PROJECT_DIR" not in upd and agent in ("goose", "codex"):
        upd["CLAUDE_PROJECT_DIR"] = cwd
    if name not in (None, "PreToolUse"):
        return None, upd
    tool = str(ev.get("tool_name") or "")
    inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), (dict, str)) else {}
    base = {k: v for k, v in ev.items() if k not in ("event", "event_type", "working_dir", "matcher_context", "metadata")}
    base.update(hook_event_name="PreToolUse", cwd=cwd, session_id=str(ev.get("session_id") or "%s-session" % agent))
    if ev.get("tool_call_id") and not base.get("tool_use_id"):
        base["tool_use_id"] = str(ev["tool_call_id"])
    short = tool.split("__")[-1]                    # Goose names an extension's tool "developer__shell"
    parts = None
    if short in NO_EFFECT:
        return [], upd
    if agent == "codex" and (short == "apply_patch" or _patch_text(inp) and short not in ("Bash", "shell", "exec_command")):
        parts = patch_parts(_patch_text(inp) or "")
        if not parts:
            parts = [("Edit", {"file_path": "(apply_patch)", "old_string": "", "new_string": str(_patch_text(inp) or inp)[:4096]})]
    elif short in ("shell", "terminal", "execute_bash", "bash", "exec_command", "local_shell", "run_shell_command") and isinstance(inp, dict):
        c = inp.get("command") if isinstance(inp.get("command"), str) else inp.get("cmd")
        if isinstance(c, list):
            c = " ".join(str(x) for x in c)
        parts = [("Bash", {"command": str(c or "")})]
    elif short in ("text_editor", "file_editor", "str_replace_editor", "editor") and isinstance(inp, dict):
        x = _editor(short, inp, cwd)
        parts = [x] if x else [(tool, inp)]
    else:
        parts = [(tool, inp)]
    out = []
    for i, (t, ti) in enumerate(parts):
        if t == "Bash" and agent == "codex":
            pt = _patch_text(ti.get("command"))            # `apply_patch <<'EOF' *** Begin Patch ..` through the shell: the writes too
            if pt and re.match(r"\s*apply_patch\b", ti.get("command") or ""):
                for t2, ti2 in patch_parts(pt):
                    out.append(dict(base, tool_name=t2, tool_input=ti2, tool_use_id="%s-p%d" % (base.get("tool_use_id") or "t", len(out))))
        out.append(dict(base, tool_name=t, tool_input=ti, **({"tool_use_id": "%s-p%d" % (base.get("tool_use_id") or "t", i)} if len(parts) > 1 else {})))
    return out, upd


def combine(results):
    """the answers for the parts of one call -> one answer: the first deny, else the first ask, else the first allow, else None"""
    rs = [r for r in results if isinstance(r, dict)]
    for want in ("deny", "ask", "defer", "allow"):
        for r in rs:
            if (r.get("hookSpecificOutput") or {}).get("permissionDecision") == want:
                return r
    return rs[0] if rs else None


def _decision(r):
    h = (r or {}).get("hookSpecificOutput") or {} if isinstance(r, dict) else {}
    return h.get("permissionDecision"), (h.get("permissionDecisionReason") or (r or {}).get("systemMessage") or "")


def render(r, agent):
    """-> (stdout text or None, exit code) in the language of the agent"""
    if agent == "claude-code":
        return (json.dumps(r, ensure_ascii=False) + "\n" if r is not None else None), 0
    d, why = _decision(r)
    if agent == "codex":
        if d in ("ask", "defer"):
            # Codex has no question of its own here: a question of the witness is a block until the person answers in Witness
            h = dict(r["hookSpecificOutput"], permissionDecision="deny",
                     permissionDecisionReason=(why + " (Witness asked the person; repeat the call after they answer.)").strip())
            r = dict(r, hookSpecificOutput=h)
        return (json.dumps(r, ensure_ascii=False) + "\n" if r is not None else None), 0
    if d in ("deny", "ask", "defer"):
        why = why or "Blocked by Deus Witness"
        if d != "deny":
            why += " (Witness asked the person; repeat the call after they answer.)"
        if agent == "goose":
            return json.dumps({"decision": "block", "reason": why}, ensure_ascii=False) + "\n", 2
        return json.dumps({"decision": "deny", "reason": why}, ensure_ascii=False) + "\n", 2
    if agent == "openhands" and d == "allow":
        return json.dumps({"decision": "allow"}) + "\n", 0
    return None, 0


def fail_closed(agent, what):
    """-> (stdout text or None, exit code): the hook's OWN failure as a block the agent understands (Claude Code: exit 2 alone, as before)"""
    why = "Blocked by Deus Witness: HOOK_ERROR %s (a failure of Deus Witness itself; the call did not run)" % what
    if agent == "goose":
        return json.dumps({"decision": "block", "reason": why}) + "\n", 2
    if agent == "openhands":
        return json.dumps({"decision": "deny", "reason": why}) + "\n", 2
    if agent == "codex":
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                  "permissionDecisionReason": why}}) + "\n", 0
    return None, 2


# ---------------------------------------------------------------- doctor: agents that let a call through when the hook fails
def _read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read(1 << 20)
    except (OSError, UnicodeDecodeError):
        return None


def doctor_lines(home=None):
    """-> [warning] for each other agent on this computer whose hook configuration names deus-witness-hook but would let a call run when
    the hook fails (Goose without on_failure: block; OpenHands always; Codex: an untrusted or crashing hook)."""
    import glob
    h = home or os.path.expanduser("~")
    out = []
    for p in sorted(glob.glob(os.path.join(h, ".agents", "plugins", "*", "hooks", "hooks.json")) +
                    glob.glob(os.path.join(h, ".config", "goose", "*.json")) + glob.glob(os.path.join(h, ".config", "goose", "*.yaml"))):
        t = _read(p)
        if t and "deus-witness-hook" in t:
            if not re.search(r"[\"']?on_failure[\"']?\s*[:=]\s*[\"']?block", t):
                out.append("Goose (%s): a failing hook lets the call run -- add \"on_failure\": \"block\" to the deus-witness-hook entry, "
                           "and run it with --agent goose." % p)
            elif "--agent goose" not in t:
                out.append("Goose (%s): run the hook as `deus-witness-hook --agent goose` (it is detected from the event, the flag is surer)." % p)
    for p in (os.path.join(h, ".openhands", "hooks.json"),):
        t = _read(p)
        if t and "deus-witness-hook" in t:
            out.append("OpenHands (%s): OpenHands runs the call when the hook fails or times out (only exit 2 or \"decision\": \"deny\" "
                       "blocks). The hook answers deny on its own errors; keep its \"timeout\" above DEUS_WITNESS_HOOK_TIMEOUT, and use a "
                       "managed hook where your organisation can set one." % p)
    found = codex_hooks(h)
    for p, kinds in found:
        if "PreToolUse" in kinds or not kinds:
            line = ("Codex (%s): without trusting this hook in /hooks there is NO protection -- Codex skips a new or changed hook until you "
                    "trust it, and a hook error, timeout or bad answer can let the tool run (the hook itself answers deny on its own "
                    "errors). Open /hooks in Codex and trust the deus-witness-hook entry." % p)
            if not any("SessionStart" in k for _, k in found):
                line += " Add a SessionStart hook `deus-witness-hook --session-start --agent codex` for a reminder at every start."
            out.append(line)
    return out


# ---------------------------------------------------------------- Codex: the hook files and the session-start reminder (0.2.82, r0355)
def codex_files(home=None, cwd=None, env=None):
    """the files Codex reads hooks from (Codex docs, "Hooks": /etc/codex/hooks.json, $CODEX_HOME/hooks.json, a trusted project's
    .codex/hooks.json; hooks also inline under [hooks] in config.toml), those that exist"""
    e = os.environ if env is None else env
    h = home or os.path.expanduser("~")
    ch = e.get("CODEX_HOME") or os.path.join(h, ".codex")
    ps = ["/etc/codex/hooks.json", os.path.join(ch, "hooks.json"), os.path.join(ch, "config.toml")]
    if ch != os.path.join(h, ".codex"):
        ps += [os.path.join(h, ".codex", "hooks.json"), os.path.join(h, ".codex", "config.toml")]
    if cwd:
        ps += [os.path.join(cwd, ".codex", "hooks.json"), os.path.join(cwd, ".codex", "config.toml")]
    seen, out = set(), []
    for p in ps:
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            out.append(p)
    return out


_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop",
           "PermissionRequest", "Notification", "PreCompact")


def _json_hook_events(t):
    """-> set of events whose hook commands name deus-witness-hook in a hooks.json text, or None when it is not JSON"""
    try:
        d = json.loads(t)
    except ValueError:
        return None
    hk = d.get("hooks") if isinstance(d, dict) else None
    if not isinstance(hk, dict):
        return set()
    out = set()
    for ev, groups in hk.items():
        if "deus-witness-hook" in json.dumps(groups):
            out.add(str(ev))
    return out


def codex_hooks(home=None, cwd=None, env=None):
    """-> [(file, {events whose hook runs deus-witness-hook})] for each Codex hook file that names deus-witness-hook. A TOML file is read
    by its section names ([[hooks.PreToolUse]] ...) around the name; an event Witness cannot tell -> empty set (still listed)."""
    out = []
    for p in codex_files(home, cwd, env):
        t = _read(p)
        if not t or "deus-witness-hook" not in t:
            continue
        ev = _json_hook_events(t) if p.endswith(".json") else None
        if ev is None:
            ev = set()
            cur = None
            for ln in t.splitlines():
                m = re.match(r"^\s*\[\[?\s*hooks\.([A-Za-z]+)", ln)
                if m:
                    cur = m.group(1)
                elif re.match(r"^\s*\[", ln):
                    cur = None
                if "deus-witness-hook" in ln and cur in _EVENTS:
                    ev.add(cur)
        out.append((p, ev))
    return out


def codex_session_line(home=None, cwd=None, env=None):
    """-> the reminder a Codex SessionStart hook (`deus-witness-hook --session-start --agent codex`) shows the person. The hook cannot
    see whether Codex trusts its PreToolUse entry (a SessionStart entry is trusted on its own), so it says what makes the protection
    real; with no PreToolUse entry at all it says that nothing is checked."""
    found = codex_hooks(home, cwd, env)
    if not any("PreToolUse" in k for _, k in found):
        return ("DEUS WITNESS: Codex does not send its tool calls to Witness in this session -- no PreToolUse hook runs deus-witness-hook. "
                "Add one (`deus-witness-hook --agent codex`) and trust it in /hooks.")
    return ("DEUS WITNESS: Witness protects this Codex session only if its PreToolUse hook is trusted. Codex skips a new or changed hook "
            "until you trust it in /hooks -- then no call is checked. If Codex asked you to review hooks, open /hooks now.")
