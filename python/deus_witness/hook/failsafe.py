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
import sys

from .. import _compat

MIN_CC = (2, 1, 295)                       # first Claude Code with "onFailure": "block" for command hooks
MARGIN_S = 5.0                             # our own decision must be printed this long before Claude Code cancels the hook
DEFAULT_CC_TIMEOUT_S = 600.0               # Claude Code's timeout for a command hook without "timeout"
BUILTIN = ("Bash", "Edit", "Write", "MultiEdit", "NotebookEdit", "Read", "WebFetch")
# 0.2.12 (R7-06): built-in tools that read files or send data out. Outside the matcher they bypass the witness: `Grep` with pattern "." on .env
# prints the secret that Read / `cat` would ask about, `WebSearch` sends its query out. Missing ones are a problem, not a note.
READERS = ("Grep", "Glob", "WebSearch")
OPTIONAL = ("PowerShell", "NotebookRead", "LS", "ReadMcpResourceTool", "ListMcpResourcesTool")     # older or rarer tools: a note
MATCHER = "Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Read|Grep|Glob|LS|WebFetch|WebSearch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*"


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


# Managed settings (code.claude.com/docs/en/managed-settings): file-based policy lives in a system directory.
MANAGED_DIRS = {"darwin": "/Library/Application Support/ClaudeCode", "win32": r"C:\Program Files\ClaudeCode"}
MANAGED_DIR_DEFAULT = "/etc/claude-code"                   # Linux and WSL
MANAGED_DIR_OVERRIDE = None                                # TESTS ONLY (monkeypatch). Deliberately not an env var: a project `env` block must not redirect it.


def managed_dir(platform=None):
    if MANAGED_DIR_OVERRIDE is not None:
        return MANAGED_DIR_OVERRIDE
    return MANAGED_DIRS.get(platform or sys.platform, MANAGED_DIR_DEFAULT)


def managed_files(platform=None):
    """Managed settings files in MERGE order (the later one wins a single value): managed-settings.json, then every
    managed-settings.d/*.json alphabetically (hidden files and non-.json are ignored, as Claude Code does)."""
    d = managed_dir(platform)
    out = [os.path.join(d, "managed-settings.json")]
    try:
        names = sorted(n for n in os.listdir(os.path.join(d, "managed-settings.d")) if n.endswith(".json") and not n.startswith("."))
    except OSError:
        names = []
    return out + [os.path.join(d, "managed-settings.d", n) for n in names]


def user_config_dir(env=None):
    """Claude Code's user configuration directory: $CLAUDE_CONFIG_DIR when set to an absolute path, else ~/.claude."""
    e = os.environ if env is None else env
    cfg = e.get("CLAUDE_CONFIG_DIR")
    return cfg if isinstance(cfg, str) and os.path.isabs(cfg) else os.path.join(_compat.home(e), ".claude")


def _base_settings_files(project_dir, e):
    out = list(reversed(managed_files()))
    if project_dir:
        out += [os.path.join(project_dir, ".claude", "settings.local.json"), os.path.join(project_dir, ".claude", "settings.json")]
    out.append(os.path.join(user_config_dir(e), "settings.json"))
    return out


PLUGIN_NAME = "deus-witness"


def _under(path, root) -> bool:
    try:
        p, r = os.path.realpath(path), os.path.realpath(root)
    except (TypeError, ValueError):
        return False
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def plugin_state(project_dir, env=None):
    """0.2.40: the Deus Witness plugin as Claude Code registered it, for a doctor run from a plain terminal (no CLAUDE_PLUGIN_ROOT).
    Claude Code (checked 26.10.2026, 2.1.311) records an install in <config dir>/plugins/installed_plugins.json
    ({"version": 2, "plugins": {"deus-witness@<marketplace>": [{"scope", "installPath", "projectPath"?...}]}}) and switches it on or off
    with "enabledPlugins": {"deus-witness@<marketplace>": true|false} in settings.json (user, project, local or managed; the usual merge
    order). -> [{"id", "hooks", "scope", "enabled": True|False|None, "enabled_in": file or None}]; enabled None = installed, but no
    settings file says whether it is on (the doctor says so instead of guessing). Read only; never raises."""
    e = os.environ if env is None else env
    d = _load(os.path.join(user_config_dir(e), "plugins", "installed_plugins.json"))
    plugins = d.get("plugins") if d else None
    if not isinstance(plugins, dict):
        return []
    enabled, where = {}, {}
    for p in reversed(_base_settings_files(project_dir, e)):          # lowest priority first, later wins
        s = _load(p)
        ep = s.get("enabledPlugins") if s else None
        if isinstance(ep, dict):
            for k, v in ep.items():
                if isinstance(v, bool):
                    enabled[k], where[k] = v, p
    out = []
    for pid, installs in sorted(plugins.items()):
        if not isinstance(pid, str) or pid.split("@", 1)[0] != PLUGIN_NAME or not isinstance(installs, list):
            continue
        for inst in installs:
            if not isinstance(inst, dict) or not isinstance(inst.get("installPath"), str):
                continue
            scope = inst.get("scope") or "user"
            pp = inst.get("projectPath")
            if scope != "user" and isinstance(pp, str) and not (project_dir and _under(project_dir, pp)):
                continue                                          # installed for another project
            hooks = os.path.join(inst["installPath"], "hooks", "hooks.json")
            if not os.path.isfile(hooks):
                continue
            out.append({"id": pid, "hooks": hooks, "scope": scope, "enabled": enabled.get(pid), "enabled_in": where.get(pid)})
    return out


def settings_files(project_dir: str | None, env=None):
    """Highest priority first: managed (last drop-in first), project local, project, user, plugin.
    0.2.56: local BEFORE project (it was the other way round, so a project value beat a local one in the merged view; Claude Code's
    order is "managed, command line, project local, shared project, user"), and the user file follows $CLAUDE_CONFIG_DIR when it is
    set to an absolute path (Claude Code keeps settings.json there instead of ~/.claude). Read from the process environment only:
    a settings `env` block must not redirect it."""
    e = os.environ if env is None else env
    out = _base_settings_files(project_dir, e)
    # 0.2.27: installed as a Claude Code plugin, the hook entry lives in the plugin's hooks/hooks.json, and Claude Code exports
    # CLAUDE_PLUGIN_ROOT to the hook process. Read that file too, or --session-start reports a missing hook that is there.
    root = e.get("CLAUDE_PLUGIN_ROOT")
    if root:
        out.append(os.path.join(root, "hooks", "hooks.json"))
    else:
        # 0.2.40: outside Claude Code (a doctor run from a terminal) there is no CLAUDE_PLUGIN_ROOT: take the plugin's hooks file from
        # Claude Code's own plugin registry, when a settings file switches the plugin on (unknown or off: see plugin_state / check)
        out += [p["hooks"] for p in plugin_state(project_dir, e) if p["enabled"] is True]
    return out


def agent_key_source(env=None):
    """0.2.40: where the hook gets its agent key, as the hook itself does (hook/main.py): DEUS_WITNESS_KEY, else the key file
    `deus-witness try` saved. -> "DEUS_WITNESS_KEY", the key file path, or None."""
    e = os.environ if env is None else env
    if e.get("DEUS_WITNESS_KEY"):
        return "DEUS_WITNESS_KEY"
    try:
        from ..trial import key_path, load_key
        if load_key(e) is not None:
            return key_path(e)
    except Exception:      # noqa: BLE001  a thin install without httpx: the env variable is all we can see
        pass
    return None


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def find_entries(project_dir, env=None):
    """-> [(file, matcher, hook dict)] for every ACTIVE PreToolUse command hook that runs deus-witness-hook, and the merged env.
    Active, per the Claude Code docs: `disableAllHooks` outside managed settings cannot switch off managed hooks; only managed
    `disableAllHooks` can. Managed `allowManagedHooksOnly` blocks user/project/local/plugin hooks. Skipped hooks go to self-notes
    via find_state(); this wrapper keeps the old two-value shape."""
    found, merged_env, _ = find_state(project_dir, env)
    return found, merged_env


def is_managed(path):
    return path in set(managed_files())


def find_state(project_dir, env=None):
    files = settings_files(project_dir, env)
    managed = set(managed_files())
    flags = {"managed_disable": False, "other_disable": [], "managed_only": False}
    for p in reversed(files):                                  # merge order: lowest priority first, later wins
        d = _load(p)
        if not d:
            continue
        if p in managed:
            if "disableAllHooks" in d:
                flags["managed_disable"] = d["disableAllHooks"] is True
            if d.get("allowManagedHooksOnly") is True:
                flags["managed_only"] = True
        elif d.get("disableAllHooks") is True:
            flags["other_disable"].append(p)
    found, merged_env = [], {}
    for p in reversed(files):                                  # user < project < local < managed, as Claude Code merges env
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
    skipped = []
    active = []
    for ent in found:
        m = ent[0] in managed
        if flags["managed_disable"]:
            skipped.append((ent[0], "managed disableAllHooks=true switches every hook off"))
        elif not m and flags["other_disable"]:
            skipped.append((ent[0], "disableAllHooks=true in %s (outside managed it disables non-managed hooks only)" % ", ".join(flags["other_disable"])))
        elif not m and flags["managed_only"]:
            skipped.append((ent[0], "managed allowManagedHooksOnly=true blocks non-managed hooks"))
        else:
            active.append(ent)
    flags["skipped"] = skipped
    return active, merged_env, flags


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
    entries, senv, st = find_state(project_dir, e)
    unsure = []
    # 0.2.40 (HN rehearsal 6, K1): a client installed inside the project can be rewritten by an allowed write in the project
    from . import selfpath
    if project_dir and selfpath.inside(selfpath.places(e), {os.path.normpath(os.path.abspath(project_dir)), os.path.realpath(project_dir)}):
        problems.append("this client runs from inside the project (%s): an agent that may write in the project can replace the hook "
                        "itself (a venv in the project, a `bin` on PATH). Install it outside the project: uvx, or a venv elsewhere"
                        % sorted(p for p in selfpath.places(e) if selfpath._under(p, os.path.realpath(project_dir)) or
                                 selfpath._under(p, os.path.normpath(os.path.abspath(project_dir))))[0])
    # 0.2.40: the plugin as Claude Code registered it (a doctor run from a terminal has no CLAUDE_PLUGIN_ROOT)
    inside = bool(e.get("CLAUDE_PLUGIN_ROOT"))
    plugins = [] if inside else plugin_state(project_dir, e)
    plugin_hooks = {p["hooks"]: p for p in plugins}
    if inside:
        plugin_hooks[os.path.join(e["CLAUDE_PLUGIN_ROOT"], "hooks", "hooks.json")] = {"id": PLUGIN_NAME, "enabled": True, "enabled_in": "this Claude Code session"}
    for p in plugins:
        if p["enabled"] is None:
            unsure.append("the %s plugin is installed (%s) but no settings file says whether it is enabled, so this check cannot tell "
                          "whether Claude Code runs its hook. In Claude Code: /plugin -> Installed -> %s must say enabled (the "
                          "session-start message there is the authoritative check)" % (p["id"], p["hooks"], p["id"]))
        elif p["enabled"] is False:
            notes.append("the %s plugin is installed but switched off (enabledPlugins false in %s): its hook does not run" % (p["id"], p["enabled_in"]))
    for path, why in st["skipped"]:
        problems.append("%s: hook is NOT running - %s" % (path, why))
    for path, matcher, h in entries:
        pl = plugin_hooks.get(path)
        notes.append("hook taken from %s%s" % (path, " (managed settings)" if is_managed(path) else
                                                (" (plugin %s, enabled in %s)" % (pl["id"], pl["enabled_in"]) if pl else "")))
    key_source = agent_key_source(e)
    if not inside and key_source is None and any(path in plugin_hooks for path, _, _ in entries + [(x["hooks"], 0, 0) for x in plugins if x["enabled"] is None]):
        # the plugin's own script lets a call run (and says so) while it has no key: not fail-closed, but it may have a key we cannot see
        unsure.append("no agent key here (DEUS_WITNESS_KEY is not set and there is no key file): unless agent_key is set in /plugin -> "
                      "deus-witness -> Configure (not visible from a terminal), the plugin lets every call run unwitnessed. Set up: %s" % TRY_CMD)
    for p in st["other_disable"]:
        if any(is_managed(x[0]) for x in entries) and not st["managed_disable"]:
            notes.append("%s: disableAllHooks=true is ignored for the managed hook (only managed settings can disable it)" % p)
    for k, v in senv.items():
        e.setdefault(k, v)                                    # the shell's own env wins, as in Claude Code
    if not entries and not any(p["enabled"] is None for p in plugins):
        problems.append("no PreToolUse hook running deus-witness-hook in %s" % ", ".join(settings_files(project_dir, e)))
    hook_timeout = _num(e.get("DEUS_WITNESS_HOOK_TIMEOUT"), 20.0)
    wait = _num(e.get("DEUS_WITNESS_HOOK_WAIT"), 0.0)
    for path, matcher, h in entries:
        where = "%s%s (matcher %r)" % (path, " [managed]" if is_managed(path) else "", matcher)
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
    if e.get("DEUS_WITNESS_HOOK_ON_DEFER") == "ask":
        notes.append("DEUS_WITNESS_HOOK_ON_DEFER=ask: a held call becomes a yes/no question in the terminal, and `yes` runs it WITHOUT a witness "
                     "receipt - the person at the keyboard approves in the owner's place. The default is deny (the owner approves in Witness)")
    return {"version": ".".join(map(str, ver)) if ver else None, "version_source": how, "problems": problems, "notes": notes,
            "unsure": unsure, "key_source": key_source, "plugin": bool(plugin_hooks)}


BANNER = "DEUS WITNESS: THIS HOOK CAN BE BYPASSED (fail-open)."
UNSURE_BANNER = "DEUS WITNESS: CANNOT TELL FROM HERE whether the hook is fail-closed (see why below)."
TRY_CMD = "uvx --from deus-witness deus-witness try"     # 0.2.40: a uv user has no `deus-witness` on PATH


QUICKSTART_HOOK = "https://witness.sipkigroup.com/dl/docs/quickstart.html#hook"
SETTINGS_EXAMPLE = "https://github.com/sipkigroup/witness/blob/main/python/examples/unattended/settings.unattended.json"


def next_steps(env=None, r=None):
    """What to do after a fail-open report: the missing key (if it is missing) and where the working settings are.
    0.2.40: the key counts when it is in the key file `try` saved too (the hook reads it there), as check() found it (r)."""
    e = os.environ if env is None else env
    out = [""]
    ks = r.get("key_source") if r is not None and "key_source" in r else agent_key_source(e)
    if ks is None:
        out.append("  DEUS_WITNESS_KEY not set -> sign up and create an agent with the claude-code preset: "
                   "https://witness.sipkigroup.com/signup.html")
        out.append("  (no key file either; a trial account in one command: %s)" % TRY_CMD)
    if r is not None and r.get("plugin"):
        out.append("  Plugin install: its hooks.json already has \"onFailure\": \"block\", `|| exit 2` and the timeout; fix the lines above.")
        return out
    out.append("  Next: copy the settings from settings.unattended.json (%s) into <project>/.claude/settings.json" % SETTINGS_EXAMPLE)
    out.append("  Guide (steps 1-3 of the hook section): " + QUICKSTART_HOOK)
    return out


def report_text(r) -> str:
    lines = ["Claude Code: %s (%s)" % (r["version"] or "unknown", r["version_source"])]
    if r["problems"]:
        lines += ["", "!" * 72, "!! " + BANNER, "!" * 72] + ["  - " + p for p in r["problems"]]
        lines += ["  ? " + u for u in r.get("unsure") or []]
        lines += next_steps(r=r)
    elif r.get("unsure"):
        lines += ["", "?" * 72, "?? " + UNSURE_BANNER, "?" * 72] + ["  - " + p for p in r["unsure"]]
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
