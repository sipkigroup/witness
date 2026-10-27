"""deus-witness run [--] claude <args...>   (0.2.41) - run Claude Code and FAIL when the Witness hook did not run in it.

`claude --bare` (and CLAUDE_CODE_SIMPLE=1, which --bare sets) skips the hooks defined in settings and by installed plugins, and Claude
Code's Headless docs say --bare "will become the default for -p in a future release". A Witness hook that is skipped says nothing:
the run goes on, nothing is checked, CI is green. This wrapper makes that a visible failure:

  before the run   refuses (exit 2) the known signs of a run without hooks: `--bare` / `--safe-mode` in the arguments,
                   CLAUDE_CODE_SIMPLE / CLAUDE_CODE_SAFE_MODE in the environment, and print mode (-p / --print) on a Claude Code version
                   that runs -p bare by default (BARE_DEFAULT_FOR_P below, empty today; DEUS_WITNESS_BARE_DEFAULT_FROM=X.Y.Z adds one)
  the run          the command as given, same stdin/stdout/stderr, plus DEUS_WITNESS_RUN_ID (random) and DEUS_WITNESS_RUN_DIR
                   (a fresh private temp directory); Claude Code hands its environment to its hooks
  after the run    the Witness hook (client 0.2.41+: every --session-start and PreToolUse call; plugin script 0.2.41+: every call)
                   leaves an empty file <run id>.<what>.<pid> there. No such file from this run: exit 3 (or Claude Code's own non-zero
                   code) and "Witness hook did not run in this session (bare mode?) - nothing was checked". A plugin that ran without a
                   key ("not set up") or without its client ("blocked") is a failure too.

0.2.41 after red team RT-0.2.41 (server 0.2.63+): the WITNESS counts, not a file. With an agent key (DEUS_WITNESS_KEY or the key file of
`deus-witness try`) `run` first asks the witness for a one-time run nonce (POST /v1/hook/run) and hands it to Claude Code as
DEUS_WITNESS_RUN_NONCE; the hook sends it with its SessionStart call and with every PreToolUse call it has judged; after the run `run`
asks the witness how many of each it saw (GET /v1/hook/run/<nonce>) and counts the tool calls the hook covers in this run's Claude Code
transcript (<config dir>/projects/<project>/<session>.jsonl, lines written during the run):

  witness judged >= 1 call                                  pass (a transcript with more covered calls than judged ones: a warning)
  session start seen, 0 judged, transcript shows tool calls  FAIL: the PreToolUse hook did not run (F2)
  session start seen, 0 judged, no transcript found          pass, or FAIL with --expect-tools
  nothing seen, the transcript shows no tool call           pass with a warning: nothing ran unwitnessed, but the hook was not shown
                                                            to be on (a PreToolUse-only hook is silent when no tool runs; F3)
  nothing seen otherwise                                    FAIL
Without a key (or a witness older than 0.2.63) the same table runs on the local mark files, and the text says that such a mark can be
written by any process of the run (the run id and directory are in the environment of the whole process tree).

What it proves: the witness judged N calls / saw a session start carrying this run's nonce, with this agent's key. A process of the run
that holds the key and the nonce can still send such calls itself (they are then judged and journaled like any other), and it cannot
make the run's own tool calls disappear from the transcript count. A local mark proves less: only that some process of the run wrote it.
Exit codes: Claude Code's own code when the run passed; 2 refused before the run; 3 not witnessed (Claude Code exited 0);
127 the command was not found."""
from __future__ import annotations

import os
import json
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ENV_ID = "DEUS_WITNESS_RUN_ID"
ENV_DIR = "DEUS_WITNESS_RUN_DIR"
ENV_BARE_FROM = "DEUS_WITNESS_BARE_DEFAULT_FROM"
ENV_NONCE = "DEUS_WITNESS_RUN_NONCE"          # RT-0.2.41: the witness' one-time nonce of this run (server 0.2.63+)
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{43}")
# the tools the plugin's PreToolUse matcher covers (release/out/open-repo/plugins/deus-witness/hooks/hooks.json): only these are expected
# to be judged; TodoWrite, Task and the like run without the hook by design
COVERED = re.compile(r"(Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|Read|Grep|Glob|LS|WebFetch|WebSearch|"
                     r"ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*)")
RID_RE = re.compile(r"[0-9a-f]{32}")
# Claude Code versions from which `claude -p` runs bare by default: (X, Y, Z) = that release and later. Empty: no release does yet
# (checked 26.10.2026 on 2.1.311 and code.claude.com/docs/en/headless). Add the release when it ships.
BARE_DEFAULT_FOR_P: tuple = ()
BARE_ARGS = {"--bare": "--bare skips the hooks defined in settings and by installed plugins (claude --help)",
             "--safe-mode": "--safe-mode starts with hooks and installed plugins disabled (claude --help)"}
BARE_ENVS = {"CLAUDE_CODE_SIMPLE": "CLAUDE_CODE_SIMPLE is what --bare sets: it skips the hooks of settings and plugins",
             "CLAUDE_CODE_SAFE_MODE": "CLAUDE_CODE_SAFE_MODE is what --safe-mode sets: hooks and installed plugins are disabled"}
PRINT_FLAGS = ("-p", "--print")
NOT_RAN = "Witness hook did not run in this session (bare mode?) - nothing was checked"
RC_REFUSED, RC_NOT_WITNESSED, RC_NOT_FOUND = 2, 3, 127
USAGE = ("usage: deus-witness run [--expect-tools] [--] claude <args...>   (e.g. uvx --from deus-witness deus-witness run -- claude -p \"...\")\n"
         "  --expect-tools   fail when no tool call was judged and the transcript could not be read")


def _on(v) -> bool:
    return v is not None and str(v).strip().lower() not in ("", "0", "false", "no", "off")


def mark(what: str, env=None) -> bool:
    """Called by the hook (hook/main.py): an empty file <run id>.<what>.<pid> in DEUS_WITNESS_RUN_DIR when `deus-witness run` started
    this Claude Code. Writes only into an existing absolute directory (not a symlink) with a well-formed run id. Never raises."""
    e = os.environ if env is None else env
    rid, d = str(e.get(ENV_ID) or ""), str(e.get(ENV_DIR) or "")
    if not RID_RE.fullmatch(rid) or not re.fullmatch(r"[a-z-]{1,40}", what or "") or not os.path.isabs(d):
        return False
    try:
        if not stat.S_ISDIR(os.lstat(d).st_mode):
            return False
        fd = os.open(os.path.join(d, "%s.client-%s.%d" % (rid, what, os.getpid())), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        return True
    except OSError:
        return False


def seen(d: str, rid: str) -> dict:
    """-> {what: count} of this run's marks."""
    out = {}
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        parts = n.split(".")
        if len(parts) == 3 and parts[0] == rid:
            out[parts[1]] = out.get(parts[1], 0) + 1
    return out


FORGEABLE = "local mark only: any process of this run can write it, the witness was not asked"
PRETOOL_ONLY = ("If the hook is installed for PreToolUse only (settings.json without a SessionStart hook) and this run made no tool call, "
                "this is expected: add the SessionStart hook (`deus-witness-hook --session-start`) or use the Claude Code plugin, which has both")


def _plugin_failure(marks: dict):
    if any(k.endswith("-blocked") for k in marks):
        return ("the Witness plugin ran but its client is missing: every matched tool call was BLOCKED and nothing was witnessed. "
                "Install uv (https://docs.astral.sh/uv/) on this machine")
    if any(k.endswith("-unset") for k in marks):
        return ("the Witness plugin ran but is NOT set up (no agent key): nothing was checked. Set DEUS_WITNESS_KEY "
                "(the agent key) in this environment")
    return None


def decide(starts: int, judged: int, tools, expect_tools: bool = False, source: str = "witness", plugin_fail=None):
    """-> (state, message); state: "ok" | "warn" (both keep Claude Code's code) | "fail". RT-0.2.41 F2/F3.
    starts / judged: SessionStart calls and judged PreToolUse calls of this run, as the witness counted them (source "witness") or as
    local marks (source "local"); tools: covered tool calls in this run's transcript, None when no transcript was found."""
    by = "the witness" if source == "witness" else "local marks, which any process of the run can write"
    seen_t = "" if tools is None else ", covered tool calls in the transcript: %d" % tools
    if starts == 0 and judged == 0:
        if plugin_fail:
            return "fail", plugin_fail
        if tools == 0:
            return "warn", ("deus-witness run: this run made no tool call the hook covers, so nothing ran unwitnessed; but no Witness hook "
                            "call was seen (%s), so it was NOT shown that the hook is on. %s." % (by, PRETOOL_ONLY))
        return "fail", (NOT_RAN + " (%s saw no hook call%s). Claude Code started no Witness hook in this run: `--bare`, CLAUDE_CODE_SIMPLE, "
                        "a Claude Code that runs -p bare by default, disableAllHooks, --setting-sources without the file that has the hook, "
                        "or no hook installed. (A hook from a Deus Witness client older than 0.2.41 leaves no trace either: use "
                        "deus-witness>=0.2.41.) %s." % (by, seen_t, PRETOOL_ONLY))
    if judged == 0:
        if tools:
            return "fail", ("Witness hook ran at session start, but NONE of the %d tool call(s) of this run went through it (%s): the "
                            "PreToolUse hook did not run (removed, not registered, or its matcher does not cover these tools) - nothing "
                            "was checked" % (tools, by))
        if tools is None and expect_tools:
            return "fail", ("Witness hook ran at session start, but no tool call went through it (%s), and --expect-tools was given "
                            "(the transcript of this run was not found, so whether tools ran is unknown)" % by)
        why = "no tool call in the transcript" if tools == 0 else \
            "the transcript was not found, so tool calls were not counted; --expect-tools makes this a failure"
        return "ok", "deus-witness run: the Witness hook ran in this run at session start (seen by %s: %d), no tool call went through it (%s)" % (by, starts, why)
    msg = "deus-witness run: the Witness hook ran in this run (seen by %s: session start %d, %s %d%s)" % (
        by, starts, "tool calls judged" if source == "witness" else "hook calls on tools", judged, seen_t)
    if tools is not None and tools > judged:
        return "warn", msg + (". WARNING: %d covered tool call(s) in the transcript were not judged - a call the hook refused before "
                              "asking the witness, or a tool call without the hook; see the journal" % (tools - judged))
    return "ok", msg


def counts(marks: dict):
    """local marks -> (starts, judged)."""
    starts = sum(v for k, v in marks.items() if k in ("client-session-start", "plugin-session-start-on"))
    judged = sum(v for k, v in marks.items() if k in ("client-pretool", "plugin-pretool-on"))
    return starts, judged


def verdict(marks: dict, tools=None, expect_tools=False):
    """local marks -> (witnessed, message). 0.2.41 kept for callers; RT-0.2.41: a session-start mark alone with tool calls is a failure."""
    st, msg = decide(*counts(marks), tools, expect_tools, "local", _plugin_failure(marks))
    return st != "fail", msg


# ---------------------------------------------------------------- RT-0.2.41: the transcript of this run
def _sanitize(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def _config_dirs(env: dict) -> list:
    from . import _compat
    out = []
    c = env.get("CLAUDE_CONFIG_DIR")
    if isinstance(c, str) and os.path.isabs(c):
        out.append(c)
    h = os.path.join(_compat.home(env), ".claude")
    if h not in out:
        out.append(h)
    return out


def _ts(v):
    import datetime
    try:
        return datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


MAX_TRANSCRIPT = 256 * 1024 * 1024


def transcripts(env: dict, cwd: str, sessions, t0: float) -> list:
    """This run's Claude Code transcripts: <config dir>/projects/*/<session>.jsonl of the sessions the witness saw, plus every transcript
    of this project (projects/<cwd with non-alphanumerics as ->/) written to since the run began (a session that called no hook)."""
    import glob
    found = []
    sids = [x for x in (sessions or ()) if isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", x)]
    for cfg in _config_dirs(env):
        proj = os.path.join(cfg, "projects")
        for sid in sids:
            found += glob.glob(os.path.join(glob.escape(proj), "*", glob.escape(sid) + ".jsonl"))
        for c in {cwd, os.path.realpath(cwd)}:
            d = os.path.join(proj, _sanitize(c))
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                f = os.path.join(d, n)
                try:
                    if n.endswith(".jsonl") and os.stat(f).st_mtime >= t0 - 1:
                        found.append(f)
                except OSError:
                    pass
    out = []
    for f in found:
        f = os.path.realpath(f)
        if f not in out:
            out.append(f)
    return out


def tool_calls(files, t0: float):
    """-> number of covered tool calls (distinct tool_use ids, by COVERED name) in assistant lines written at or after t0; None: no file."""
    if not files:
        return None
    ids, n = set(), 0
    for f in files:
        try:
            with open(f, "rb") as fh:
                for raw in fh:
                    n += len(raw)
                    if n > MAX_TRANSCRIPT:
                        break
                    if b'"tool_use"' not in raw:
                        continue
                    try:
                        d = json.loads(raw)
                    except ValueError:
                        continue
                    if not isinstance(d, dict) or d.get("type") != "assistant":
                        continue
                    t = _ts(d.get("timestamp"))
                    if t is not None and t < t0 - 1:
                        continue
                    c = (d.get("message") or {}).get("content") if isinstance(d.get("message"), dict) else None
                    for x in c if isinstance(c, list) else ():
                        if isinstance(x, dict) and x.get("type") == "tool_use" and isinstance(x.get("name"), str) \
                                and COVERED.fullmatch(x["name"]):
                            ids.add(str(x.get("id") or "%s:%d" % (f, len(ids))))
        except OSError:
            continue
    return len(ids)


# ---------------------------------------------------------------- RT-0.2.41 F1: the witness counts
def witness_client(env: dict):
    """-> (Witness, None) when this machine has an agent key and a witness the hook would send to; (None, why) otherwise. No network."""
    from .client import Witness
    from .hook.main import Settings
    s = Settings(env)
    if not s.key:
        return None, "no agent key here (DEUS_WITNESS_KEY or `deus-witness try`)"
    if s.url_conflict:
        return None, "DEUS_WITNESS_URL differs from the witness of the key file"
    w = Witness(s.url, s.key, verify=False, timeout=15.0, pin_new=False)
    pins = w._read_pins()
    if pins and w.url not in pins and w.url != s.file_url:
        w.close()
        return None, "%s is not the witness this machine trusts" % w.url
    return w, None


def _version(exe: str, env: dict):
    from .hook import failsafe
    e = dict(env)
    e["CLAUDE_CODE_EXECPATH"] = exe
    e.pop("CLAUDE_CODE_VERSION", None)
    v, _ = failsafe.claude_version(e)
    return v


def _bare_from(env: dict) -> list:
    out = list(BARE_DEFAULT_FOR_P)
    s = env.get(ENV_BARE_FROM)
    if s:
        m = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", s)
        if m:
            out.append(tuple(int(x) for x in m.groups()))
    return out


def refusals(cmd: list, env: dict, version_of=None) -> list:
    """Known signs that this run starts no hook. -> [reason]."""
    why = []
    args = cmd[1:]
    for a in args:
        # RT-0.2.41 F4: `--bare=1`, `--Bare`, `--safe-mode=true` too (claude --help 2.1.311 has no short form of either, and no prefix
        # abbreviations: only the full names, any case, with or without =value)
        k = a.split("=", 1)[0].lower() if isinstance(a, str) and a.startswith("--") else None
        if k in BARE_ARGS and BARE_ARGS[k] not in why:
            why.append(BARE_ARGS[k] + ("" if a == k else " (given as %s)" % a))
    for name, v in env.items():
        # the variable names in any case (Windows environments are case-insensitive)
        t = BARE_ENVS.get(str(name).upper())
        if t is not None and _on(v):
            why.append("%s=%s in the environment: %s" % (name, v, t))
    froms = _bare_from(env)
    if froms and any(a in PRINT_FLAGS for a in args):
        v = (version_of or _version)(cmd[0], env)
        if v is not None and any(v >= f for f in froms):
            why.append("Claude Code %s runs `-p` bare by default (from %s): its hooks are skipped" % (
                ".".join(map(str, v)), ".".join(map(str, min(f for f in froms if v >= f)))))
    return why


def _clean(d: str) -> None:
    """The run directory holds only flat mark files; remove them and it (a symlink is unlinked, never followed)."""
    try:
        for n in os.listdir(d):
            try:
                os.unlink(os.path.join(d, n))
            except OSError:
                pass
        os.rmdir(d)
    except OSError:
        pass


def run(argv=None, env=None, out=None, witness=None, popen=None, cwd=None) -> int:
    """witness: a factory env -> (client, why) (tests); popen: subprocess.Popen (tests); cwd: the project directory (default: current)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    e = dict(os.environ if env is None else env)
    err = out or sys.stderr
    expect_tools = False
    while argv[:1] == ["--expect-tools"]:
        expect_tools, argv = True, argv[1:]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE + "\n\n" + __doc__, file=err if not argv else sys.stdout)
        return RC_REFUSED if not argv else 0
    why = refusals(argv, e)
    if why:
        print("deus-witness run: REFUSED - this Claude Code run would start without the Witness hook, so nothing would be checked:", file=err)
        for w in why:
            print("  - " + w, file=err)
        print("  Remove it and run again (managed policy hooks under --bare are not documented; do not rely on them).", file=err)
        return RC_REFUSED
    exe = argv[0]
    if os.sep not in exe and not shutil.which(exe, path=e.get("PATH")):
        print("deus-witness run: %s: command not found" % exe, file=err)
        return RC_NOT_FOUND
    cwd = cwd or os.getcwd()
    # RT-0.2.41 F1: the witness' nonce of this run first (the local mark below stays the fallback without a key or an older witness)
    w, nonce, fallback = None, None, None
    try:
        w, fallback = (witness or witness_client)(e)
    except Exception as x:      # noqa: BLE001
        w, fallback = None, "cannot set up the witness client (%s)" % type(x).__name__
    if w is not None:
        try:
            j = w.run_new()
            nonce = j.get("run") if isinstance(j, dict) else None
            if not (isinstance(nonce, str) and NONCE_RE.fullmatch(nonce)):
                nonce, fallback = None, "the witness gave no run nonce"
        except Exception as x:      # noqa: BLE001
            st = getattr(x, "status", None)
            fallback = ("the witness is older than 0.2.63 (no run check)" if st in (404, 405) else
                        "the witness did not give a run nonce (%s)" % (getattr(x, "code", None) or type(x).__name__))
    if nonce is None:
        e.pop(ENV_NONCE, None)
        print("deus-witness run: %s - %s." % (fallback, FORGEABLE), file=err)
    else:
        e[ENV_NONCE] = nonce
    rid = secrets.token_hex(16)
    d = tempfile.mkdtemp(prefix="deus-witness-run-")
    e[ENV_ID], e[ENV_DIR] = rid, d
    t0 = time.time()
    try:
        try:
            p = (popen or subprocess.Popen)(argv, env=e)
        except OSError as x:
            print("deus-witness run: cannot start %s (%s)" % (exe, type(x).__name__), file=err)
            return RC_NOT_FOUND
        while True:
            try:
                rc = p.wait()
                break
            except KeyboardInterrupt:       # Claude Code got the same Ctrl-C from the terminal; wait for it to finish
                continue
        marks = seen(d, rid)
        sessions = []
        if nonce is not None:
            try:
                v = w.run_view(nonce)
                starts, judged = int(v.get("starts") or 0), int(v.get("judged") or 0)
                sessions = v.get("sessions") if isinstance(v.get("sessions"), list) else []
                source = "witness"
            except Exception as x:      # noqa: BLE001  the nonce was given: an unanswered count is not a pass
                msg = ("deus-witness run: cannot ask the witness what it saw in this run (%s): NOT confirmed"
                       % (getattr(x, "code", None) or type(x).__name__))
                print("\n".join(["!" * 72, "!! " + msg, "!" * 72]), file=err)
                return rc if rc else RC_NOT_WITNESSED
        else:
            (starts, judged), source = counts(marks), "local"
        tools = tool_calls(transcripts(e, cwd, sessions, t0), t0)
        state, msg = decide(starts, judged, tools, expect_tools, source, _plugin_failure(marks))
        if state == "ok":
            print(msg, file=err)
            return rc
        if state == "warn":
            print("\n".join(["-" * 72, msg, "-" * 72]), file=err)
            return rc
        bar = "!" * 72
        print("\n".join([bar, "!! deus-witness run: " + msg, bar]), file=err)
        return rc if rc else RC_NOT_WITNESSED
    finally:
        _clean(d)
        if w is not None:
            try:
                w.close()
            except Exception:      # noqa: BLE001
                pass


def main(argv=None) -> None:
    sys.exit(run(argv))
