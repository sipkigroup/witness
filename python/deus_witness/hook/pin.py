"""r0272 (ISPYTANIE-SOVMESTIMOST-1311, gate 6): what Witness approved is what runs, next to other plugins that rewrite tool calls.

The hole (L3, Claude Code 2.1.323, 13.11): Claude Code runs every matching PreToolUse hook IN PARALLEL, each on the input Claude wrote. A
second hook that returns `updatedInput` (rtk, "Rust Token Killer": `git status` -> `rtk git status`, `cat f` -> `rtk read f`,
`env | grep -i node` -> `env | rtk grep -i node`) changes the call AFTER Witness judged it: Witness answered allow for `echo SIGNED`, the
receipt names `echo SIGNED`, and `echo REWRITTEN` ran. Claude Code merges the decisions (deny > defer > ask > allow) and takes the
`updatedInput` of the hook that FINISHED LAST (`n.updatedInput ?? e.updatedInput` over the results as they come in; docs: "Claude Code
doesn't merge the rewrites or guarantee which rewrite the tool runs with").

Two layers here:
  1. pin   -- a witnessed `allow` always carries `updatedInput` = exactly the tool_input Witness judged (the receipt's arguments). Witness
             answers after a round trip to the server (100+ ms), a local rewriter after a few ms (rtk 1.2.0: ~18 ms), so the pinned input is
             normally the one that runs. Normally, not always: a hook that answers later still wins. Hence 2.
  2. check -- PostToolUse / PostToolUseFailure (they carry the tool_input that RAN): when it is not the pinned input, the person is told
             at once (systemMessage) and Claude is told the receipt does not cover what ran; one line in `rewritten.log` next to the key
             (hashes only, never the arguments). After the fact: it cannot undo the call; it makes the lie visible.

Records: <key dir>/pinned/<sha256(session_id, tool_use_id)>.json, written at the allow, removed by the check; older than a day removed.

r0297 (client 0.2.76): a NEUTRAL allow (no decision: Claude Code's own check still decides, in auto mode its classifier; main.neutral_allow)
consumed its receipts, but the call may still be refused after Witness. Its record (pin_neutral) carries the receipts and no updatedInput
(docs: "With no permissionDecision, auto mode can deny the changed call"). The same check then tells the witness what happened
(POST /v1/actions/{rid}/report, the endpoint the core has for it: the journal says "executed" / "not executed"):
  PostToolUse / PostToolUseFailure with the judged input -> executed (the tool started; a failure is still a run)
  PermissionDenied (auto mode refused the call; docs: "This hook only fires in auto mode", input has tool_use_id) -> NOT executed
  neither within a day (refused at a prompt, interrupted, a plugin without these hooks) -> nothing is claimed either way: one line
    "unconfirmed" in neutral.log next to the key. A "not executed" is said only on Claude Code's own word (PermissionDenied), never by
    guess: the witness takes a not-executed write or read as never run (provenance), so a wrong "not executed" would hide a real one.
Every outcome is one line in neutral.log (rids and hashes, never arguments).
"""
from __future__ import annotations

import hashlib
import json
import os
import time

DIR = "pinned"
LOG = "rewritten.log"
NLOG = "neutral.log"
AFTER_EVENTS = ("PostToolUse", "PostToolUseFailure", "PermissionDenied")
LOG_MAX = 1024 * 1024
KEEP_S = 24 * 3600
SHOW = 160


def _bare(args, cosmetic):
    """The arguments the receipt binds: the cosmetic labels (Bash `description`) are not sent to the witness (main._envelope)."""
    if isinstance(args, dict) and any(isinstance(args.get(k), str) for k in cosmetic):
        return {k: v for k, v in args.items() if not (k in cosmetic and isinstance(v, str))}
    return args


def _canon(tool, args) -> str:
    return hashlib.sha256(json.dumps([tool, args], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _home(env):
    from ..trial import home_dir
    return home_dir(env)


def _name(ev):
    sid, tid = ev.get("session_id"), ev.get("tool_use_id")
    if not isinstance(tid, str) or not tid:
        return None
    return hashlib.sha256(("%s\0%s" % (sid if isinstance(sid, str) else "", tid)).encode("utf-8")).hexdigest() + ".json"


def pin(ev, out, env, orig=None, cosmetic=()) -> dict:
    """A witnessed allow -> the same output with updatedInput = the judged tool_input (unless the hook already set one, e.g. the env mask),
    and a record for the check. Anything else is returned as it is. Never raises."""
    try:
        hs = out.get("hookSpecificOutput") if isinstance(out, dict) else None
        if not isinstance(hs, dict) or hs.get("permissionDecision") != "allow":
            return out
        if orig is None:
            orig = ev.get("tool_input") if isinstance(ev, dict) else None
        if not isinstance(orig, dict):
            return out
        if "updatedInput" not in hs:
            hs["updatedInput"] = json.loads(json.dumps(orig))
        _record(ev, _bare(hs["updatedInput"], cosmetic), env)
    except Exception:      # noqa: BLE001  the pin is extra safety; the decision stands without it
        pass
    return out


def pin_neutral(ev, rids, env, orig=None, cosmetic=()) -> None:
    """r0297: a neutral allow (no decision) -> a record with the consumed receipts, for the check after the call. Never raises."""
    try:
        if orig is None:
            orig = ev.get("tool_input") if isinstance(ev, dict) else None
        if not isinstance(orig, dict) or not rids:
            return
        _record(ev, _bare(orig, cosmetic), env, rids=[str(r) for r in rids][:32])
    except Exception:      # noqa: BLE001  the decision stands without it; the journal then keeps "consumed"
        pass


def _record(ev, pinned, env, rids=None) -> None:
    n = _name(ev)
    if n is None:
        return
    d = os.path.join(_home(env), DIR)
    os.makedirs(d, mode=0o700, exist_ok=True)
    _sweep(d, env)
    tool = ev.get("tool_name")
    rec = {"t": int(time.time()), "tool": tool, "sha": _canon(tool, pinned), "shown": _short(pinned)}
    if rids:
        rec["neutral"] = True
        rec["rids"] = rids
    body = json.dumps(rec)
    p = os.path.join(d, n)
    fd = os.open(p + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(p + ".tmp", p)


def _sweep(d, env=None) -> None:
    now = time.time()
    try:
        for f in os.listdir(d)[:2000]:
            p = os.path.join(d, f)
            try:
                if now - os.path.getmtime(p) > KEEP_S:
                    if env is not None:
                        _unconfirmed(p, env)
                    os.unlink(p)
            except OSError:
                pass
    except OSError:
        pass


def _unconfirmed(p, env) -> None:
    """r0297: a neutral record nobody checked within a day: neither "ran" nor "not run" is known; said as such, locally."""
    try:
        with open(p, encoding="utf-8") as f:
            rec = json.loads(f.read(65536))
        if rec.get("neutral"):
            _nlog(env, rec, "unconfirmed: no PostToolUse and no PermissionDenied within a day", None)
    except (OSError, ValueError):
        pass


def _short(inp) -> str:
    """What the person is shown: the command / path / url of the call, cut. The secret mask of the hook applies (mask.py)."""
    if isinstance(inp, dict):
        for k in ("command", "file_path", "notebook_path", "path", "url", "pattern", "query"):
            if isinstance(inp.get(k), str):
                s = inp[k]
                break
        else:
            s = json.dumps(inp, sort_keys=True, ensure_ascii=False)
    else:
        s = str(inp)
    try:
        from . import mask
        s = mask.mask_value(s, 4096)
    except Exception:      # noqa: BLE001  never shown unmasked
        s = "(not shown)"
    s = " ".join(s.split())
    return s if len(s) <= SHOW else s[:SHOW - 3] + "..."


def check(ev, env, cosmetic=None, report=None) -> dict | None:
    """PostToolUse / PostToolUseFailure / PermissionDenied -> None (nothing to say) or the hook output that tells the person and Claude
    that a call other than the approved one ran. Only calls this hook pinned are checked. r0297: for a neutral record `report(rids,
    executed)` tells the witness whether the call ran (PermissionDenied: not run; the judged input ran: executed). Never raises."""
    try:
        if not isinstance(ev, dict) or ev.get("hook_event_name") not in AFTER_EVENTS:
            return None
        n = _name(ev)
        if n is None:
            return None
        p = os.path.join(_home(env), DIR, n)
        try:
            with open(p, encoding="utf-8") as f:
                rec = json.loads(f.read(65536))
        except (OSError, ValueError):
            return None
        try:
            os.unlink(p)
        except OSError:
            pass
        tool = ev.get("tool_name")
        rids = [r for r in (rec.get("rids") or []) if isinstance(r, str)] if rec.get("neutral") else []
        if ev["hook_event_name"] == "PermissionDenied":
            # Claude Code's own word that the call did not run (auto mode refused it after the witness allowed it)
            if rids:
                _nlog(env, rec, "not run: auto mode denied it", _tell(report, rids, False))
            return None
        ran = _bare(ev.get("tool_input"), (cosmetic or {}).get(tool, ()))
        if rec.get("tool") == tool and rec.get("sha") == _canon(tool, ran):
            if rids:
                _nlog(env, rec, "ran" if ev["hook_event_name"] == "PostToolUse" else "ran (the tool failed)", _tell(report, rids, True))
            return None
        if rids:                                          # something else ran: the receipts do not cover it, "executed" would be a lie too
            _nlog(env, rec, "a different call ran (rewritten by another hook): not reported", None)
        _journal(env, tool, rec.get("sha"), _canon(tool, ran))
        msg = ("DEUS WITNESS: a different call ran than the one you approved. Approved: `%s`. Ran: `%s`. Another hook (a plugin or your "
               "settings, e.g. rtk) rewrote it after Witness decided; the Witness receipt does not cover what ran. Remove or narrow that "
               "hook if you want every run witnessed." % (rec.get("shown", "?"), _short(ran)))
        ctx = ("Deus Witness warning: the tool call that just ran is NOT the one Witness approved (another PreToolUse hook rewrote its input). "
               "Tell the user. Do not describe this call as witnessed.")
        return {"systemMessage": msg, "hookSpecificOutput": {"hookEventName": ev["hook_event_name"], "additionalContext": ctx}}
    except Exception:      # noqa: BLE001
        return None


def _tell(report, rids, executed):
    """-> True (the witness took the report), False (it could not be told), None (no witness to tell). Never raises."""
    if report is None:
        return None
    try:
        report(rids, executed)
        return True
    except Exception:      # noqa: BLE001  the journal keeps "consumed"; the local line says it was not told
        return False


def _nlog(env, rec, outcome, told) -> None:
    _append(env, NLOG, {"t": int(time.time()), "tool": str(rec.get("tool"))[:200], "rids": rec.get("rids"), "sha256": rec.get("sha"),
                        "outcome": outcome, "witness_told": told})


def _append(env, name, obj) -> None:
    try:
        d = _home(env)
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, name)
        try:
            if os.path.getsize(p) > LOG_MAX:
                os.replace(p, p + ".1")
        except OSError:
            pass
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(obj) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:      # noqa: BLE001
        pass


def _journal(env, tool, approved, ran) -> None:
    try:
        d = _home(env)
        os.makedirs(d, mode=0o700, exist_ok=True)
        p = os.path.join(d, LOG)
        try:
            if os.path.getsize(p) > LOG_MAX:
                os.replace(p, p + ".1")
        except OSError:
            pass
        line = json.dumps({"t": int(time.time()), "tool": str(tool)[:200], "approved_sha256": approved, "ran_sha256": ran})
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:      # noqa: BLE001
        pass


REWRITERS = ("rtk hook claude", "rtk-rewrite.sh")


def rewriters(project, home=None) -> list:
    """Session start: other PreToolUse hooks known to rewrite tool calls (settings files of the user and the project). -> their commands."""
    home = home or os.path.expanduser("~")
    found = []
    for f in (os.path.join(home, ".claude", "settings.json"), os.path.join(home, ".claude", "settings.local.json"),
              os.path.join(project or "", ".claude", "settings.json"), os.path.join(project or "", ".claude", "settings.local.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                s = json.loads(fh.read(4 * 1024 * 1024))
        except (OSError, ValueError):
            continue
        for e in ((s.get("hooks") or {}).get("PreToolUse") or []) if isinstance(s, dict) else []:
            for h in (e.get("hooks") or []) if isinstance(e, dict) else []:
                c = h.get("command") if isinstance(h, dict) else None
                if isinstance(c, str) and any(r in c for r in REWRITERS) and c not in found:
                    found.append(c)
    return found


def rewriters_line(project, home=None) -> str | None:
    r = rewriters(project, home)
    if not r:
        return None
    return ("Deus Witness: another hook rewrites your commands (%s). Calls Witness approves run exactly as approved (that hook does not "
            "shorten them); if one ever runs changed, Witness tells you." % r[0][:80])
