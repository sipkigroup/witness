"""deus-witness-hook: Claude Code PreToolUse hook. Every matched tool call goes through the witness before it runs.

  stdin   the PreToolUse event (JSON: tool_name, tool_input, cwd, ...)
  stdout  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": allow|deny|ask, "permissionDecisionReason": ...}}
  exit    0 always when a decision was printed; 2 (= Claude Code blocks the call) if even that failed

Fail-closed, three layers (see failsafe.py): the hook answers `deny` on every error it can catch; settings.json runs it as
`deus-witness-hook || exit 2` (a missing or broken install = exit 2 = block); and the entry carries `"onFailure": "block"`
(Claude Code 2.1.295+: a timeout, crash or bad output of the hook blocks the call). `--doctor` / the SessionStart hook
(`--session-start`) warn loudly when a layer is missing or Claude Code is too old to honour it.

Witness verdict -> Claude Code decision
  allow (receipt verified, consumed in the ledger)  -> allow   (0.2.10: also OK_ALLOWANCE, an owner-signed project allowance)
  pass  (class pass: not witnessed)                 -> no decision: Claude Code's own permission rules apply
  defer (owner approval pending)                    -> ask (default) | deny | defer   (DEUS_WITNESS_HOOK_ON_DEFER)
  deny / refused / expired / any error / timeout    -> deny with the reason

Env: DEUS_WITNESS_KEY (required), DEUS_WITNESS_URL, DEUS_WITNESS_HOME (key pin dir),
     DEUS_WITNESS_HOOK_TIMEOUT  seconds for the whole decision, default 20, at most 900 (keep it at least 5 s BELOW the hook
                                `timeout` in settings.json: a hook that Claude Code cancels for time gives no decision),
     DEUS_WITNESS_HOOK_WAIT     seconds to wait for the owner on defer before answering, default 0, cut to TIMEOUT - 5
                                (to wait the whole approval window: WAIT 600, TIMEOUT 610, settings `timeout` 620),
     DEUS_WITNESS_HOOK_ON_DEFER ask | deny | defer, default ask (defer: print mode / Agent SDK only - interactive Claude Code
                                ignores it),
     DEUS_WITNESS_HOOK_ALLOW    allow | neutral, default allow (neutral: a witnessed allow still goes through Claude Code's prompts),
     DEUS_WITNESS_VERIFY=0      do not check receipts (not recommended).
The log (stderr) carries the tool, rid and verdict only - never arguments.

0.2.16 (thin client): the hook does not classify anything. It sends the event as Claude Code gave it (tool name, tool_input as is, cwd),
CLAUDE_PROJECT_DIR / HOME, and the file-system facts the witness asks for (realpath / isdir / exists of the paths it names, and SHA-256
fingerprints of project files by a list the witness signs) to POST /v1/hook/judge; the witness classifies, decides through the core and
answers with the receipts. The hook checks every receipt against the pinned witness key and that each judged call is its own tool_input,
consumes them, and answers Claude Code. No answer, a bad signature or anything unexpected: deny (fail-closed, as before).
0.2.17 (R9-01): every call carries a fresh random nonce; the witness signs a statement of its answer (the nonce, the hash of the exact request,
the full list of parts, and per judged part its args_sha256, rid and verdict). The hook uses an answer only when that statement verifies
against the pinned key and matches the call; a part list that was cut, reordered or replayed from another call is a deny.
(R9-05) The hook answers file-system questions only about paths of this call: inside the project, the session's directories and their
parents, and paths built from the words of the tool_input; any other question is a deny.

  deus-witness-hook --print-form PROJECT_DIR    the recommended mandate form (default rules) as JSON; paste it into the Mandate page
                                                ("Import from JSON"), which shows what will be signed. The default form has
                                                delete.allow_irreversible = true: that is what lets Write / Edit and shell
                                                redirections work INSIDE the project and the temp dir (the witness judges a write as an
                                                irreversible delete of its path). Add --no-irreversible for a read-only mandate: then
                                                every Write / Edit is refused.
  deus-witness-hook --doctor [PROJECT_DIR]      is the hook fail-closed here? (Claude Code version, settings.json); exit 1 if not
  deus-witness-hook --session-start             for a SessionStart hook: a loud warning when the hook can be bypassed
"""
from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import secrets
import sys
import threading
import time

from .. import __version__, _compat
from . import failsafe, fingerprint
from ..client import AARError, ActionResult, Witness, WitnessError, WitnessKeyChanged, args_sha256, request_sha256
from .form import default_form
from .messages import LOCAL

MAX_EVENT = 16 * 1024 * 1024
VERSION = __version__
RESERVED = "_witness"
ENV_KEYS = ("CLAUDE_PROJECT_DIR", "HOME", "DEUS_WITNESS_EXEC_SCAN")
MAX_ROUNDS = 8                 # fact rounds per call; the witness asks what its classifier needs (usually one round, two with a project scan)
MAX_ASKED = 4096               # paths answered per round
CLIENT = {"name": "deus-witness-hook", "version": VERSION}
HINTS = {k: v[1] for k, v in LOCAL.items() if v[0] == "deny"}


class Fail(Exception):
    """-> deny(code, detail)"""

    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def log(msg: str) -> None:
    try:
        sys.stderr.write("[deus-witness-hook] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


def _changed(res) -> str:
    """0.2.13: the files that made the command a question, as the witness recorded them in the action."""
    ch = (res.action or {}).get("exec_changed") if isinstance(res.action, dict) else None
    if not isinstance(ch, list) or not ch:
        return ""
    names = [str(x) for x in ch[:5]]
    return " [changed: %s%s]" % (", ".join(names), " ..." if len(ch) > 5 else "")


def decision(kind: str | None, reason: str = "") -> dict:
    if kind is None:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}}


def deny(code: str, rid: str | None = None, detail: str = "", texts: dict | None = None) -> dict:
    """texts: {code: [kind, text]} from the witness' answer; the hook's own codes are in messages.LOCAL."""
    t = (texts or {}).get(code)
    hint = t[1] if isinstance(t, (list, tuple)) and len(t) == 2 and t[0] == "deny" and isinstance(t[1], str) else HINTS.get(code)
    text = "Blocked by Deus Witness: %s (receipt %s)" % (code, rid or "none")
    if detail:
        text += " %s" % detail
    if hint:
        text += ". " + hint
    return decision("deny", text + ". Do not try to reach the same effect another way.")


class Settings:
    def __init__(self, env=None):
        e = os.environ if env is None else env
        self.env = e
        self.timeout = _num(e.get("DEUS_WITNESS_HOOK_TIMEOUT"), 20.0, 1.0, 900.0)
        # the answer must be printed before our own deadline: a wait that eats the whole timeout ends as WITNESS_TIMEOUT
        self.wait = min(_num(e.get("DEUS_WITNESS_HOOK_WAIT"), 0.0, 0.0, 900.0), max(0.0, self.timeout - failsafe.MARGIN_S))
        self.on_defer = e.get("DEUS_WITNESS_HOOK_ON_DEFER", "ask") if e.get("DEUS_WITNESS_HOOK_ON_DEFER", "ask") in ("ask", "deny", "defer") else "deny"
        self.allow = "neutral" if e.get("DEUS_WITNESS_HOOK_ALLOW") == "neutral" else "allow"
        self.verify = e.get("DEUS_WITNESS_VERIFY") != "0"
        self.key = e.get("DEUS_WITNESS_KEY")
        self.url = e.get("DEUS_WITNESS_URL")


def _num(v, default, lo, hi):
    try:
        return max(lo, min(float(v), hi)) if v not in (None, "") else default
    except ValueError:
        return default


# ---------------------------------------------------------------- raw facts
def _envelope(ev):
    """The shape every event must have before anything is sent (the witness checks everything else)."""
    if not isinstance(ev, dict):
        raise Fail("EVENT_MALFORMED")
    tool, inp = ev.get("tool_name"), ev.get("tool_input")
    inp = {} if inp is None else inp
    if not isinstance(tool, str) or not tool or len(tool) > 200 or not isinstance(inp, dict):
        raise Fail("EVENT_MALFORMED")
    if RESERVED in inp:
        raise Fail("RESERVED_KEY")
    return tool, json.loads(json.dumps(inp))          # a plain JSON copy: exactly what is sent and compared with the judged call


def _realpath(p):
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return None                                   # the witness treats it as the error os.path.realpath raised here


# R9-05: the words of a call (split at blanks, shell operators, quotes, `=` and `/`): a path asked about outside the project must be made of them
_WORD_SPLIT = re.compile(r"""[\s;|&<>()`'"=,:{}\[\]$*?!#\\/]+""")
_PATH_FIELDS = ("command", "file_path", "notebook_path", "path", "glob", "url")
_UNQUOTE = re.compile(r"""['"\\]""")
_VAR = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
# names the classifier adds by itself (npx: <a parent of cwd>/node_modules/.bin/<tool>), and where bash puts a process substitution
# `<(...)` (/dev/fd/63: says nothing about this machine)
_DERIVED = {"node_modules", ".bin", ".", ".."}
_CLASSIFIER_DIRS = ("/dev/fd",)


def _strings(x, out):
    if isinstance(x, str):
        out.append(x)
    elif isinstance(x, dict):
        for k, v in x.items():
            _strings(k, out)
            _strings(v, out)
    elif isinstance(x, list):
        for v in x:
            _strings(v, out)
    return out


# 0.2.21: paths of this platform. POSIX: exactly as before. Windows: drive paths, both separators, case-insensitive compare.
# `windows` is a parameter only so that tests can run the Windows rules on any OS.
def _flavour(windows):
    return ntpath if (_compat.IS_WINDOWS if windows is None else windows) else posixpath


def _norm(p, windows=None):
    f = _flavour(windows)
    n = f.normpath(p)
    return f.normcase(n).replace("\\", "/") if f is ntpath else n


def _under(p, base, windows=None):
    if _flavour(windows) is ntpath:
        p, base = _norm(p, True), _norm(base, True)
    return p == base or p.startswith(base.rstrip("/") + "/")


def _rest(q, b, windows=None):
    """The path components of `q` below `b`, or None when q is not under b. Windows: both separators, case-insensitive, case kept in the result."""
    if _flavour(windows) is ntpath:
        qq, bb = ntpath.normpath(q).replace("\\", "/"), ntpath.normpath(b).replace("\\", "/").rstrip("/")
        if qq.lower() == bb.lower():
            return []
        if qq.lower().startswith(bb.lower() + "/"):
            return [c for c in qq[len(bb) + 1:].split("/") if c]
        return None
    if not _under(q, b, False):
        return None
    return [c for c in q[len(b):].split("/") if c]


def _is_abs(p, windows=None):
    return _compat.is_abs_path(p, windows)


class Facts:
    def __init__(self, ev, env):
        self.proc_cwd = os.getcwd()
        self.home = _compat.home()
        self.env = {k: env[k] for k in ENV_KEYS if isinstance(env.get(k), str)}
        self.fs = {"realpath": {}, "isdir": {}, "exists": {}}
        self.exec = "off" if self.env.get("DEUS_WITNESS_EXEC_SCAN") == "0" else None
        self.nonce = secrets.token_urlsafe(24)        # R9-01: 192 bits, fresh for every call (and for a re-judge)
        cwd = ev.get("cwd") if isinstance(ev.get("cwd"), str) and _is_abs(ev.get("cwd")) else self.proc_cwd
        p = self.env.get("CLAUDE_PROJECT_DIR")
        self.root = _realpath(p if isinstance(p, str) and _is_abs(p) else cwd)    # the only directory the hook ever fingerprints
        for x in (cwd, p if isinstance(p, str) and _is_abs(p) else None, self.env.get("HOME") or self.home):
            if x:                                     # asked for every event: sent at once
                self.fs["realpath"][x] = _realpath(x)
        # R9-05: what this call may be asked about
        self.bases = {b for b in (cwd, self.proc_cwd, p if isinstance(p, str) and _is_abs(p) else None, self.home,
                                  self.env.get("HOME"), self.root) if isinstance(b, str) and _is_abs(b)}
        self.bases |= {v for v in self.fs["realpath"].values() if isinstance(v, str)}
        self.words = set()
        inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
        # only the fields that name paths (not the text of a Write or an Edit: words of a file's content name nothing to look up)
        for t in _strings([inp.get(k) for k in _PATH_FIELDS], []):
            # as written, and with quotes / backslashes / $VAR / ${VAR} taken out (bash joins `"${HOME}/a"1` into one word `<home>/a1`)
            for v in (t, _UNQUOTE.sub("", t), _UNQUOTE.sub("", _VAR.sub("", t))):
                self.words.update(w for w in _WORD_SPLIT.split(v) if w)

    def related(self, p, windows=None) -> bool:
        """R9-05: is `p` a path of THIS call? Inside the project root; a session directory or one of its parents; or one of those plus
        names that all occur as words of the tool_input (or that the classifier derives itself, `_DERIVED`)."""
        if not isinstance(p, str) or not _is_abs(p, windows):
            return False
        f = _flavour(windows)
        nt = f is ntpath
        n = f.normpath(p)
        if (self.root and _under(n, self.root, windows)) or any(_under(n, d, windows) for d in _CLASSIFIER_DIRS):
            return True
        for b in self.bases:
            if _under(b, n, windows):                 # a parent of a session directory (the classifier walks up from cwd)
                return True
        prefixes = {f.splitdrive(b)[0] + "\\" for b in self.bases} if nt else {"/"}
        for b in list(self.bases):                    # a session directory or a parent of one (npx looks upwards from cwd)
            while b not in prefixes:
                prefixes.add(b)
                nb = f.dirname(b)
                if nb == b:
                    break
                b = nb
        for b in prefixes:
            for q in (p, n):
                rest = _rest(q, b, windows)
                if rest is not None and all(c in _DERIVED or all(x in self.words for x in _WORD_SPLIT.split(c) if x) for c in rest):
                    return True                       # (a quoted word may hold blanks: `eval 'cd /etc'` asks about "<cwd>/cd /etc")
        return False

    def prescan(self, w, tool_name):
        """With a cached list that names this tool: walk the project root now, so the witness need not ask (one round less). Never a
        network call, never another directory than the hook's own root."""
        if self.exec is not None or self.root is None:
            return
        try:
            lst = w.scan_list(cached_only=True) if hasattr(w, "scan_list") else None
        except Exception:      # noqa: BLE001  a bad cache: the witness asks, as without one
            lst = None
        if isinstance(lst, dict) and tool_name in (lst.get("prescan_tools") or ()):
            spec = fingerprint.Spec(lst)
            rep = fingerprint.scan(self.root, spec)
            self.exec = dict(rep, rev=spec.rev) if rep is not None else {"root": self.root, "rev": spec.rev, "none": True}

    def body(self, ev, part=None):
        return {"v": 1, "event": {k: ev.get(k) for k in ("tool_name", "tool_input", "cwd") if k in ev},
                "facts": {"home": self.home, "proc_cwd": self.proc_cwd, "env": self.env, "fs": self.fs, "exec": self.exec},
                "client": CLIENT, "part": part, "nonce": self.nonce}

    def answer(self, need, w):
        n = 0
        kinds = (("realpath", _realpath), ("isdir", os.path.isdir), ("exists", os.path.exists))
        for kind, _fn in kinds:                       # the whole question is checked before anything is looked at
            asked = need.get(kind) or []
            if not isinstance(asked, list):
                raise Fail("HOOK_ERROR", "(bad witness answer)")
            for p in asked:
                n += 1
                if not isinstance(p, str) or len(p) > 4096 or n > MAX_ASKED:
                    raise Fail("EVENT_TOO_LARGE")
        if not all(self.related(p) for kind, _fn in kinds for p in need.get(kind) or []):
            raise Fail("HOOK_ERROR", "(the witness asked about a path unrelated to this call)")   # R9-05: nothing about the rest of the machine
        for kind, fn in kinds:
            for p in need.get(kind) or []:
                v = fn(p)
                self.fs[kind][p] = v
                if kind == "realpath" and isinstance(v, str):
                    self.bases.add(v)                 # the classifier goes on from where a link of the call points
        if "scan" in need:
            if need["scan"] != self.root or self.root is None:
                raise Fail("HOOK_ERROR", "(the witness asked for another directory)")
            spec = fingerprint.Spec(w.scan_list(need.get("scan_rev")))
            rep = fingerprint.scan(self.root, spec)
            self.exec = dict(rep, rev=spec.rev) if rep is not None else {"root": self.root, "rev": spec.rev, "none": True}


class Part:
    def __init__(self, d, inp, tool_name):
        if not isinstance(d, dict) or not isinstance(d.get("tool"), str) or not isinstance(d.get("args"), dict) or not isinstance(d.get("result"), dict):
            raise Fail("HOOK_ERROR", "(bad witness answer)")
        self.i, self.tool, self.args = d.get("i"), d["tool"], d["args"]
        self.summary = str(d.get("summary") or self.tool)
        self.why = d.get("why") if isinstance(d.get("why"), str) else ""
        # the judged call must be THIS call: exactly the tool_input Claude Code gave, plus the witness' own `_witness`; a receipt for
        # anything else is not used (and its args_sha256 binds the receipt to these args)
        if {k: v for k, v in self.args.items() if k != RESERVED} != inp:
            raise Fail("REQUEST_MISMATCH")
        self.res = ActionResult.from_json(d["result"])


def _ask(w, ev, facts, part=None):
    """One judged answer, after as many fact rounds as the witness needs. -> (answer, the body that got it)."""
    for _ in range(MAX_ROUNDS):
        body = facts.body(ev, part)
        r = w.hook_judge(body)
        if not isinstance(r, dict) or r.get("v") != 1:
            raise Fail("HOOK_ERROR", "(bad witness answer)")
        if isinstance(r.get("need"), dict):
            facts.answer(dict(r["need"], scan_rev=r.get("scan_rev")), w)
            continue
        return r, body
    raise Fail("HOOK_ERROR", "(the witness kept asking for facts)")


def _bound(w, r, body, part, parts, inp, tool_name, verify, tools=None):
    """0.2.17 (R9-01): the parts of answer `r` as [Part], after checking the witness' signed statement: it is for THIS request (nonce, hash of
    the exact body), it lists every part of the call, and the parts in `r` are exactly the judged ones (index, tool, args_sha256, rid,
    verdict, status, reason), none missing: either all parts were judged or the last judged one refused the line. tools: the part list of
    the first answer (a re-judge of one part must name the same parts). Fail(REQUEST_MISMATCH) otherwise."""
    if not isinstance(parts, list) or not parts:
        raise Fail("HOOK_ERROR", "(bad witness answer)")
    got = [Part(d, inp, tool_name) for d in parts]
    if not verify:
        return got, None
    st = w.judge_statement(r.get("statement_b64"))
    if st.get("nonce") != body["nonce"] or st.get("request_sha256") != request_sha256(body) or st.get("part") != part:
        raise Fail("REQUEST_MISMATCH", "(the answer is not for this call)")
    names, n, judged = st.get("parts"), st.get("n_parts"), st.get("judged")
    if not isinstance(names, list) or not names or n != len(names) or not isinstance(judged, list) or len(judged) != len(got) or not judged \
            or (tools is not None and names != tools):
        raise Fail("REQUEST_MISMATCH", "(the set of parts does not match)")
    want = [part] if part is not None else list(range(len(judged)))
    for k, (j, m) in enumerate(zip(judged, got)):
        res = m.res
        if not isinstance(j, dict) or j.get("i") != want[k] or m.i != want[k] or not isinstance(j.get("i"), int) or j["i"] >= n \
                or j.get("tool") != m.tool or names[j["i"]] != m.tool or j.get("args_sha256") != args_sha256(m.tool, m.args) \
                or (res.action or {}).get("args_sha256", j["args_sha256"]) != j["args_sha256"] or j.get("rid") != res.rid or j.get("verdict") != res.verdict \
                or j.get("status") != res.status or j.get("reason") != res.reason:
            raise Fail("REQUEST_MISMATCH", "(a part does not match the witness' statement)")
    last = got[-1].res
    if part is None and len(got) < n and not (last.verdict == "deny" or last.status in ("refused", "expired")):
        raise Fail("REQUEST_MISMATCH", "(parts are missing from the answer)")
    return got, names


def judge(ev, s: Settings, witness: Witness | None = None, deadline: float | None = None) -> dict:
    """One PreToolUse event -> hook output. Never raises: anything unexpected is a deny."""
    deadline = deadline or (time.monotonic() + s.timeout)
    try:
        tool_name, inp = _envelope(ev)
    except Fail as e:
        log("refused before the witness: %s" % e.code)
        return deny(e.code)
    if not s.key and witness is None:
        return deny("WITNESS_NOT_CONFIGURED", detail="(set DEUS_WITNESS_KEY; the key is shown once when you create an agent on the Agents page of https://witness.sipkigroup.com)")
    own = witness is None
    w = witness or Witness(s.url, s.key, verify=s.verify, timeout=max(1.0, deadline - time.monotonic()))
    texts = {}
    try:
        facts = Facts(ev, s.env)
        if w.verify and getattr(w, "_pub", True) is None:
            w.witness_info()                              # the pinned key first: the answer is checked against it
        facts.prescan(w, tool_name)
        r, body = _ask(w, ev, facts)
        texts = r.get("texts") if isinstance(r.get("texts"), dict) else {}
        if r.get("refuse"):
            log("refused by the witness: %s" % r["refuse"])
            return deny(str(r["refuse"]), detail=str(r.get("detail") or ""), texts=texts)
        got, tools = _bound(w, r, body, None, r.get("parts"), inp, tool_name, w.verify)
        results = []
        for m in got:
            res = m.res
            if res.verdict == "defer" and res.status == "pending_approval" and s.wait > 0:
                end = min(deadline - 1.0, time.monotonic() + s.wait)
                rid = res.rid
                while res.status == "pending_approval" and time.monotonic() < end:
                    res = w.get(rid, wait=int(max(1, min(25, end - time.monotonic()))))
                    if res.rid != rid:
                        raise Fail("REQUEST_MISMATCH", "(an answer about another receipt)")
                if res.status == "covered" and isinstance(m.i, int):
                    # 0.2.10: the owner answered with "allow in this project" (a signed allowance, not an approval of THIS receipt):
                    # the same part is judged again once, under the allowance (a new receipt, OK_ALLOWANCE)
                    facts.nonce = secrets.token_urlsafe(24)
                    r2, body2 = _ask(w, ev, facts, part=m.i)
                    if isinstance(r2.get("texts"), dict):
                        texts.update(r2["texts"])
                    if r2.get("refuse") or not isinstance(r2.get("parts"), list) or len(r2["parts"]) != 1:
                        return deny(str(r2.get("refuse") or "HOOK_ERROR"), detail=str(r2.get("detail") or ""), texts=texts)
                    m = _bound(w, r2, body2, m.i, r2["parts"], inp, tool_name, w.verify, tools)[0][0]
                    res = m.res
            log("tool=%s rid=%s verdict=%s status=%s" % (m.tool, res.rid, res.verdict, res.status))
            results.append((m, res))
            if res.verdict == "deny" or res.status in ("refused", "expired"):
                break                                     # the first refusal decides; nothing is consumed
        for m, res in results:
            if res.verdict == "deny":
                return deny(res.reason or "DENIED", res.rid, texts=texts)
            if res.status in ("refused", "expired") or res.verdict not in ("allow", "pass", "defer"):
                return deny({"refused": "APPROVAL_REFUSED", "expired": "RECEIPT_EXPIRED"}.get(res.status, res.reason or res.status or "UNKNOWN"), res.rid, texts=texts)
        pending = [(m, res) for m, res in results if res.verdict == "defer"]
        if pending:
            msg = " ".join("Deus Witness: %s is waiting for the owner's approval in Witness (%s, receipt %s)%s%s: %s ." % (
                m.summary, r_.reason, r_.rid, _why(m, r_, texts), _changed(r_), r_.approval_url) for m, r_ in pending) + \
                " After the owner approves there, retry the SAME call."
            if s.wait > 0:
                msg += " (No answer from the owner within %.0f s.)" % s.wait
            if s.on_defer == "ask":
                return decision("ask", msg + " Answering yes here runs it WITHOUT a witness receipt; the safe answer is No: "
                                "approve in Witness, then retry.")
            return decision(s.on_defer, msg)
        allowed = [(m, res) for m, res in results if res.verdict == "allow"]
        for m, res in allowed:                            # check every receipt BEFORE consuming any
            if res.status not in ("allowed", "approved"):
                return deny(res.reason or res.status, res.rid, texts=texts)
            if (res.action or {}).get("args_sha256") != args_sha256(m.tool, m.args):
                return deny("REQUEST_MISMATCH", res.rid, texts=texts)
            if w.verify:
                w.check(res, sent=(m.tool, m.args))
        for m, res in allowed:
            pr = w.present(res.rid)                       # CONSUME in the ledger BEFORE the tool runs: one receipt, one run
            if pr.get("result") != "accept":
                return deny(str(pr.get("reason", "NOT_ACCEPTED")), res.rid, texts=texts)
        owned = [(m, res) for m, res in allowed if res.reason != "OK_PASS"]   # 0.2.4+: a `pass` call under a signed map is answered allow/OK_PASS WITH a receipt (consumed above); it is still not the mandate's decision
        if not owned or s.allow == "neutral":
            return decision(None)                         # only `pass` parts: Claude Code's own permission rules decide
        return decision("allow", "Deus Witness: allowed by the owner's mandate (%s)" % ", ".join(
            "%s, receipt %s" % (res.reason, res.rid) for _, res in owned))
    except Fail as e:
        log("refused: %s" % e.code)
        return deny(e.code, detail=e.detail, texts=texts)
    except AARError as e:
        log("AAR rejected: %s" % e)
        return deny("AAR_%s" % e)
    except WitnessKeyChanged:
        return deny("WITNESS_KEY_CHANGED")
    except WitnessError as e:
        log("witness error %s %s" % (e.status, e.code))
        if e.status == 401 or e.code == "BAD_KEY":        # the witness answered and refused the key: not "unreachable"; the call still does not run
            return deny("BAD_KEY", detail="(the agent key is wrong or was deleted: create a new agent on the Agents page of https://witness.sipkigroup.com and use its key)")
        return deny("WITNESS_UNAVAILABLE", detail=e.code)
    except Exception as e:      # noqa: BLE001  whatever goes wrong while judging, the call does not run
        log("cannot judge (%s)" % type(e).__name__)
        return deny("HOOK_ERROR", detail=type(e).__name__)
    finally:
        if own:
            try:
                w.close()
            except Exception:
                pass


def _why(m, res, texts) -> str:
    """The witness' words for the code of this part (it knows what the part is); a code that changed while waiting: its table text."""
    t = m.why if res.reason == m.res.reason else ""
    if not t:
        x = texts.get(res.reason) if isinstance(texts, dict) else None
        t = x[1] if isinstance(x, (list, tuple)) and len(x) == 2 and isinstance(x[1], str) else ""
    return " - " + t if t else ""


def run(stdin_bytes: bytes, env=None) -> dict | None:
    """-> the hook output, or None for an event that is not PreToolUse (no decision)."""
    s = Settings(env)
    try:
        if len(stdin_bytes) > MAX_EVENT:
            return deny("EVENT_TOO_LARGE")
        ev = json.loads(stdin_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return deny("EVENT_MALFORMED")
    if isinstance(ev, dict) and ev.get("hook_event_name") not in (None, "PreToolUse"):
        return None
    out = {}
    deadline = time.monotonic() + s.timeout

    def work():
        out["r"] = judge(ev, s, deadline=deadline)
    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(s.timeout)
    if "r" not in out:
        log("no decision within %.0f s" % s.timeout)
        return deny("WITNESS_TIMEOUT", detail="(no answer within %.0f s)" % s.timeout)
    return out["r"]


def _out(text: str) -> None:
    """stdout as UTF-8 bytes with plain \\n: the same JSON line on every OS (Windows text mode would write cp1252 and CRLF)."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8", "replace"))
    except AttributeError:      # a stdout without .buffer (tests that replace sys.stdout)
        sys.stdout.write(text)


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--print-form"]:
        rest = [a for a in argv[1:] if a != "--no-irreversible"]
        form = default_form(rest[0] if rest else os.getcwd())
        if "--no-irreversible" in argv:
            form["delete"]["allow_irreversible"] = False      # read-only mandate: Write/Edit/redirections are refused everywhere
        print(json.dumps(form, indent=1))
        return
    if argv[:1] == ["--doctor"]:
        r = failsafe.check(argv[1] if len(argv) > 1 else os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        print(failsafe.report_text(r))
        sys.stdout.flush()
        os._exit(1 if r["problems"] else 0)
    if argv[:1] == ["--session-start"]:
        try:                                              # a warning only: it never blocks the session
            raw = sys.stdin.read(MAX_EVENT) if not sys.stdin.isatty() else ""
            ev = json.loads(raw) if raw.strip() else {}
            d = (ev.get("cwd") if isinstance(ev, dict) else None) or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
            out = failsafe.session_start_output(failsafe.check(os.environ.get("CLAUDE_PROJECT_DIR") or d))
            if out:
                _out(json.dumps(out, ensure_ascii=False) + "\n")
                log(out["systemMessage"])
        except Exception as e:   # noqa: BLE001
            log("session-start check failed (%s)" % type(e).__name__)
        sys.stdout.flush()
        os._exit(0)
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return
    try:
        r = run(sys.stdin.buffer.read(MAX_EVENT + 1))
        if r is not None:
            _out((json.dumps(r, ensure_ascii=False) + "\n"))
        sys.stdout.flush()
    except BaseException as e:   # noqa: BLE001  exit 2 is the one non-zero code Claude Code treats as "block"
        try:
            sys.stderr.write("Blocked by Deus Witness: HOOK_ERROR %s\n" % type(e).__name__)
        finally:
            os._exit(2)
    os._exit(0)                  # do not wait for a judging thread stuck on the network


if __name__ == "__main__":
    main()
