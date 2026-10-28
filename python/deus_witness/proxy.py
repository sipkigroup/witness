"""deus-witness-mcp: stdio MCP proxy. Every tools/call goes through the witness; the rest is forwarded untouched.

  deus-witness-mcp [--url U] [--no-verify-aar] -- <upstream MCP server command...>

Env: DEUS_WITNESS_KEY (required), DEUS_WITNESS_URL, DEUS_WITNESS_WAIT (seconds per long poll, default 25),
DEUS_WITNESS_POLLS (number of long polls on defer, default 2), DEUS_WITNESS_HOLD_MAX_S (how long one tools/call may wait for the owner;
default WAIT x POLLS = 50 s; for Claude Code it can be raised, see README "Waiting for approval / timeouts"),
DEUS_WITNESS_VERIFY=0 (same as --no-verify-aar).
0.2.22: notifications/cancelled from the client ends the wait and the held action is never run later (no ghost execution);
a tools/call with _meta.progressToken gets notifications/progress every ~12 s while it waits; the Held text says "NOT executed".
Fail closed: if the witness cannot be reached, the call is blocked. The log (stderr) has only tool, rid, verdict - never arguments.
0.2: once the client has initialized, the proxy asks the upstream for tools/list itself (a private id; the
answer is not forwarded), sends POST /v1/catalog, runs the light doctor (configs only, no network probes) and sends POST /v1/coverage.
tools/call waits for that; a network error to the witness there blocks every call of this run (fail closed)."""
import argparse
import asyncio
import json
import os
import sys

from . import __version__, _compat
from .client import AARError, Witness, WitnessError, WitnessKeyChanged, args_sha256
from .doctor import coverage_body, diagnose

MAX_LINE = 64 * 1024 * 1024
STARTUP_WAIT = 60        # s a tools/call waits for the start-up catalog/coverage
LIST_WAIT = 30           # s for the upstream to answer the private tools/list
CATALOG_ID = "deus-witness-catalog-%d"
PROGRESS_EVERY = 12.0    # s between notifications/progress while a call waits for the owner (only if the client sent a progressToken)
HOLD_CAP = 3600          # s, upper bound of DEUS_WITNESS_HOLD_MAX_S (the server keeps an action 900 s or longer anyway)


def log(msg: str) -> None:
    sys.stderr.write("[deus-witness] %s\n" % msg)
    sys.stderr.flush()


KEY_HELP = ("the agent key is wrong or was deleted: create a new agent on the Agents page of https://witness.sipkigroup.com "
            "and use its key (dwk_...)")
NO_KEY_HELP = ("set DEUS_WITNESS_KEY (dwk_...). The key is shown once when you create an agent on the Agents page of "
               "https://witness.sipkigroup.com (quickstart step 2: https://witness.sipkigroup.com/dl/docs/quickstart.html)")


def witness_error_text(e: WitnessError) -> str:
    """The text for the agent when the witness answered with an error. The call is blocked in every case (fail closed); only the words
    differ: a refused key is not an unreachable witness."""
    if e.status == 401 or e.code == "BAD_KEY":
        return "Blocked by Deus Witness: BAD_KEY (receipt none): %s" % KEY_HELP
    return "Blocked by Deus Witness: WITNESS_UNAVAILABLE %s (receipt none)" % e.code


def _text_error(req_id, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}], "isError": True}}


class CallCancelled(Exception):
    """The MCP client cancelled this tools/call (notifications/cancelled) before it was forwarded."""


class CallState:
    """What the proxy knows about one tools/call that is being judged."""
    def __init__(self, token=None):
        self.cancel = asyncio.Event()
        self.token = token          # params._meta.progressToken or None
        self.forwarded = False      # True once the line went to the upstream: a later cancel is the upstream's business
        self.rid = None
        self.n = 0                  # progress counter


def held_text(url: str, rid: str) -> str:
    return ("Action NOT executed: waiting for the owner's approval.\n"
            "Receipt (rid): %s\n"
            "The owner can approve it at: %s\n"
            "After the owner has approved, retry the exact same call (same tool, same arguments). Do not change the arguments.") % (rid, url)


def advisor_text(url: str, rid: str) -> str:
    return ("Held by advisor for owner review at %s. Action NOT executed.\n"
            "Receipt (rid): %s\n"
            "After the review, retry the exact same call (same tool, same arguments). Do not change the arguments.") % (url, rid)


class Proxy:
    def __init__(self, witness: Witness, cmd: list, wait_s: int = 25, polls: int = 2, hold_max_s=None, progress_every: float = PROGRESS_EVERY):
        self.w, self.cmd, self.wait_s, self.polls = witness, cmd, wait_s, polls
        self.hold_s = max(0, min(HOLD_CAP, int(hold_max_s if hold_max_s is not None else wait_s * polls)))   # 0.2.22: default = the old WAIT x POLLS
        self.max_polls = polls if hold_max_s is None else None      # without HOLD_MAX_S: exactly the old rule (POLLS long polls of WAIT s)
        self.progress_every = progress_every
        self.calls = {}      # json id -> CallState of a tools/call that is still being judged or was forwarded
        self.up = None
        self.out_lock = asyncio.Lock()
        self.inflight = {}   # json id -> rid of an allowed call that has been forwarded (report after the response)
        self.tasks = set()
        self.private = {}    # json id -> future: our own requests to the upstream, answers are not forwarded
        self.started = False
        self.ready = asyncio.Event()
        self.startup_block = None   # text: the start-up could not reach the witness, every call is blocked

    async def send_client(self, msg) -> None:
        data = (msg if isinstance(msg, str) else json.dumps(msg, ensure_ascii=False, separators=(",", ":"))).encode() + b"\n"
        async with self.out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def send_up(self, line: bytes) -> None:
        self.up.stdin.write(line if line.endswith(b"\n") else line + b"\n")
        await self.up.stdin.drain()

    # ---- decision for one tools/call ----
    async def _thread(self, st: CallState, fn, *a, interruptible: bool = True):
        """Runs a blocking witness call in a thread. While it runs: progress notifications (if the client asked for them) and the
        cancellation of the client. A cancelled interruptible call is abandoned (its thread ends by itself, the result is dropped)."""
        if st.cancel.is_set():
            raise CallCancelled()
        fut = asyncio.ensure_future(asyncio.to_thread(fn, *a))
        if not interruptible:
            res = await fut
            if st.cancel.is_set():
                raise CallCancelled()
            return res
        fut.add_done_callback(lambda f: f.cancelled() or f.exception())     # an abandoned result is never awaited: no "never retrieved" noise
        cw = asyncio.ensure_future(st.cancel.wait())
        try:
            while True:
                done, _ = await asyncio.wait({fut, cw}, timeout=self.progress_every if st.token is not None else None,
                                             return_when=asyncio.FIRST_COMPLETED)
                if fut in done:
                    return fut.result()
                if cw in done:
                    raise CallCancelled()
                await self.progress(st)
        finally:
            cw.cancel()

    async def progress(self, st: CallState) -> None:
        st.n += 1
        await self.send_client({"jsonrpc": "2.0", "method": "notifications/progress",
                                "params": {"progressToken": st.token, "progress": st.n, "message": "waiting for owner approval"}})

    async def _poll_wait(self, st: CallState, res, deadline: float):
        """Long-polls until the action leaves pending_approval/held or the hold time (deadline, monotonic) is used up."""
        loop = asyncio.get_running_loop()
        pause, n = 0.5, 0
        while (self.max_polls is None or n < self.max_polls) and (res.status == "held" or (res.verdict == "defer" and res.status == "pending_approval")) and loop.time() < deadline:
            n += 1
            left = deadline - loop.time()
            t0 = loop.time()
            res = await self._thread(st, self.w.get, res.rid, max(1, min(self.wait_s, int(-(-left // 1)))))
            st.rid = res.rid
            if self.max_polls is None and (res.status == "held" or res.status == "pending_approval") and loop.time() - t0 < 0.5:   # answered at once: do not spin
                try:
                    await asyncio.wait_for(st.cancel.wait(), min(pause, max(0.0, deadline - loop.time())))
                    raise CallCancelled()
                except asyncio.TimeoutError:
                    pass
                pause = min(pause * 2, 8.0)
        return res

    async def decide(self, name: str, args: dict, st: CallState = None):
        """-> ("forward", rid or None) | ("block", text). Raises CallCancelled if the client cancelled meanwhile (nothing was forwarded)."""
        w = self.w
        st = st or CallState()
        res = None
        sent_hash = await self._thread(st, w.args_hash, name, args, interruptible=False)        # R-09: the receipt must be for THIS call
        try:
            res = await self._thread(st, w.act, name, args, {"name": "deus-witness-mcp", "version": __version__}, False)
            st.rid = res.rid
            res = await self._poll_wait(st, res, asyncio.get_running_loop().time() + self.hold_s)     # defer, and 0.2 held by the advisor (4.2)
            log("tool=%s rid=%s verdict=%s status=%s" % (name, res.rid, res.verdict, res.status))
            if res.status == "held":
                return "block", advisor_text(res.approval_url or w.url, res.rid)
            if res.verdict == "pass":
                return "forward", None
            if res.verdict == "allow" and res.status in ("allowed", "approved"):
                if (res.action or {}).get("args_sha256") != sent_hash:
                    log("tool=%s rid=%s REQUEST_MISMATCH" % (name, res.rid))
                    return "block", "Blocked by Deus Witness: REQUEST_MISMATCH (receipt %s)" % res.rid
                if w.verify:
                    await self._thread(st, w.check, res, interruptible=False)
                pr = await self._thread(st, w.present, res.rid, interruptible=False)   # CONSUME in the ledger BEFORE the tool runs
                if pr.get("result") != "accept":
                    log("tool=%s rid=%s present=%s" % (name, res.rid, pr.get("reason")))
                    return "block", "Blocked by Deus Witness: %s (receipt %s)" % (pr.get("reason", "NOT_ACCEPTED"), res.rid)
                return "forward", res.rid
            if res.verdict == "defer" and res.status == "pending_approval":
                return "block", held_text(res.approval_url or w.url, res.rid)
            reason = res.reason if res.verdict == "deny" else {"refused": "APPROVAL_REFUSED", "expired": "RECEIPT_EXPIRED"}.get(res.status, res.reason or res.status)
            return "block", "Blocked by Deus Witness: %s (receipt %s)" % (reason, res.rid)
        except AARError as e:
            log("tool=%s AAR rejected: %s" % (name, e))
            return "block", "Blocked by Deus Witness: AAR_%s (receipt %s)" % (e, res.rid if res else "none")
        except WitnessKeyChanged:
            log("tool=%s witness key changed" % name)
            return "block", "Blocked by Deus Witness: WITNESS_KEY_CHANGED (receipt none)"
        except WitnessError as e:
            log("tool=%s witness error %s %s" % (name, e.status, e.code))
            return "block", witness_error_text(e)

    async def handle_call(self, line: bytes, msg: dict, st: CallState = None) -> None:
        st = st or CallState()
        key = json.dumps(msg.get("id"))
        try:
            await self._handle_call(line, msg, st)
        except CallCancelled:
            # 0.2.22: the client gave up (notifications/cancelled). Nothing was forwarded and nothing will be: the approval that may still
            # come is for a call nobody waits for. No response is sent (MCP: the receiver SHOULD NOT answer a cancelled request).
            log("tool=%s rid=%s cancelled by the client, not executed" % (self._name(msg), st.rid or "none"))
            if st.rid:
                try:
                    await asyncio.to_thread(self.w.report, st.rid, False)    # release the receipt if it was already consumed; "ignored" if still pending
                except Exception as e:      # noqa: BLE001  best effort, the action is not forwarded in any case
                    log("cancel report failed rid=%s %s" % (st.rid, getattr(e, "code", type(e).__name__)))
        finally:
            if self.calls.get(key) is st:
                self.calls.pop(key, None)

    @staticmethod
    def _name(msg: dict) -> str:
        p = msg.get("params")
        return p.get("name") if isinstance(p, dict) and isinstance(p.get("name"), str) else "?"

    async def _handle_call(self, line: bytes, msg: dict, st: CallState) -> None:
        p = msg.get("params")
        p = {} if p is None else p
        name = p.get("name") if isinstance(p, dict) else None
        args = p.get("arguments") if isinstance(p, dict) else None
        args = {} if args is None else args
        if not isinstance(name, str) or not name or not isinstance(args, dict):
            # R-10: fail closed. A tools/call that cannot be shown to the witness in a well-formed shape never reaches the upstream.
            await self.send_client({"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32602, "message": "Blocked by Deus Witness: MALFORMED_CALL"}})
            return
        try:
            await asyncio.wait_for(self.ready.wait(), STARTUP_WAIT)
        except asyncio.TimeoutError:
            self.startup_block = self.startup_block or "Blocked by Deus Witness: WITNESS_UNAVAILABLE STARTUP (receipt none)"
        if self.startup_block:
            log("tool=%s blocked: start-up did not reach the witness" % name)
            await self.send_client(_text_error(msg["id"], self.startup_block))
            return
        try:
            kind, val = await self.decide(name, args, st)
        except CallCancelled:
            raise
        except Exception as e:      # noqa: BLE001  N-10b: whatever goes wrong while judging, the client gets an answer and nothing runs
            log("tool=%s cannot be judged (%s)" % (name, type(e).__name__))
            await self.send_client({"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32602, "message": "Blocked by Deus Witness: MALFORMED_CALL"}})
            return
        if kind == "block":
            await self.send_client(_text_error(msg["id"], val))
            return
        if st.cancel.is_set():          # cancelled while the last step ran: the receipt (if consumed) is released by handle_call, the tool does not run
            raise CallCancelled()
        if val is not None:
            self.inflight[json.dumps(msg["id"])] = val
        if kind == "forward":
            # N-07: forward EXACTLY what was judged (the parsed message re-serialised), not the raw line: a duplicate key could mean another thing upstream
            line = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8", "surrogatepass")
        st.forwarded = True             # no await between the check above and this line: a cancel can no longer stop it, the upstream gets the notification
        await self.send_up(line)

    # ---- start-up: catalog + light doctor -> coverage (once per run) ----
    async def ask_up(self, method: str, params: dict, n: int):
        rid = CATALOG_ID % n
        fut = asyncio.get_running_loop().create_future()
        self.private[json.dumps(rid)] = fut
        await self.send_up(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode())
        try:
            return await asyncio.wait_for(fut, LIST_WAIT)
        finally:
            self.private.pop(json.dumps(rid), None)

    async def upstream_tools(self):
        """-> list of tools of the upstream (all pages) or None."""
        tools, cursor = [], None
        for n in range(1, 51):
            msg = await self.ask_up("tools/list", {"cursor": cursor} if cursor else {}, n)
            r = msg.get("result") if isinstance(msg, dict) else None
            if not isinstance(r, dict) or not isinstance(r.get("tools"), list):
                return None
            tools += [t for t in r["tools"] if isinstance(t, dict) and isinstance(t.get("name"), str)]
            cursor = r.get("nextCursor")
            if not cursor:
                return tools
        return tools

    async def startup(self) -> None:
        try:
            pass_net = None
            try:
                tools = await self.upstream_tools()
            except (asyncio.TimeoutError, OSError):
                tools = None
            if tools is None:
                log("catalog: upstream tools/list failed, catalog not sent")
            else:
                try:
                    res = await asyncio.to_thread(self.w.catalog, tools)
                    pn = res.get("pass_net_tools") if isinstance(res, dict) else None
                    pass_net = [x for x in pn if isinstance(x, str)] if isinstance(pn, list) else None
                    log("catalog: %d tools sha256=%s changed=%s" % (len(tools), str(res.get("catalog_sha256"))[:12], res.get("changed")))
                except WitnessError as e:
                    if e.status == 0:
                        raise
                    log("catalog: witness answered %s %s (not stored)" % (e.status, e.code))
            try:
                rep = await asyncio.to_thread(diagnose, None, None, False, pass_net, True)
            except Exception as e:      # noqa: BLE001  a broken config reader must not take the proxy down
                log("coverage: doctor failed (%s), not sent" % type(e).__name__)
                return
            try:
                await asyncio.to_thread(self.w.coverage, coverage_body(rep, pass_net))
                log("coverage: %s (operator-declared), %d bypass" % (rep["coverage"], len(rep["bypass"])))
            except WitnessError as e:
                if e.status == 0:
                    raise
                log("coverage: witness answered %s %s (not stored)" % (e.status, e.code))
        except WitnessError as e:
            log("start-up: witness unreachable (%s), every call of this run is blocked" % e.code)
            self.startup_block = witness_error_text(e)
        finally:
            self.ready.set()

    # ---- pumps ----
    def _cancel_pending(self, msg: dict) -> bool:
        """notifications/cancelled for a tools/call that is still being judged (not forwarded): stop its wait. True = consumed here."""
        p = msg.get("params")
        rid = p.get("requestId") if isinstance(p, dict) else None
        st = self.calls.get(json.dumps(rid)) if rid is not None else None
        if st is None or st.forwarded:
            return False
        st.cancel.set()
        return True

    async def client_to_up(self) -> None:
        reader = await _compat.open_stdin_reader(MAX_LINE)     # POSIX: the loop watches the pipe; Windows: a reader thread
        while True:
            try:
                line = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                log("input line too long, closing")
                break
            if not line:
                break
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                log("not JSON, dropped")                      # R-10: nothing unparsable is forwarded
                continue
            if isinstance(msg, list):                         # JSON-RPC batch: not supported, so no call can slip through inside one
                log("batch refused")
                await self.send_client({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Blocked by Deus Witness: BATCH_NOT_SUPPORTED"}})
                continue
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                if "id" not in msg:                           # a tools/call without id is not answerable and must not run
                    log("tools/call without id dropped")
                    continue
                meta = (msg.get("params") or {}).get("_meta") if isinstance(msg.get("params"), dict) else None
                tok = meta.get("progressToken") if isinstance(meta, dict) else None
                st = CallState(tok if isinstance(tok, (str, int)) and not isinstance(tok, bool) else None)
                self.calls[json.dumps(msg["id"])] = st
                t = asyncio.create_task(self.handle_call(line, msg, st))
                self.tasks.add(t)
                t.add_done_callback(self.tasks.discard)
            elif isinstance(msg, dict) and msg.get("method") == "notifications/cancelled" and self._cancel_pending(msg):
                continue                   # 0.2.22: a call that was never forwarded: the upstream does not know it, nothing to tell it
            else:
                await self.send_up(line)
                if isinstance(msg, dict) and msg.get("method") == "notifications/initialized" and not self.started:
                    self.started = True
                    t = asyncio.create_task(self.startup())
                    self.tasks.add(t)
                    t.add_done_callback(self.tasks.discard)
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)
        try:
            self.up.stdin.close()
        except Exception:
            pass

    async def up_to_client(self) -> None:
        while True:
            line = await self.up.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                msg = None
            if isinstance(msg, dict) and "id" in msg and "method" not in msg:
                fut = self.private.get(json.dumps(msg["id"]))
                if fut is not None:          # the answer to our own tools/list: not for the client
                    if not fut.done():
                        fut.set_result(msg)
                    continue
                rid = self.inflight.pop(json.dumps(msg["id"]), None)
                if rid is not None:
                    ok = "error" not in msg and not (msg.get("result") or {}).get("isError")
                    try:
                        await asyncio.to_thread(self.w.report, rid, ok)
                    except WitnessError as e:
                        log("report failed rid=%s %s" % (rid, e.code))
            await self.send_client(line.decode("utf-8", "replace").rstrip("\n"))

    async def run(self) -> int:
        self.up = await asyncio.create_subprocess_exec(*_compat.resolve_command(self.cmd), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                                       stderr=None, limit=MAX_LINE)
        a = asyncio.create_task(self.client_to_up())
        b = asyncio.create_task(self.up_to_client())
        await asyncio.wait({a, b}, return_when=asyncio.FIRST_COMPLETED)
        if a.done():   # client closed: let the upstream finish
            try:
                await asyncio.wait_for(self.up.wait(), 5)
            except asyncio.TimeoutError:
                self.up.terminate()
            await asyncio.wait({b}, timeout=2)
        else:
            a.cancel()
        for t in (a, b):
            t.cancel()
        if self.up.returncode is None:
            self.up.terminate()
        return self.up.returncode or 0


HELP = """usage: deus-witness-mcp [--url U] [--no-verify-aar] -- <upstream MCP server command...>
Witness proxy: stands between the agent and an upstream MCP server; every tool call is judged first.
  --url U            witness address (default: the hosted one)
  --no-verify-aar    do not verify the signed receipts
  needs DEUS_WITNESS_KEY in the environment
example: DEUS_WITNESS_KEY=... deus-witness-mcp -- npx -y some-mcp-server
exit: 0 for -h / --help; 2 wrong usage
"""


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in (argv[:argv.index("--")] if "--" in argv else argv)):
        sys.stdout.write(HELP)
        sys.exit(0)
    if "--" not in argv:
        sys.stderr.write("usage: deus-witness-mcp [--url U] [--no-verify-aar] -- <upstream MCP server command...>\n")
        sys.exit(2)
    i = argv.index("--")
    ap = argparse.ArgumentParser(prog="deus-witness-mcp")
    ap.add_argument("--url", default=None)
    ap.add_argument("--no-verify-aar", action="store_true")
    o = ap.parse_args(argv[:i])
    cmd = argv[i + 1:]
    if not cmd:
        sys.stderr.write("deus-witness-mcp: upstream command missing after --\n")
        sys.exit(2)
    key = os.environ.get("DEUS_WITNESS_KEY")
    if not key:
        sys.stderr.write("deus-witness-mcp: %s\n" % NO_KEY_HELP)
        sys.exit(2)
    verify = not (o.no_verify_aar or os.environ.get("DEUS_WITNESS_VERIFY") == "0")
    w = Witness(o.url, key, verify=verify)
    wait_s = int(os.environ.get("DEUS_WITNESS_WAIT", "25"))
    polls = int(os.environ.get("DEUS_WITNESS_POLLS", "2"))
    hold = os.environ.get("DEUS_WITNESS_HOLD_MAX_S")
    try:
        hold_s = int(hold) if hold not in (None, "") else None
    except ValueError:
        sys.stderr.write("deus-witness-mcp: DEUS_WITNESS_HOLD_MAX_S must be a whole number of seconds (got %r)\n" % hold)
        sys.exit(2)
    log("url=%s verify_aar=%s upstream=%s" % (w.url, verify, cmd[0]))
    try:
        rc = asyncio.run(Proxy(w, cmd, wait_s, polls, hold_s, float(os.environ.get("DEUS_WITNESS_PROGRESS_S", PROGRESS_EVERY))).run())
    except KeyboardInterrupt:
        rc = 130
    except OSError as e:
        sys.stderr.write("deus-witness-mcp: cannot start the upstream command %r (%s). Is it installed and on PATH? (On Windows `npx` is found as npx.cmd.)\n"
                         % (cmd[0], type(e).__name__))
        rc = 127
    if _compat.READER_THREAD_STARTED:
        _compat.exit_now(rc)
    sys.exit(rc)


if __name__ == "__main__":
    main()
