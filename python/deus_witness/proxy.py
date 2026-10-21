"""deus-witness-mcp: stdio MCP proxy. Every tools/call goes through the witness; the rest is forwarded untouched.

  deus-witness-mcp [--url U] [--no-verify-aar] -- <upstream MCP server command...>

Env: DEUS_WITNESS_KEY (required), DEUS_WITNESS_URL, DEUS_WITNESS_WAIT (seconds per long poll, default 25),
DEUS_WITNESS_POLLS (number of long polls on defer, default 2), DEUS_WITNESS_VERIFY=0 (same as --no-verify-aar).
Fail closed: if the witness cannot be reached, the call is blocked. The log (stderr) has only tool, rid, verdict - never arguments.
0.2: once the client has initialized, the proxy asks the upstream for tools/list itself (a private id; the
answer is not forwarded), sends POST /v1/catalog, runs the light doctor (configs only, no network probes) and sends POST /v1/coverage.
tools/call waits for that; a network error to the witness there blocks every call of this run (fail closed)."""
import argparse
import asyncio
import json
import os
import sys

from . import __version__
from .client import AARError, Witness, WitnessError, WitnessKeyChanged, args_sha256
from .doctor import coverage_body, diagnose

MAX_LINE = 64 * 1024 * 1024
STARTUP_WAIT = 60        # s a tools/call waits for the start-up catalog/coverage
LIST_WAIT = 30           # s for the upstream to answer the private tools/list
CATALOG_ID = "deus-witness-catalog-%d"


def log(msg: str) -> None:
    sys.stderr.write("[deus-witness] %s\n" % msg)
    sys.stderr.flush()


def _text_error(req_id, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}], "isError": True}}


class Proxy:
    def __init__(self, witness: Witness, cmd: list, wait_s: int = 25, polls: int = 2):
        self.w, self.cmd, self.wait_s, self.polls = witness, cmd, wait_s, polls
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
    async def decide(self, name: str, args: dict):
        """-> ("forward", rid or None) | ("block", text)."""
        w = self.w
        res = None
        sent_hash = args_sha256(name, args)       # R-09: the receipt must be for THIS call
        try:
            res = await asyncio.to_thread(w.act, name, args, {"name": "deus-witness-mcp", "version": __version__}, False)
            polls = 0
            while res.verdict == "defer" and res.status == "pending_approval" and polls < self.polls:
                polls += 1
                res = await asyncio.to_thread(w.get, res.rid, self.wait_s)
            while res.status == "held" and polls < self.polls:       # 0.2: held by the advisor (4.2), waits like defer
                polls += 1
                res = await asyncio.to_thread(w.get, res.rid, self.wait_s)
            log("tool=%s rid=%s verdict=%s status=%s" % (name, res.rid, res.verdict, res.status))
            if res.status == "held":
                return "block", "Held by advisor for owner review at %s. Retry the same call after review." % (res.approval_url or w.url)
            if res.verdict == "pass":
                return "forward", None
            if res.verdict == "allow" and res.status in ("allowed", "approved"):
                if (res.action or {}).get("args_sha256") != sent_hash:
                    log("tool=%s rid=%s REQUEST_MISMATCH" % (name, res.rid))
                    return "block", "Blocked by Deus Witness: REQUEST_MISMATCH (receipt %s)" % res.rid
                if w.verify:
                    await asyncio.to_thread(w.check, res)
                pr = await asyncio.to_thread(w.present, res.rid)   # CONSUME in the ledger BEFORE the tool runs
                if pr.get("result") != "accept":
                    log("tool=%s rid=%s present=%s" % (name, res.rid, pr.get("reason")))
                    return "block", "Blocked by Deus Witness: %s (receipt %s)" % (pr.get("reason", "NOT_ACCEPTED"), res.rid)
                return "forward", res.rid
            if res.verdict == "defer" and res.status == "pending_approval":
                return "block", "Held for owner approval at %s. Retry the same call after approval." % res.approval_url
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
            return "block", "Blocked by Deus Witness: WITNESS_UNAVAILABLE %s (receipt none)" % e.code

    async def handle_call(self, line: bytes, msg: dict) -> None:
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
            kind, val = await self.decide(name, args)
        except Exception as e:      # noqa: BLE001  N-10b: whatever goes wrong while judging, the client gets an answer and nothing runs
            log("tool=%s cannot be judged (%s)" % (name, type(e).__name__))
            await self.send_client({"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32602, "message": "Blocked by Deus Witness: MALFORMED_CALL"}})
            return
        if kind == "block":
            await self.send_client(_text_error(msg["id"], val))
            return
        if val is not None:
            self.inflight[json.dumps(msg["id"])] = val
        if kind == "forward":
            # N-07: forward EXACTLY what was judged (the parsed message re-serialised), not the raw line: a duplicate key could mean another thing upstream
            line = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8", "surrogatepass")
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
            self.startup_block = "Blocked by Deus Witness: WITNESS_UNAVAILABLE %s (receipt none)" % e.code
        finally:
            self.ready.set()

    # ---- pumps ----
    async def client_to_up(self) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=MAX_LINE)
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
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
                t = asyncio.create_task(self.handle_call(line, msg))
                self.tasks.add(t)
                t.add_done_callback(self.tasks.discard)
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
        self.up = await asyncio.create_subprocess_exec(*self.cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
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


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
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
        sys.stderr.write("deus-witness-mcp: set DEUS_WITNESS_KEY (dwk_...)\n")
        sys.exit(2)
    verify = not (o.no_verify_aar or os.environ.get("DEUS_WITNESS_VERIFY") == "0")
    w = Witness(o.url, key, verify=verify)
    wait_s = int(os.environ.get("DEUS_WITNESS_WAIT", "25"))
    polls = int(os.environ.get("DEUS_WITNESS_POLLS", "2"))
    log("url=%s verify_aar=%s upstream=%s" % (w.url, verify, cmd[0]))
    try:
        rc = asyncio.run(Proxy(w, cmd, wait_s, polls).run())
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
