#!/usr/bin/env python3
"""Cross-platform smoke test of the installed Python client (no bash; runs the same in PowerShell, cmd, zsh).

Run after `pip install` of the wheel built from python/. Needs no account and no network: the proxy is pointed at a closed
local port, so the witness is "unreachable" and a tool call must be blocked (fail closed)."""
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile

TIMEOUT = 90
FAILS = []


def check(ok, what, extra=""):
    print(("ok   " if ok else "FAIL ") + what + ((" :: " + extra) if (extra and not ok) else ""), flush=True)
    if not ok:
        FAILS.append(what)


def exe(name):
    p = shutil.which(name)
    if p:
        return p
    for d in (sysconfig.get_path("scripts"), os.path.join(os.path.dirname(sys.executable), "Scripts"), os.path.dirname(sys.executable)):
        for ext in ("", ".exe"):
            c = os.path.join(d, name + ext)
            if os.path.isfile(c):
                return c
    raise SystemExit("console script not found: " + name)


def run(args, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def main():
    home = tempfile.mkdtemp(prefix="dw-smoke-")
    env = dict(os.environ, PYTHONUTF8="1", DEUS_WITNESS_HOME=os.path.join(home, "pin"), DEUS_DEMO_OUT=os.path.join(home, "out"),
               DEUS_WITNESS_URL="http://127.0.0.1:9", DEUS_WITNESS_KEY="dwk_CI_NOT_A_KEY", HOME=home, USERPROFILE=home)
    print("python", sys.version.split()[0], sys.platform, "home", home, flush=True)

    # 1. imports
    import importlib
    for m in ("deus_witness", "deus_witness.client", "deus_witness.proxy", "deus_witness.doctor", "deus_witness.demo_upstream",
              "deus_witness.hook.main", "deus_witness.hook.form", "deus_witness.hook.failsafe"):
        try:
            importlib.import_module(m)
            check(True, "import " + m)
        except Exception as e:  # noqa
            check(False, "import " + m, repr(e))

    # 2. doctor: empty HOME -> C0, rc 2 (nothing behind the proxy)
    r = run([exe("deus-witness"), "doctor", "--no-network", "--project", home], env=env)
    check("coverage:" in r.stdout and r.returncode == 2, "deus-witness doctor --no-network (C0, rc 2)", r.stdout + r.stderr + str(r.returncode))
    r = run([exe("deus-witness"), "--help"], env=env)
    check(r.returncode == 0 and "doctor" in r.stdout, "deus-witness --help")

    # 3. hook --print-form
    r = run([exe("deus-witness-hook"), "--print-form", home], env=env)
    try:
        form = json.loads(r.stdout)
        check(r.returncode == 0 and isinstance(form, dict) and "delete" in form, "deus-witness-hook --print-form is JSON")
    except Exception as e:  # noqa
        check(False, "deus-witness-hook --print-form is JSON", repr(e) + r.stdout[:300] + r.stderr[:300])

    # 3b. hook without key: must DENY (fail closed), rc 0
    ev = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": home})
    env_nokey = {k: v for k, v in env.items() if k != "DEUS_WITNESS_KEY"}
    r = run([exe("deus-witness-hook")], env=env_nokey, input=ev)
    check(r.returncode == 0 and '"deny"' in r.stdout, "deus-witness-hook without key denies (fail closed)", r.stdout + r.stderr)

    # 4. proxy end to end over stdio: deus-witness -- python -m deus_witness.demo_upstream
    cmd = [exe("deus-witness"), "--", sys.executable, "-m", "deus_witness.demo_upstream"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def send(obj):
        p.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        p.stdin.flush()

    def recv():
        line = p.stdout.readline()
        return json.loads(line.decode("utf-8")) if line else None

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                              "clientInfo": {"name": "ci", "version": "0"}}})
        r1 = recv()
        check(bool(r1) and r1.get("id") == 1 and "serverInfo" in r1.get("result", {}), "proxy: initialize answered by the upstream", str(r1))
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        r2 = recv()
        names = [t["name"] for t in (r2 or {}).get("result", {}).get("tools", [])]
        check("send_email" in names, "proxy: tools/list passes through", str(r2)[:300])
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "send_email", "arguments": {"to": "a@b.example", "subject": "s", "body": "b"}}})
        r3 = recv()
        txt = json.dumps(r3)
        check("Blocked by Deus Witness" in txt, "proxy: tools/call blocked when the witness is unreachable", txt[:300])
        check(not os.path.exists(os.path.join(home, "out", "effects.jsonl")), "proxy: the tool did NOT run (no effects.jsonl)")
    except Exception as e:  # noqa
        check(False, "proxy end to end", repr(e))
    finally:
        try:
            p.stdin.close()
        except Exception:  # noqa
            pass
        try:
            p.wait(timeout=15)
        except Exception:  # noqa
            p.kill()
        err = p.stderr.read().decode("utf-8", "replace")
        print("--- proxy stderr (tail) ---\n" + err[-1500:], flush=True)

    print("FAILED: %d" % len(FAILS) if FAILS else "ALL OK")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
