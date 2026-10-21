"""deus-witness doctor: where can the agent go around the witness.

  deus-witness doctor [--json] [--no-network] [--project DIR]

Reads client configs ONLY (never writes): Claude Desktop, Claude Code (~/.claude.json, ~/.claude/settings.json, project .mcp.json,
.claude/settings.json, .claude/settings.local.json), Cursor (~/.cursor/mcp.json). A MCP server is "behind the proxy" when its
`command` is deus-witness-mcp. Prints `coverage: C0|C1|C2|C3` and `bypass: <what> -> <how to close>`; rc 0 for C2/C3, 2 for C0/C1.
The level is a claim of the operator made from local files, not a proof. --no-network: no socket is opened (the proxy runs this
light part at start and sends it as POST /v1/coverage)."""
import argparse
import json
import os
import socket
import sys

TOOL = "doctor-0.2"
PROXY_CMD = "deus-witness-mcp"
BUILTINS = ("Bash", "Write", "Edit", "WebFetch")          # Claude Code built-in executing tools (5.1, 5.3)
EGRESS = (("1.1.1.1", 443), ("example.com", 443))
CLAIM = "operator-declared: a claim made from local client configs, not a proof"
HOW_DENY = 'add "%s" to permissions.deny in ~/.claude/settings.json (or the project .claude/settings.json)'


def _home() -> str:
    return os.environ.get("HOME") or os.path.expanduser("~")


def desktop_paths(home: str) -> list:
    """Claude Desktop config: macOS, Windows (%APPDATA%), Linux."""
    p = [os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
         os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"), "Claude", "claude_desktop_config.json")]
    if os.environ.get("APPDATA"):
        p.append(os.path.join(os.environ["APPDATA"], "Claude", "claude_desktop_config.json"))
    return p


def _read(path: str):
    """-> (data, error). Read only; a missing file is (None, None)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(4 * 1024 * 1024)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, type(e).__name__
    try:
        d = json.loads(raw.decode("utf-8-sig"))
    except ValueError:
        return None, "NOT_JSON"
    return (d, None) if isinstance(d, dict) else (None, "NOT_OBJECT")


def is_proxied(spec) -> bool:
    if not isinstance(spec, dict) or not isinstance(spec.get("command"), str):
        return False
    base = os.path.basename(spec["command"].replace("\\", "/"))
    return base in (PROXY_CMD, PROXY_CMD + ".exe", PROXY_CMD + ".cmd")


def _servers(d: dict) -> dict:
    s = d.get("mcpServers") if isinstance(d, dict) else None
    return s if isinstance(s, dict) else {}


def _deny_rules(d: dict) -> list:
    p = d.get("permissions") if isinstance(d, dict) else None
    deny = p.get("deny") if isinstance(p, dict) else None
    return [x for x in deny if isinstance(x, str)] if isinstance(deny, list) else []


def _denied_fully(tool: str, rules: list) -> bool:
    """A rule closes the tool only when it is the whole tool: "Bash", "Bash(*)" or "Bash(**)"; "Bash(rm:*)" is a partial deny."""
    return any(r.strip() in (tool, tool + "()", tool + "(*)", tool + "(**)") for r in rules)


def collect(home: str = None, project: str = None) -> dict:
    """Read every known config. -> {configs:[{client, kind, path, error}], servers:[{client, path, name, proxied, remote}],
    claude_code: bool, cursor: bool, deny: [rules]}."""
    home = home or _home()
    project = os.path.abspath(project or os.getcwd())
    out = {"configs": [], "servers": [], "claude_code": False, "cursor": False, "deny": []}

    def add(client, kind, path):
        d, err = _read(path)
        if d is None and err is None:
            return None
        out["configs"].append({"client": client, "kind": kind, "path": path, "error": err})
        return d or {}

    def servers(client, path, srv):
        for name, spec in sorted(srv.items()):
            remote = isinstance(spec, dict) and not spec.get("command") and bool(spec.get("url") or spec.get("type") in ("http", "sse"))
            out["servers"].append({"client": client, "path": path, "name": str(name), "proxied": is_proxied(spec), "remote": remote})

    seen = set()
    for p in desktop_paths(home):
        if p in seen:
            continue
        seen.add(p)
        d = add("claude-desktop", "mcp", p)
        if d is not None:
            servers("claude-desktop", p, _servers(d))

    p = os.path.join(home, ".claude.json")
    d = add("claude-code", "user-state", p)
    if d is not None:
        out["claude_code"] = True
        servers("claude-code", p, _servers(d))
        prj = d.get("projects")
        if isinstance(prj, dict) and isinstance(prj.get(project), dict):
            servers("claude-code", p + " [projects." + project + "]", _servers(prj[project]))
    read = set()
    for kind, p in (("user-settings", os.path.join(home, ".claude", "settings.json")),
                    ("project-mcp", os.path.join(project, ".mcp.json")),
                    ("project-settings", os.path.join(project, ".claude", "settings.json")),
                    ("project-settings-local", os.path.join(project, ".claude", "settings.local.json"))):
        if os.path.abspath(p) in read:      # project == HOME: the project .claude/settings.json IS the user one, read once
            continue
        read.add(os.path.abspath(p))
        d = add("claude-code", kind, p)
        if d is not None:
            out["claude_code"] = True
            servers("claude-code", p, _servers(d))
            out["deny"] += _deny_rules(d)

    p = os.path.join(home, ".cursor", "mcp.json")
    d = add("cursor", "mcp", p)
    if d is not None:
        out["cursor"] = True
        servers("cursor", p, _servers(d))
    return out


def probe_egress(timeout: float = 3.0) -> list:
    """-> [(host:port, reachable)]. Only called without --no-network."""
    res = []
    for host, port in EGRESS:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            res.append(("%s:%d" % (host, port), True))
        except (OSError, Exception):    # noqa: BLE001  any failure = no egress
            res.append(("%s:%d" % (host, port), False))
    return res


def diagnose(home: str = None, project: str = None, network: bool = True, pass_net_tools=None, in_proxy: bool = False) -> dict:
    """The doctor as a function. pass_net_tools: names of pass tools with a network effect (the proxy gets them from POST /v1/catalog);
    None = not known here. in_proxy: called by a running deus-witness-mcp (so a proxy IS in place even if no config shows it)."""
    c = collect(home, project)
    bypass = []
    unproxied = [s for s in c["servers"] if not s["proxied"]]
    proxied = [s for s in c["servers"] if s["proxied"]]
    for s in unproxied:
        if s["remote"]:
            how = "remove it, or run it through a local stdio bridge behind deus-witness-mcp"
        else:
            how = 'wrap it: "command": "deus-witness-mcp", "args": ["--", <old command>, <old args>...] in %s' % s["path"]
        bypass.append({"kind": "mcp", "what": "MCP server %s (%s) not behind deus-witness-mcp" % (s["name"], s["client"]), "how": how})
    if c["claude_code"]:
        for t in BUILTINS:
            if not _denied_fully(t, c["deny"]):
                bypass.append({"kind": "builtin", "what": "%s (Claude Code built-in, allowed)" % t, "how": HOW_DENY % t})
    if c["cursor"]:
        bypass.append({"kind": "builtin", "what": "Cursor agent built-in terminal/edit tools (not controlled by ~/.cursor/mcp.json)",
                       "how": "turn off the agent terminal and auto-run in Cursor settings, or run the agent in the sandbox (deploy/sandbox)"})
    for t in sorted(set(pass_net_tools or [])):
        bypass.append({"kind": "pass-net", "what": "pass tool %s has a network effect the witness does not see" % t,
                       "how": "give it a class (message/publish/...) in the agent toolmap, or forbid the tool"})
    if pass_net_tools is None:
        notes = ["pass tools with a network effect are checked by deus-witness-mcp at start (agent toolmap), not here"]
    else:
        notes = []
    if not proxied and in_proxy:
        bypass.append({"kind": "config", "what": "the client config that started this proxy is not among the configs read",
                       "how": "run `deus-witness doctor` in the agent working directory and put every MCP server behind deus-witness-mcp"})
    if not proxied and not in_proxy:
        level = "C0"
    elif bypass:
        level = "C1"
    else:
        level = "C2"
    c3 = []
    shell = os.path.exists("/bin/sh")
    if shell:
        c3.append({"what": "shell /bin/sh present", "how": "run the agent in the sandbox image without a shell (deploy/sandbox)"})
    egress = None
    if network:
        egress = probe_egress()
        for hp, ok in egress:
            if ok:
                c3.append({"what": "egress to %s open" % hp, "how": "egress proxy with an allow list (model API, witness, tool hosts)"})
    else:
        c3.append({"what": "egress not probed (--no-network)", "how": "run `deus-witness doctor` without --no-network"})
    if level == "C2" and not c3:
        level = "C3"
    return {"coverage": level, "operator_declared": True, "claim": CLAIM, "tool": TOOL, "network": network,
            "configs": c["configs"], "servers": c["servers"], "deny": c["deny"], "bypass": bypass,
            "c3_gaps": c3 if level in ("C2", "C3") else [], "notes": notes,
            "checks": {"shell": shell, "egress": [{"to": hp, "open": ok} for hp, ok in egress] if egress is not None else None}}


def coverage_body(r: dict, pass_net_tools=None) -> dict:
    """The POST /v1/coverage body from a diagnose() result."""
    return {"level": r["coverage"], "unwitnessed": [b["what"] for b in r["bypass"]], "tool": TOOL, "pass_net_tools": sorted(set(pass_net_tools or []))}


def rc_of(level: str) -> int:
    return 0 if level in ("C2", "C3") else 2


def render(r: dict) -> str:
    lines = ["deus-witness doctor (%s, %s)" % (TOOL, "no network" if not r["network"] else "with network probes"),
             "note: coverage level is %s" % r["claim"]]
    if r["configs"]:
        lines.append("configs read (read only):")
        for c in r["configs"]:
            lines.append("  %s %s %s%s" % (c["client"], c["kind"], c["path"], " (%s)" % c["error"] if c["error"] else ""))
    else:
        lines.append("configs read: none found (Claude Desktop, Claude Code, Cursor)")
    for s in r["servers"]:
        lines.append("  mcp %s/%s: %s" % (s["client"], s["name"], "behind deus-witness-mcp" if s["proxied"] else "NOT behind the proxy"))
    lines.append("coverage: %s" % r["coverage"])
    if r["coverage"] == "C0":
        lines.append("bypass: everything (no MCP server behind deus-witness-mcp) -> put your MCP servers behind deus-witness-mcp (see README)")
    for b in r["bypass"]:
        lines.append("bypass: %s -> %s" % (b["what"], b["how"]))
    for g in r["c3_gaps"]:
        lines.append("c3-gap: %s -> %s" % (g["what"], g["how"]))
    for n in r["notes"]:
        lines.append("note: %s" % n)
    return "\n".join(lines)


SUBCOMMANDS = ("doctor",)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deus-witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("doctor", help="where can the agent go around the witness (reads configs, changes nothing)")
    d.add_argument("--json", action="store_true")
    d.add_argument("--no-network", action="store_true", help="no network probes (no socket is opened)")
    d.add_argument("--project", default=None, help="project directory (default: current)")
    o = ap.parse_args(argv)
    r = diagnose(project=o.project, network=not o.no_network)
    print(json.dumps(r, indent=1, ensure_ascii=False) if o.json else render(r))
    return rc_of(r["coverage"])


def cli() -> None:
    argv = sys.argv[1:]
    # `uvx deus-witness -- <upstream...>` (MCP Registry launch form): same as `deus-witness-mcp -- <upstream...>`.
    # Only when "--" is present and the first argument is not a known subcommand; without "--" the doctor is unchanged.
    if "--" in argv and argv[0] not in SUBCOMMANDS:
        from .proxy import main as proxy_main
        proxy_main(argv)
        return
    sys.exit(main())


if __name__ == "__main__":
    cli()
