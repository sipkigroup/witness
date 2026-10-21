"""Demo MCP server (stdio). Nothing real happens: every tool call appends one line to $DEUS_DEMO_OUT/effects.jsonl."""
import json
import os
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("deus-demo-tools")


def _effect(tool: str, args: dict) -> None:
    out = os.environ.get("DEUS_DEMO_OUT") or os.getcwd()
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "effects.jsonl"), "a") as f:
        f.write(json.dumps({"t": time.time(), "tool": tool, "args": args}, ensure_ascii=False) + "\n")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email (demo: only recorded)."""
    _effect("send_email", {"to": to, "subject": subject, "body": body})
    return "email to %s queued (demo)" % to


@mcp.tool()
def purchase(vendor: str, amount_cents: int) -> str:
    """Buy something (demo: only recorded)."""
    _effect("purchase", {"vendor": vendor, "amount_cents": amount_cents})
    return "purchase of %d cents at %s recorded (demo)" % (amount_cents, vendor)


@mcp.tool()
def delete_resource(resource: str) -> str:
    """Delete a resource (demo: only recorded)."""
    _effect("delete_resource", {"resource": resource})
    return "resource %s deleted (demo)" % resource


@mcp.tool()
def publish(channel: str, text: str) -> str:
    """Publish text to a channel (demo: only recorded)."""
    _effect("publish", {"channel": channel, "text": text})
    return "published to %s (demo)" % channel


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file (demo: returns fixed text, reads nothing)."""
    _effect("read_file", {"path": path})
    return "demo contents of %s" % path


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
