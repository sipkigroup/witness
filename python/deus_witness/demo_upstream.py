"""Demo MCP server (stdio). Nothing real happens: every tool call appends one line to $DEUS_DEMO_OUT/effects.jsonl."""
import json
import os
import time
from typing import Annotated

from pydantic import Field

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("deus-demo-tools")


def _effect(tool: str, args: dict) -> None:
    out = os.environ.get("DEUS_DEMO_OUT") or os.getcwd()
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "effects.jsonl"), "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"t": time.time(), "tool": tool, "args": args}, ensure_ascii=False) + "\n")


@mcp.tool()
def send_email(
    to: Annotated[str, Field(description="Recipient email address, e.g. alice@example.com. Free text in this demo; nothing is validated or sent.")],
    subject: Annotated[str, Field(description="Subject line, plain text.")],
    body: Annotated[str, Field(description="Message body, plain text.")],
) -> str:
    """Send an email. Demo tool: no mail leaves the machine; the call is only appended as one line to $DEUS_DEMO_OUT/effects.jsonl and a confirmation string is returned. Use it to see how the witness decides on a call with an outside effect (allow, deny or defer to the owner); use read_file instead for a call without one. Needs no credentials."""
    _effect("send_email", {"to": to, "subject": subject, "body": body})
    return "email to %s queued (demo)" % to


@mcp.tool()
def purchase(
    vendor: Annotated[str, Field(description="Name of the vendor to pay, free text, e.g. acme-store.")],
    amount_cents: Annotated[int, Field(description="Amount in integer cents (1999 means 19.99). The mandate can cap this value.")],
) -> str:
    """Record a purchase of the given amount at a vendor. Demo tool: no money moves and nothing is bought; the call is only appended as one line to $DEUS_DEMO_OUT/effects.jsonl. Use it to see how a witness mandate with a spending limit allows, denies or defers a call. Needs no credentials."""
    _effect("purchase", {"vendor": vendor, "amount_cents": amount_cents})
    return "purchase of %d cents at %s recorded (demo)" % (amount_cents, vendor)


@mcp.tool()
def delete_resource(
    resource: Annotated[str, Field(description="Identifier of the resource to delete, free text, e.g. db/orders-2025.")],
) -> str:
    """Delete a named resource. Demo tool: nothing is deleted; the call is only appended as one line to $DEUS_DEMO_OUT/effects.jsonl. It stands for a destructive action that a mandate would normally hold for the owner's approval. Needs no credentials."""
    _effect("delete_resource", {"resource": resource})
    return "resource %s deleted (demo)" % resource


@mcp.tool()
def publish(
    channel: Annotated[str, Field(description="Name of the channel to post to, free text, e.g. #announcements.")],
    text: Annotated[str, Field(description="Text to post, plain text.")],
) -> str:
    """Publish text to a channel. Demo tool: nothing is posted anywhere; the call is only appended as one line to $DEUS_DEMO_OUT/effects.jsonl. It stands for an outward, public action. Needs no credentials."""
    _effect("publish", {"channel": channel, "text": text})
    return "published to %s (demo)" % channel


@mcp.tool()
def read_file(
    path: Annotated[str, Field(description="Path of the file to read, free text, e.g. /tmp/notes.txt. The file is never opened.")],
) -> str:
    """Read a file. Demo tool: reads nothing from disk and returns the fixed text 'demo contents of <path>'; the call is only appended as one line to $DEUS_DEMO_OUT/effects.jsonl. A read-only call, so a witness usually lets it pass. Needs no credentials."""
    _effect("read_file", {"path": path})
    return "demo contents of %s" % path


HELP = """usage: deus-witness-demo-tools
Demo MCP server over stdio (tools: send_email, read_file, ...). Takes no arguments; nothing real happens,
every call is appended to $DEUS_DEMO_OUT/effects.jsonl.
example: deus-witness-mcp -- deus-witness-demo-tools
exit: 0 for -h / --help; 2 for any other argument
"""


def main(argv=None) -> None:
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        if argv in (["-h"], ["--help"]):
            sys.stdout.write(HELP)
            sys.exit(0)
        sys.stderr.write("deus-witness-demo-tools: unknown argument %r (see --help)\n" % argv[0])
        sys.exit(2)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
