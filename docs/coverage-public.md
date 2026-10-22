# What the witness sees - and what it does not

Deus Witness judges the tool calls that are sent to it: through the MCP proxy, the Claude Code hook, or the SDK. Each judged call gets a verdict (allow, deny, hold for your approval) and a signed receipt. It is a checkpoint, not a monitor.

## What Witness protects
- **Deletion** - deleting or overwriting data is judged against what your mandate allows; irreversible deletes are held for you.
- **Sending data out** - messages, uploads and publishing go only to recipients and channels you listed.
- **Secrets** - API keys, credentials and data you marked as closed are not allowed to leave in the text of a call.
- **Money** - purchases are checked against the budget and per-purchase limit you signed.
- **Commands outside what you allowed** - shell commands that your mandate does not cover are held for your approval, and clearly dangerous ones are always asked about.
- **Changes to the project's own executable files** - a command that runs files the agent has just changed is held for your approval.

Every decision is written to a signed, append-only ledger that you or an outsider can re-check offline.

## What Witness does NOT do
- **It is not a sandbox.** It does not stop a process; it decides on calls that are shown to it.
- **It sees only what goes through the hook, the MCP proxy or the SDK.** Another tool server, a built-in tool you did not route, a direct network call or code the agent runs on its own leaves no receipt.
- **It does not read intent.** Content checks are deterministic and can be evaded by rewording; the recipient list is the stronger barrier.
- **A coverage level is the operator's own statement**, not something Witness verifies.
- **It cannot make an approval screen honest by itself**: you trust the page you sign on; its script hashes are published on the home page.
- **It is as independent as its operator.** At this stage the operator is the author of the project.

To close the gaps, route every tool through Witness, deny other executing tools in the client, and run the agent in a sandbox. See also the Concepts page for what is proven and what is not.
