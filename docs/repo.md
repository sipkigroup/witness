# What is in this repository

| Path | What | License |
|---|---|---|
| `spec/` | Draft specification of the action receipt (`draft-deus-aar-05`, plus history and errata) and the test vectors (`spec/vectors`) | Apache-2.0 |
| `verifier_js/` | Verifier in JavaScript, written from the spec | Apache-2.0 |
| `verifier_swift/` | Verifier in Swift, written from the spec (source; build with `./build.sh`) | Apache-2.0 |
| `sdk-ts/` | `@deus-witness/sdk` (npm): TypeScript client, no dependencies | Apache-2.0 |
| `python/` | `deus-witness` (PyPI): Python thin client - MCP proxy, Claude Code hook, doctor, SDK. Registry name `io.github.sipkigroup/witness` | Apache-2.0 |
| `contract/` | HTTP API contract (OpenAPI), WebAuthn signing profile, contract stub | Apache-2.0 |
| `plugins/deus-witness/` + `.claude-plugin/marketplace.json` | Claude Code plugin: the hook in one install command | Apache-2.0 |
| `integrations/` | Examples: Vercel AI SDK, curl | Apache-2.0 |
| `docs/` | Teams, recovery, anchors, verifying receipts | Apache-2.0 |

**In this repo, all Apache-2.0 and run locally:** the complete MCP server (`deus-witness-mcp`, a stdio proxy you put in front of any MCP server), the Claude Code hook and plugin, the offline verifiers and the specs.
**Not in this repo:** the hosted Witness API that the MCP server calls, like any API-backed MCP server calls its API (passkey approvals, the signed journal). It is run by the author and is not covered by this license; packs it issues are checked offline with the verifiers here, so you don't have to trust it.
You can implement your own witness from `spec/` and `contract/`.

## Use it

Claude Code: the three commands of [Install](../README.md#install-3-lines-in-claude-code) (the one-step form `/plugin install deus-witness --marketplace sipkigroup/witness` also exists in Claude Code 2.1.275 or later); see [`plugins/deus-witness/README.md`](../plugins/deus-witness/README.md).

The hosted service is at <https://witness.sipkigroup.com>. From TypeScript: `npm install @deus-witness/sdk` (see [`sdk-ts/README.md`](../sdk-ts/README.md)). From Python, or to put any MCP server behind the witness: `pip install deus-witness` (Python 3.10+ in a venv) or, with no install, `uvx deus-witness -- <your MCP server command>` (MCP Registry: `io.github.sipkigroup/witness`; see [`python/README.md`](../python/README.md); setup: <https://witness.sipkigroup.com/dl/docs/quickstart.html>).
Any other language: speak HTTP, see [`contract/openapi.yaml`](../contract/openapi.yaml) and [`integrations/`](../integrations/).

## Verify the receipts yourself

```
python3 spec/vectors/check_vectors.py              # the abstract spec vectors through the reference model of the spec (no dependencies)
(cd verifier_js && npm ci && npm test)             # the same vectors through the JavaScript verifier
(cd verifier_swift && ./build.sh && ./aarc --quiet --extra extra-vectors)
```
If two implementations disagree on a vector, one of them (or the spec) is wrong - please open an issue with the vector.
