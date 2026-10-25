# Deus Witness

**A witness service for AI-agent tool calls.** Your agent asks before it acts; a witness outside the agent
checks the call against a mandate you signed, and answers `allow`, `deny` or `defer` (wait for you). Every answer is a signed,
append-only, independently verifiable receipt - so "what did the agent do, and who allowed it" has an answer you do not have to take on trust.

- Hosted service: <https://witness.sipkigroup.com> - live demo: <https://witness.sipkigroup.com/demo>
- This repository: the open parts - the receipt specification, two separate verifiers, the TypeScript client, the Python client and the HTTP API contract (OpenAPI, data only).

> **Status: early (0.x).** The specification is an individual draft in `spec/` (not an IETF standard, not submitted to the IETF).
> The evidence so far is our own simulations and separate implementations written from the spec by one author; there are no external audits or deployments yet.
> Treat it as something to test and attack, not as a certified security boundary. Reports of bypasses are the most valuable thing you can send us.

## Try it (Claude Code, needs `uv` or `pip install deus-witness`)

```
/plugin marketplace add sipkigroup/witness
/plugin install deus-witness@sipkigroup
/deus-witness:try
```

`try` makes a trial account and opens a page in your browser. The first tool call that needs you waits; the page asks for two passkey touches (one makes your passkey, one signs the recommended rules), then that call is decided - allowed, refused, or shown to you for one more touch. Until your first touch every call waits. A trial account you do not keep is erased after 7 days. Without the plugin: `deus-witness try`.

## What is here

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
Claude Code: the three commands above (the one-step form `/plugin install deus-witness --marketplace sipkigroup/witness` also exists in Claude Code 2.1.275 or later); see [`plugins/deus-witness/README.md`](plugins/deus-witness/README.md).

The hosted service is at <https://witness.sipkigroup.com>. From TypeScript: `npm install @deus-witness/sdk` (see [`sdk-ts/README.md`](sdk-ts/README.md)). From Python, or to put any MCP server behind the witness: `pip install deus-witness` or, with no install, `uvx deus-witness -- <your MCP server command>` (MCP Registry: `io.github.sipkigroup/witness`; see [`python/README.md`](python/README.md); setup: <https://witness.sipkigroup.com/dl/docs/quickstart.html>).
Any other language: speak HTTP, see [`contract/openapi.yaml`](contract/openapi.yaml) and [`integrations/`](integrations/).

## Honest limits
- A witness cannot know what an action *really* does beyond what the tool map and the operator's description say; it checks the call against your mandate. Routes that do not go through the witness are not covered.
- The TypeScript client does **not** verify receipt signatures yet (the verifiers here do). Do not treat an `allow` seen through it as cryptographically checked.
- If the witness is unreachable, calls should be blocked (fail closed). That is a safety choice that costs availability.

## Verify the receipts yourself

```
python3 spec/vectors/check_vectors.py              # the abstract spec vectors through the reference model of the spec (no dependencies)
(cd verifier_js && npm ci && npm test)             # the same vectors through the JavaScript verifier
(cd verifier_swift && ./build.sh && ./aarc --quiet --extra extra-vectors)
```
If two implementations disagree on a vector, one of them (or the spec) is wrong - please open an issue with the vector.

## Security, contributing, license
- Vulnerabilities: [`SECURITY.md`](SECURITY.md) (support@sipkigroup.com). Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Apache License 2.0 ([`LICENSE`](LICENSE), [`NOTICE`](NOTICE)). Copyright 2026 Sipki LLC.
