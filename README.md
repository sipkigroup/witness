# Deus Witness

**An independent witness for AI-agent tool calls.** Your agent asks before it acts; a witness that is *not* the agent's operator
checks the call against a mandate you signed, and answers `allow`, `deny` or `defer` (wait for you). Every answer is a signed,
append-only, independently verifiable receipt - so "what did the agent do, and who allowed it" has an answer you do not have to take on trust.

- Hosted service: <https://witness.sipkigroup.com> - live demo: <https://witness.sipkigroup.com/demo>
- This repository: the open parts - the receipt specification, two independent verifiers, the TypeScript client and the HTTP API contract (OpenAPI, data only).

> **Status: early (0.x).** The specification is an unpublished individual draft (not an IETF standard, not submitted anywhere).
> The evidence so far is our own simulations and independent implementations written inside one project; there are no external audits or deployments yet.
> Treat it as something to test and attack, not as a certified security boundary. Reports of bypasses are the most valuable thing you can send us.

## What is here

| Path | What | License |
|---|---|---|
| `spec/` | Draft specification of the action receipt (`draft-deus-aar-05`, plus history and errata) and the test vectors (`spec/vectors`) | Apache-2.0 |
| `verifier_js/` | Independent clean-room verifier in JavaScript | Apache-2.0 |
| `verifier_swift/` | Independent clean-room verifier in Swift (source; build with `./build.sh`) | Apache-2.0 |
| `sdk-ts/` | `@deus-witness/sdk` (npm): TypeScript client, no dependencies | Apache-2.0 |
| `contract/` | HTTP API contract (OpenAPI), WebAuthn signing profile, contract stub | Apache-2.0 |
| `integrations/` | Examples: Vercel AI SDK, curl | Apache-2.0 |
| `docs/` | Teams, recovery, anchors, verifying receipts | Apache-2.0 |

**Not here:** the Witness cloud service (server, web app, deployment). It is not open source. The hosted service is offered under separate
Terms of Use published on the website (not part of this license).
You can implement your own witness from `spec/` and `contract/`.

## Use it
The hosted service is at <https://witness.sipkigroup.com>. From TypeScript: `npm install @deus-witness/sdk` (see [`sdk-ts/README.md`](sdk-ts/README.md)).
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
