# @deus-witness/sdk (TypeScript)

Zero dependencies, `fetch` (Node >= 18 and browsers). Build: `npx -y -p typescript@5 tsc` -> `dist/index.js` + `dist/index.d.ts`.

```ts
import { Witness } from "./dist/index.js";
const w = new Witness({ url: "https://witness.sipkigroup.com", key: "dwk_..." });
const r = await w.act("send_email", { to: "bob@acme.example", subject: "hi", body: "..." });
if (r.verdict === "allow" && (await w.present(r.rid)).result === "accept") { /* act */ await w.report(r.rid, true); }
if (r.verdict === "defer") { const r2 = await w.wait(r.rid, 50); }
```
Methods: `act`, `get`, `wait`, `present`, `report`, `witnessInfo`; 0.2: `catalog(tools)` (POST /v1/catalog, the MCP tools/list)
and `coverage(report)` (POST /v1/coverage). Errors: `WitnessError(status, code)`.

```ts
await w.catalog([{ name: "send_email", description: "...", inputSchema: { type: "object", properties: { to: { type: "string" } } } }]);
await w.coverage({ level: "C1", unwitnessed: ["Bash (Claude Code built-in, allowed)"] });
```
`coverage` here does NOT run the doctor (the Python SDK `Witness.coverage()` does): you pass the report, e.g. from
`deus-witness doctor --no-network --json` (`level` = `coverage`, `unwitnessed` = `bypass[].what`). The level is a claim of the
operator, not a proof. A `held` status (held by the advisor, 0.2) behaves like `pending_approval`: `wait` does not loop on it, poll `get`.

IMPORTANT: this SDK does NOT verify the receipt (AAR) signature. That is planned after 25.10.2026. Until then use the Python SDK
(`deus_witness.verify_aar`) or the offline evidence-pack verifiers if you need cryptographic checks on the agent side.

Test: `npm test` = `node test/smoke.mjs && node test/wait.mjs && node test/catalog.mjs` (each starts the contract stub itself
— `catalog.mjs` the 0.2 stub — and stops it by PID).
