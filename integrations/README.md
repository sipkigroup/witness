# Deus Witness integration examples

Minimal examples of calling a witness from your own agent code. They show the protocol; they are not tested here
(the tests need the closed Witness server).

| # | Example | Language |
|---|---------|----------|
| 04 | [Vercel AI SDK](04-vercel-ai-sdk/) with `sdk-ts` | TypeScript |
| 05 | [HTTP / curl](05-http-curl/) | shell |

## Verdicts you will see
| verdict | meaning | what the integration does |
|---|---|---|
| `pass` | tool class `pass` (declared harmless), no receipt | forwards |
| `allow` | inside the mandate; signed receipt (AAR) | `present` (consume), run, `report` |
| `deny` | outside the mandate or tool not mapped | tool is **not** called; the model gets `Blocked by Deus Witness: <REASON> (receipt <rid>)` |
| `defer` | needs the owner (passkey approval of this exact call) | `Held for owner approval at <url>`; after approval the same call returns `allow` |

`04-vercel-ai-sdk/witnessed.ts` implements this protocol for any TypeScript function; copy it.
The wire format is in [`../contract/openapi.yaml`](../contract/openapi.yaml).
