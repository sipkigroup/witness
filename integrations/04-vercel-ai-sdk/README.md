# 04 - Vercel AI SDK tools (TypeScript, `sdk-ts`)

```ts
import { tool } from "ai"; import { z } from "zod";
import { Witness } from "../../sdk-ts/dist/index.js";      // or your copy of @deus-witness/sdk
import { witnessed } from "./witnessed.ts";

const w = new Witness({ url, key });
const sendEmail = tool({
  description: "Send an email",
  inputSchema: z.object({ to: z.string(), subject: z.string(), body: z.string() }),
  execute: witnessed(w, "send_email", async (a) => doSend(a)),
});
```
`witnessed` returns the same strings as the other integrations (`Blocked by Deus Witness: ...`, `Held for owner approval at ...`).

**The TypeScript SDK does not verify the receipt signature** (sdk-ts/README.md; planned after 2026-10-25). `witnessed.ts` therefore checks only what it can: the decided action carries `args_sha256` of exactly the call about to run.
If you need a cryptographic check on the agent side today, use the Python SDK.

## Test
`npm install` (pins `ai@5.0.0`, `zod`), then `pytest -q .`. Python starts the witness and signs approvals; `run.ts` (Node >= 22.18 strips types) runs `generateText` with `MockLanguageModelV2` and prints what the tools returned and which side effects really ran.
Also checks that non-ASCII arguments hash identically on both sides.
