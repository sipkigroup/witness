// Runs the Vercel AI SDK `generateText` loop with a SCRIPTED model (MockLanguageModelV2: no network, no key) against a real witness.
// usage: node run.ts '<json [[tool, args], ...]>'   env: DW_URL, DW_KEY, DW_WAIT (seconds, default 1)
// prints {"outputs": {toolCallId: output}, "effects": [...]} -- what the tools returned and what REALLY ran.
import { generateText, stepCountIs, tool } from "ai";
import { MockLanguageModelV2 } from "ai/test";
import { z } from "zod";
import { Witness } from "../../sdk-ts/dist/index.js";
import { witnessed } from "./witnessed.ts";

const w = new Witness({ url: process.env.DW_URL!, key: process.env.DW_KEY! });
const wait = Number(process.env.DW_WAIT ?? "1");
const effects: unknown[] = [];

const tools = {
  send_email: tool({
    description: "Send an email",
    inputSchema: z.object({ to: z.string(), subject: z.string(), body: z.string() }),
    execute: witnessed(w, "send_email", (a) => { effects.push(["send_email", a.to]); return `sent to ${a.to}`; }, wait),
  }),
  purchase: tool({
    description: "Buy something",
    inputSchema: z.object({ vendor: z.string(), amount_cents: z.number().int() }),
    execute: witnessed(w, "purchase", (a) => { effects.push(["purchase", a.amount_cents]); return `bought ${a.amount_cents}`; }, wait),
  }),
  publish: tool({
    description: "Publish a post",
    inputSchema: z.object({ channel: z.string(), text: z.string() }),
    execute: witnessed(w, "publish", (a) => { effects.push(["publish", a.channel]); return "published"; }, wait),
  }),
  read_file: tool({
    description: "Read a file",
    inputSchema: z.object({ path: z.string() }),
    execute: witnessed(w, "read_file", (a) => { effects.push(["read_file", a.path]); return `contents of ${a.path}`; }, wait),
  }),
};

const calls: [string, Record<string, unknown>][] = JSON.parse(process.argv[2]);
let turn = 0;
const usage = { inputTokens: 1, outputTokens: 1, totalTokens: 2 };
const model = new MockLanguageModelV2({
  doGenerate: async () =>
    ++turn === 1
      ? { content: calls.map(([n, a], i) => ({ type: "tool-call" as const, toolCallId: `c${i}`, toolName: n, input: JSON.stringify(a) })), finishReason: "tool-calls" as const, usage, warnings: [] }
      : { content: [{ type: "text" as const, text: "done" }], finishReason: "stop" as const, usage, warnings: [] },
});

const res = await generateText({ model, tools, prompt: "go", stopWhen: stepCountIs(3) });
const outputs: Record<string, unknown> = {};
for (const s of res.steps) for (const r of s.toolResults) outputs[r.toolCallId] = r.output;
console.log(JSON.stringify({ outputs, effects }));
