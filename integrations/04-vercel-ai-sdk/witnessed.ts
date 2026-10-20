// Wrap a Vercel AI SDK tool `execute` with the Deus Witness (sdk-ts). Same protocol as the Python decorator / MCP proxy.
//   pass -> run; allow -> present (consume receipt) -> run -> report; deny -> NOT run; defer -> wait, else "Held for owner approval ...".
// The TS SDK does not verify the receipt signature (documented in sdk-ts/README.md). What we CAN and do check here is the binding:
// the action the witness decided on must carry args_sha256 of exactly the call we are about to run.
import { createHash } from "node:crypto";
import { Witness, WitnessError } from "../../sdk-ts/dist/index.js";

function canon(v: unknown): string {          // json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canon(o[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}
export const argsSha256 = (tool: string, args: unknown): string => createHash("sha256").update(canon([tool, args])).digest("hex");

const blocked = (reason: string, rid = "none") => `Blocked by Deus Witness: ${reason} (receipt ${rid})`;

export function witnessed<A extends Record<string, unknown>, R>(w: Witness, tool: string, run: (args: A) => Promise<R> | R, waitSeconds = 50) {
  return async (args: A): Promise<R | string> => {
    try {
      let r = await w.act(tool, args, { name: "witnessed-vercel-ai", version: "0.1.3" });
      const end = Date.now() + waitSeconds * 1000;
      while (r.verdict === "defer" && r.status === "pending_approval" && Date.now() < end) {
        // whole-second long polls; Witness.wait() floors the last fraction of a second to 0 and spins (see OTCHET)
        r = await w.get(r.rid, Math.max(1, Math.min(25, Math.ceil((end - Date.now()) / 1000))));
      }
      if (r.verdict === "pass") return await run(args);
      if (r.verdict === "allow" && (r.status === "allowed" || r.status === "approved")) {
        if ((r.action as any)?.args_sha256 !== argsSha256(tool, args)) return blocked("REQUEST_MISMATCH", r.rid);
        if ((await w.present(r.rid)).result !== "accept") return blocked("NOT_ACCEPTED", r.rid);   // consume BEFORE acting
        try {
          const out = await run(args);
          await w.report(r.rid, true);
          return out;
        } catch (e) {
          await w.report(r.rid, false);
          throw e;
        }
      }
      if (r.verdict === "defer" && r.status === "pending_approval") return `Held for owner approval at ${r.approval_url}. Retry the same call after approval.`;
      return blocked(r.verdict === "deny" ? r.reason : r.status === "refused" ? "APPROVAL_REFUSED" : r.status === "expired" ? "RECEIPT_EXPIRED" : r.reason || r.status, r.rid);
    } catch (e) {
      if (e instanceof WitnessError) return blocked(`WITNESS_UNAVAILABLE ${e.code}`);   // fail closed
      throw e;
    }
  };
}
