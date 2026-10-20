/** Deus Witness SDK (TypeScript). No dependencies: uses fetch (Node >= 18, browsers).
 *  NOTE: receipt (AAR) signature verification is NOT implemented here (planned after 2026-10-25); use the Python SDK `verify_aar`
 *  or the evidence-pack verifiers. Do not treat an `allow` as cryptographically checked on this side. */

export type Verdict = "allow" | "deny" | "defer" | "pass";
export type Status = "pass" | "allowed" | "denied" | "pending_approval" | "held" | "approved" | "refused" | "consumed" | "executed" | "not_executed" | "expired" | string;

export interface ActionBody {
  agent?: string;
  class?: string;
  recipient?: string;
  data?: string[];
  amount?: number;
  currency?: string;
  reversible?: boolean;
  [k: string]: unknown;
}

export interface ActionProof {
  entry_b64: string;
  path_b64: string[];
  checkpoint_b64: string;
  approval: { approved: boolean; envelope_b64: string } | null;
}

export interface ActionResult {
  rid: string;
  verdict: Verdict;
  reason: string;
  status: Status;
  action: ActionBody | null;
  expires: number;
  aar_b64: string | null;
  proof: ActionProof | null;
  approval_url: string | null;
}

export interface PresentResult { result: "accept" | "reject"; reason: string }
export interface ReportResult { result: "released" | "ignored" }
export interface WitnessInfo { iss: string; alg: string; kid_hex: string; pub_hex: string; web_js_sha256: Record<string, string> }
/** 0.2 (ARHITEKTURA-0.2 6): one tool of the MCP server's tools/list. */
export interface CatalogTool { name: string; description?: string; inputSchema?: Record<string, unknown> }
export interface CatalogResult { catalog_sha256: string; n_tools: number; changed: boolean; pass_net_tools?: string[] }
export type CoverageLevel = "C0" | "C1" | "C2" | "C3";
/** 0.2 (5.3): operator-declared coverage, a claim and not a proof. This SDK does not run the doctor: build the report yourself
 *  (or take it from `deus-witness doctor --json`: level = coverage, unwitnessed = bypass[].what). */
export interface CoverageReport { level: CoverageLevel; unwitnessed?: string[]; tool?: string; pass_net_tools?: string[] }
export interface CoverageResult { ok: boolean; level: CoverageLevel }
export interface WitnessOptions { url?: string; key: string; fetch?: typeof fetch }

export class WitnessError extends Error {
  /** retryAfter: seconds from a Retry-After header, if any. */
  constructor(public status: number, public code: string, public detail = "", public retryAfter?: number) {
    super(`${status} ${code} ${detail}`.trim());
    this.name = "WitnessError";
  }
}

export class Witness {
  readonly url: string;
  private key: string;
  private f: typeof fetch;

  constructor(o: WitnessOptions) {
    this.url = (o.url ?? "https://witness.sipkigroup.com").replace(/\/+$/, "");
    this.key = o.key;
    this.f = o.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private async call<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const headers: Record<string, string> = {};
    if (auth) headers["Authorization"] = "Bearer " + this.key;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let r: Response;
    try {
      r = await this.f(this.url + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
      throw new WitnessError(0, "NETWORK", String(e));
    }
    let j: any = null;
    try { j = await r.json(); } catch { /* not JSON */ }
    if (!r.ok) {
      const ra = Number(r.headers?.get?.("retry-after"));
      throw new WitnessError(r.status, String(j?.error ?? "HTTP_ERROR"), String(j?.detail ?? ""), Number.isFinite(ra) && ra >= 0 ? Math.min(ra, 60) : undefined);
    }
    if (j === null) throw new WitnessError(r.status, "BAD_RESPONSE");
    return j as T;
  }

  /** Ask the witness before the agent acts. */
  act(tool: string, args: Record<string, unknown> = {}, client?: { name: string; version: string }): Promise<ActionResult> {
    return this.call("POST", "/v1/actions", client ? { tool, args, client } : { tool, args });
  }

  /** One long poll (waitSeconds 0..25). */
  get(rid: string, waitSeconds = 0): Promise<ActionResult> {
    const w = Math.max(0, Math.min(25, Math.floor(waitSeconds)));
    return this.call("GET", `/v1/actions/${encodeURIComponent(rid)}?wait=${w}`);
  }

  /** Long-poll until the action leaves `pending_approval` or timeoutSeconds pass (then the pending result is returned). */
  async wait(rid: string, timeoutSeconds = 50): Promise<ActionResult> {
    const end = Date.now() + timeoutSeconds * 1000;
    const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, Math.max(0, ms)));
    let pause = 500;
    for (;;) {
      const left = (end - Date.now()) / 1000;
      const t0 = Date.now();
      let res: ActionResult;
      try {
        res = await this.get(rid, Math.min(25, Math.max(1, Math.ceil(left))));   // server-side long poll, never a tight wait=0 loop
      } catch (e) {
        if (!(e instanceof WitnessError) || e.status !== 429) throw e;
        const d = Math.max((e.retryAfter ?? 0) * 1000, pause);
        if (Date.now() + d >= end) throw e;
        await sleep(d); pause = Math.min(pause * 2, 8000);
        continue;
      }
      if (res.status !== "pending_approval" || Date.now() >= end) return res;
      if (Date.now() - t0 < 500) { await sleep(Math.min(pause, end - Date.now())); pause = Math.min(pause * 2, 8000); }   // answered at once: back off
      else pause = 500;
    }
  }

  /** Consume the receipt BEFORE executing the action. */
  present(rid: string): Promise<PresentResult> {
    return this.call("POST", `/v1/actions/${encodeURIComponent(rid)}/present`, {});
  }

  report(rid: string, executed: boolean): Promise<ReportResult> {
    return this.call("POST", `/v1/actions/${encodeURIComponent(rid)}/report`, { executed });
  }

  /** 0.2: send the tools/list of the MCP server (POST /v1/catalog). Only name, description, inputSchema are sent. */
  catalog(tools: CatalogTool[]): Promise<CatalogResult> {
    const body = tools.map((t) => {
      const o: CatalogTool = { name: t.name };
      if (t.description !== undefined) o.description = t.description;
      if (t.inputSchema !== undefined) o.inputSchema = t.inputSchema;
      return o;
    });
    return this.call("POST", "/v1/catalog", { tools: body });
  }

  /** 0.2: declare the coverage level (POST /v1/coverage). Unlike the Python SDK, no doctor runs here: pass the report. */
  coverage(report: CoverageReport): Promise<CoverageResult> {
    return this.call("POST", "/v1/coverage", { tool: "doctor-0.2", ...report });
  }

  witnessInfo(): Promise<WitnessInfo> {
    return this.call("GET", "/v1/witness", undefined, false);
  }
}
