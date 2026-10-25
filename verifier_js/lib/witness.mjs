// Abstract witness + tool simulator for `sequence` vectors (§§6.6, 6.7, 7, 8.4, 5.3).
// State is ALWAYS re-derived from the ledger (§7.2): there is no per-instance memory,
// so `restart` and multiple `instance` values cannot change any result by construction.
import { evaluate, riskOf } from './evaluate.mjs';
import { permWellFormed as httpPermWellFormed } from './httpcanon.mjs';

export const DEFAULT_TTL = 300; // NOT in the spec (AMBIGUITY-6). Chosen = only ttl value seen in vectors.
const DEFAULT_CEILING_WINDOW = 86400; // NOT in the spec for register_ceiling without window (AMBIGUITY-9).

export class Witness {
  constructor(pinnedKey) {
    this.pinned = pinnedKey;
    this.ledger = [];      // abstract entries {type, t, body}
    this.clock = null;     // monotonic witness clock (null until a clock op)
    this.accepted = new Set(); // tool-side replay store (§8.4 check 6)
  }
  now(actionT) {
    // §5.3: witness clock, never the agent's time. Abstract vectors without a
    // clock op use action.t as the witness clock reading (index.json "units").
    if (this.clock === null) return actionT ?? 0;
    return this.clock;
  }
  append(type, t, body) { this.ledger.push({ seq: this.ledger.length, type, t, body }); }

  // ---- state derived from ledger ----
  mandates() { const m = new Map(); for (const e of this.ledger) if (e.type === 'MANDATE') m.set(e.body.mandate.id, e.body.mandate); return m; }
  revoked(id) { return this.ledger.some((e) => e.type === 'REVOCATION' && e.body.mandate === id); }
  ceiling() { let c = null; for (const e of this.ledger) if (e.type === 'CEILING') c = e.body; return c; }
  reservations() {
    const r = new Map();
    for (const e of this.ledger) {
      if (e.type === 'RECEIPT' && e.body.reserved) r.set(e.body.id, { id: e.body.id, mandate: e.body.mandate, amount: e.body.action.amount, t: e.t, expires: e.body.expires, state: 'active' });
      if (e.type === 'CONSUME' && r.has(e.body.receipt)) r.get(e.body.receipt).state = 'consumed';
      if (e.type === 'RELEASE' && r.has(e.body.receipt)) r.get(e.body.receipt).state = 'released';
    }
    return r;
  }
  receipt(id) { let x = null; for (const e of this.ledger) if (e.type === 'RECEIPT' && e.body.id === id) x = { ...e.body }; if (!x) return null;
    for (const e of this.ledger) if (e.type === 'APPROVAL' && e.body.receipt === id) x.verdict = 'allow';
    return x; }
  committed(t, filter, window) {
    let s = 0;
    for (const r of this.reservations().values()) {
      if (!filter(r)) continue;
      if (r.state === 'released') continue;
      if (r.t > t - window && r.t <= t) s += Number(r.amount);
    }
    return s;
  }
  // §7.4 (b): first operation after now > expires releases unpresented reservations.
  expireSweep(now) {
    for (const r of this.reservations().values()) {
      if (r.state === 'active' && r.expires !== undefined && now > r.expires && !this.accepted.has(r.id))
        this.append('RELEASE', now, { receipt: r.id, cause: 'expired' });
    }
  }

  // ---- ops ----
  op(o) {
    switch (o.op) {
      case 'register_mandate': {
        if (o.signed_by !== this.pinned) return { result: 'reject', reason: 'KEY_MISMATCH' }; // §4.2, no state change
        if (o.mandate?.permissions && !httpPermWellFormed(o.mandate.permissions.http)) return { result: 'reject', reason: 'MANDATE_MALFORMED' };   // PROPOSAL-08-http PH-3
        this.append('MANDATE', this.now(), { mandate: o.mandate });
        return { result: 'accept' };
      }
      case 'register_ceiling': {
        if (o.signed_by !== this.pinned) return { result: 'reject', reason: 'KEY_MISMATCH' };
        this.append('CEILING', this.now(), { amount: o.amount, window_s: o.window_s ?? DEFAULT_CEILING_WINDOW });
        return { result: 'accept' };
      }
      case 'revoke': {
        if (o.signed_by !== this.pinned) return { result: 'reject', reason: 'KEY_MISMATCH' };
        this.append('REVOCATION', this.now(), { mandate: o.mandate });
        // §6.7 outstanding reservations released unless already presented
        for (const r of this.reservations().values()) if (r.mandate === o.mandate && r.state === 'active' && !this.accepted.has(r.id)) this.append('RELEASE', this.now(), { receipt: r.id, cause: 'revoked' });
        return { result: 'accept' };
      }
      case 'clock': {
        if (this.clock !== null && o.t < this.clock) return { result: 'clamped' }; // §5.3
        this.clock = o.t; this.expireSweep(this.clock); return { result: 'ok' };
      }
      case 'restart': return { result: 'ok' }; // state lives in the ledger only
      case 'authorize': {
        const now = this.now(o.action.t);
        this.expireSweep(now);
        const M = this.mandates().get(o.mandate) || null;
        const c = this.ceiling();
        const S = {
          committedM: M ? this.committed(now, (r) => r.mandate === M.id, Number(M.budget_window_s)) : 0,
          committedP: c ? this.committed(now, () => true, Number(c.window_s)) : 0,
          ceiling: c ? c.amount : null,
        };
        const v = evaluate(M, o.action, S, { now, revoked: M ? this.revoked(M.id) : false });
        const monetary = riskOf(o.action) === 'monetary';
        const reserved = monetary && (v.verdict === 'allow' || v.verdict === 'defer'); // §7.4 Reserve
        this.append('RECEIPT', now, { id: o.id, mandate: o.mandate, action: o.action, verdict: v.verdict, reason: v.reason, reserved, expires: now + (o.ttl ?? DEFAULT_TTL), audience: o.audience ?? 'tool' });
        return { verdict: v.verdict, reason: v.reason };
      }
      case 'approve': {
        const R = this.receipt(o.receipt);
        if (o.signed_by !== this.pinned) return { result: 'reject', reason: 'APPROVAL_SIG' }; // §6.6
        if (!R || R.verdict !== 'defer') return { result: 'reject', reason: 'UNDEFINED_BY_SPEC' };
        this.append('APPROVAL', this.now(), { receipt: o.receipt });
        return { result: 'accept', verdict: 'allow' }; // 6.6: issues an allow AAR
      }
      case 'tool_present': return this.toolPresent(o);
      case 'agent_report': return { result: 'ignored' }; // §7.4 agent statements never release
      case 'tool_report': {
        const r = this.reservations().get(o.receipt);
        if (o.executed === false && r && r.state === 'active') { this.append('RELEASE', this.now(), { receipt: o.receipt, cause: 'tool' }); return { result: 'released' }; }
        return { result: 'ok' };
      }
      default: return { result: 'error', reason: 'UNKNOWN_OP' };
    }
  }

  // §8.4 in the stated order: 1,2,3,4,5,6,7,(9 "after 7"),8.
  toolPresent(o) {
    const now = this.now();
    this.expireSweep(now);
    if (o.receipt === null || o.receipt === undefined) return { result: 'reject', reason: 'NO_RECEIPT' }; // 1
    const R = this.receipt(o.receipt);
    if (!R) return { result: 'reject', reason: 'NO_RECEIPT' };
    // 2 signature: abstract receipts are produced by this witness -> valid
    if (R.verdict !== 'allow') return { result: 'reject', reason: 'NOT_ALLOWED' };            // 3
    if (o.audience_mismatch) return { result: 'reject', reason: 'AUDIENCE' };                  // 4
    if (o.request && JSON.stringify(canonObj(o.request)) !== JSON.stringify(canonObj(R.action)))
      return { result: 'reject', reason: 'REQUEST_MISMATCH' };                                 // 5
    if (this.accepted.has(o.receipt)) return { result: 'reject', reason: 'REPLAY' };          // 6
    if (now > R.expires) return { result: 'reject', reason: 'RECEIPT_EXPIRED' };               // 7
    // 9: the receipt is in this ledger by construction (abstract model)
    const res = this.reservations().get(o.receipt);
    if (riskOf(R.action) === 'monetary' && (!res || res.state !== 'active'))
      return { result: 'reject', reason: 'RESERVATION_INACTIVE' };                             // 8
    this.accepted.add(o.receipt);
    if (res) this.append('CONSUME', now, { receipt: o.receipt });
    return { result: 'accept' };
  }
}
function canonObj(x) { if (Array.isArray(x)) return x.map(canonObj); if (x && typeof x === 'object') { const o = {}; for (const k of Object.keys(x).sort()) o[k] = canonObj(x[k]); return o; } return x; }
