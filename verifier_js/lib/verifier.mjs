// Third-party verifier, Section 10 (steps 1-7), step-major order:
// the result is the failure of the LOWEST-numbered step; within a step, the
// lowest position. (AMBIGUITY-4: text does not say step-major vs entry-major.)
import { evaluate, riskOf } from './evaluate.mjs';
import { DEFAULT_TTL } from './witness.mjs';
import { verifySign1, parseSign1, sha256, hex, toJS, cdeEncode, CoseError } from './cose.mjs';

const STEP = { WITNESS_NOT_INDEPENDENT: 1, WITNESS_SIG: 2, CHAIN_BREAK: 3, MANDATE_KEY: 4,
  MANDATE_UNKNOWN: 5, VERDICT_NOT_REPRODUCIBLE: 5, CONSUME_INVALID: 6,
  CHECKPOINT_SIG: 7, CHECKPOINT_HEAD: 7, CHECKPOINT_ROOT: 7, ANCHOR_MISMATCH: 7,
  RELEASE_MISSING: 7, RELEASE_INVALID: 7, NO_INCLUSION: 7, OFFLOG_RECEIPT: 7, INCLUSION_INVALID: 7 };
// order inside step 7 follows the text: checkpoint sig/head/root, anchor, releases, inclusion
const SUB = { CHECKPOINT_SIG: 0, CHECKPOINT_HEAD: 1, CHECKPOINT_ROOT: 2, ANCHOR_MISMATCH: 3, RELEASE_MISSING: 4, RELEASE_INVALID: 4, NO_INCLUSION: 5, OFFLOG_RECEIPT: 5, INCLUSION_INVALID: 5 };

class Findings {
  constructor() { this.list = []; this.warnings = []; }
  add(reason, at, extra = {}) { this.list.push({ reason, at, ...extra }); }
  first() {
    if (!this.list.length) return null;
    const key = (f) => [STEP[f.reason] ?? 9, SUB[f.reason] ?? 0, f.at ?? 1e9];
    return [...this.list].sort((a, b) => { const x = key(a), y = key(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; })[0];
  }
}

// RFC 6962 Merkle tree hash
const H = (...b) => sha256(Buffer.concat(b.map((x) => Buffer.from(x))));
export function mth(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return H([0], leaves[0]);
  let k = 1; while (k * 2 < leaves.length) k *= 2;
  return H([1], mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
// RFC 9162 §2.1.3.2 inclusion verification (path labels L/R are cross-checked, not trusted)
export function verifyInclusion(leaf, index, size, path, root) {
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = H([0], leaf);
  for (const [side, phex] of path) {
    const p = Buffer.from(phex, 'hex');
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      if (side !== 'L') return false;
      r = H([1], p, r);
      if ((fn & 1) === 0) while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      if (side !== 'R') return false;
      r = H([1], r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r.equals(Buffer.from(root));
}

/**
 * Core replay over normalised entries:
 * e = { seq, type, t, prev, hash, witnessSigOk, principalOk, body (plain JS), ledgerId }
 * ctx = { witnessKey, operatorKeys, independence, checkpoints:[{seq,head,root?,sigOk,ots_digest,ots_status,hashForAnchor}], presented:[...], leafHashes }
 */
export function verifyLedger(entries, ctx) {
  const F = new Findings();
  // 1
  if (ctx.operatorKeys?.includes(ctx.witnessKey)) F.add('WITNESS_NOT_INDEPENDENT', undefined);
  if (ctx.independence === 'none') F.add('WITNESS_NOT_INDEPENDENT', undefined);
  // 2
  for (const e of entries) if (e.witnessSigOk === false) F.add('WITNESS_SIG', e.seq);
  // 3
  entries.forEach((e, i) => {
    if (e.seq !== i) F.add('CHAIN_BREAK', e.seq);
    else if (i === 0 ? e.prev !== null && e.prev !== undefined : e.prev !== entries[i - 1].hash) F.add('CHAIN_BREAK', e.seq);
    else if (e.ledgerId !== undefined && e.ledgerId !== entries[0].ledgerId) F.add('CHAIN_BREAK', e.seq, { note: 'ledger id differs (transplant)' });
  });
  // 4
  for (const e of entries) if (['MANDATE', 'CEILING', 'REVOCATION', 'APPROVAL'].includes(e.type) && e.principalOk === false) F.add('MANDATE_KEY', e.seq);

  // 5, 6, 7(releases): replay
  const mandates = new Map(); let ceiling = null; const revoked = new Set();
  const receipts = new Map(); // id -> {mandate, action, verdict, t, expires, monetary, state}
  const committed = (t, filter, w) => { let s = 0; for (const r of receipts.values()) if (r.reserved && filter(r) && r.state !== 'released' && r.t > t - w && r.t <= t) s += Number(r.action.amount); return s; };
  for (const e of entries) {
    const b = e.body || {};
    const t = e.t ?? b.action?.t;
    // §7.4: an entry with t > expires following an active reservation (other than its own RELEASE)
    if (t !== undefined) for (const r of receipts.values()) {
      if (r.reserved && r.state === 'active' && t > r.expires && !(e.type === 'RELEASE' && b.receipt === r.id && b.cause === 'expired')) { F.add('RELEASE_MISSING', e.seq); break; }
    }
    switch (e.type) {
      case 'MANDATE': if (e.principalOk !== false) mandates.set(b.mandate.id, b.mandate); break;
      case 'CEILING': if (e.principalOk !== false) ceiling = { amount: b.amount, window_s: b.window_s }; break;
      case 'REVOCATION': if (e.principalOk !== false) revoked.add(b.mandate); break;
      case 'RECEIPT': {
        const M = mandates.get(b.mandate) || null;
        if (!M && !(b.verdict === 'deny' && b.reason === 'NO_MANDATE')) { F.add('MANDATE_UNKNOWN', e.seq); break; }
        const S = {
          committedM: M ? committed(t, (r) => r.mandate === M.id, Number(M.budget_window_s)) : 0,
          committedP: ceiling ? committed(t, () => true, Number(ceiling.window_s)) : 0,
          ceiling: ceiling ? ceiling.amount : null,
        };
        const v = evaluate(M, b.action, S, { now: t, revoked: M ? revoked.has(M.id) : false });
        if (v.verdict !== b.verdict || (b.reason !== undefined && v.reason !== b.reason)) F.add('VERDICT_NOT_REPRODUCIBLE', e.seq, { got: v, signed: { verdict: b.verdict, reason: b.reason } });
        const monetary = riskOf(b.action) === 'monetary';
        const reserved = monetary && (b.verdict === 'allow' || b.verdict === 'defer');
        receipts.set(b.id, { id: b.id, seq: e.seq, mandate: b.mandate, action: b.action, verdict: b.verdict, t, expires: t + (b.ttl ?? b.expires_in ?? DEFAULT_TTL), monetary, reserved, state: reserved ? 'active' : 'none', consumed: false });
        break;
      }
      case 'APPROVAL': { const r = receipts.get(b.receipt); if (r && e.principalOk !== false && r.verdict === 'defer') r.verdict = 'allow'; break; }
      case 'CONSUME': {
        const r = receipts.get(b.receipt);
        const bad = !r || r.verdict !== 'allow' || r.consumed || (t !== undefined && e.t !== undefined && e.t > r.expires) || (r.reserved && r.state !== 'active');
        if (bad) F.add('CONSUME_INVALID', e.seq);
        if (r) { r.consumed = true; if (r.reserved) r.state = 'consumed'; }
        break;
      }
      case 'RELEASE': {
        const r = receipts.get(b.receipt);
        if (b.cause === 'expired' && r && t !== undefined && !(t > r.expires)) F.add('RELEASE_INVALID', e.seq);
        // §7.4: only (a) tool non-execution, (b) expiry, (c) refusal/timeout, (d) revocation release.
        if (b.cause !== undefined && !['tool', 'expired', 'refused', 'timeout', 'revoked'].includes(b.cause)) F.add('RELEASE_INVALID', e.seq);
        if (r && r.consumed) F.add('RELEASE_INVALID', e.seq);
        if (r && r.reserved) r.state = 'released';
        break;
      }
      case 'CHECKPOINT': {
        // in-ledger checkpoint record: verify head/root it states
        if (b.seq !== undefined && b.head !== undefined) {
          const target = entries[b.seq];
          if (!target || b.seq >= e.seq || !eqH(target.hash, b.head)) F.add('CHECKPOINT_HEAD', e.seq);
          else if (b.root !== undefined && ctx.leafHashes && !eqH(hex(mth(ctx.leafHashes.slice(0, b.seq + 1))), b.root)) F.add('CHECKPOINT_ROOT', e.seq);
        }
        break;
      }
      default: break;
    }
  }
  // 7: published checkpoints
  let anchor = 'none';
  for (const c of ctx.checkpoints || []) {
    if (c.sigOk === false) { F.add('CHECKPOINT_SIG', c.seq); continue; }
    const seq = c.seq ?? (entries.length - 1);   // abstract checkpoint without seq = whole ledger (AMBIGUITY-12)
    const target = entries[seq];
    if (!target || !eqH(target.hash, c.head)) { F.add('CHECKPOINT_HEAD', seq); continue; }
    if (c.root !== undefined && ctx.leafHashes && !eqH(hex(mth(ctx.leafHashes.slice(0, seq + 1))), c.root)) { F.add('CHECKPOINT_ROOT', seq); continue; }
    if (c.ots_status !== undefined) {
      if (!eqH(c.ots_digest, c.hashForAnchor ?? c.head)) F.add('ANCHOR_MISMATCH', seq);
      else anchor = c.ots_status === 'bitcoin' ? 'bitcoin' : 'pending';
    }
  }
  // 7: presented receipts
  for (const p of ctx.presented || []) {
    if (p.reason) F.add(p.reason, undefined, { receipt: p.id });
  }
  const f = F.first();
  if (!f) return { result: 'valid', anchor, warnings: ctx.warnings || [] };
  return { result: 'invalid', reason: f.reason, at: f.at, receipt: f.receipt, detail: f, warnings: ctx.warnings || [] };
}
const eqH = (a, b) => (a instanceof Uint8Array ? hex(a) : a) === (b instanceof Uint8Array ? hex(b) : b);

// ---------- abstract (V-vectors) ----------
export function verifyAbstract(input) {
  const entries = input.entries.map((e) => ({
    seq: e.seq, type: e.type, t: e.t, prev: e.prev, hash: e.hash,
    witnessSigOk: e.witness_sig_valid !== false,
    principalOk: e.body && 'signed_by' in e.body ? e.body.signed_by === input.pinned_principal_key : undefined,
    body: normaliseAbstractBody(e),
  }));
  const checkpoints = input.checkpoint ? [{ ...input.checkpoint, sigOk: input.checkpoint.sig_valid !== false }] : [];
  const presented = (input.presented || []).map((p) => {
    if (!p.inclusion) return { id: p.id, reason: 'NO_INCLUSION' };
    const e = entries[p.inclusion.seq];
    const cseq = input.checkpoint?.seq ?? entries.length - 1;
    if (!e || e.type !== 'RECEIPT' || e.body.id !== p.id || p.inclusion.seq > cseq) return { id: p.id, reason: 'OFFLOG_RECEIPT' };
    return { id: p.id };
  });
  return verifyLedger(entries, { witnessKey: input.witness_key, operatorKeys: input.operator_keys, independence: input.independence, checkpoints, presented });
}
function normaliseAbstractBody(e) {
  const b = e.body || {};
  if (e.type === 'MANDATE') return { mandate: b.mandate };
  if (e.type === 'CEILING') return { amount: b.amount, window_s: b.window_s ?? 86400 };
  return b;
}

// ---------- byte level (cose-ledger) ----------
export function verifyCoseLedger(v) {
  const witnessKeys = v.keys;
  const reg = v.registry?.principals?.[v.principal];
  const pinnedKeys = reg ? { [hex(sha256(Buffer.from(reg.pub, 'hex'))).slice(0, 32)]: { alg: reg.alg, pub: reg.pub } } : {};
  const warnings = [];
  const entries = [];
  const leafHashes = [];
  let witnessKidHex = null;
  for (let i = 0; i < v.ledger_hex.length; i++) {
    const bytes = Buffer.from(v.ledger_hex[i], 'hex');
    const h = sha256(bytes); leafHashes.push(h);
    let p, witnessSigOk = true;
    try { p = verifySign1(bytes, witnessKeys); witnessKidHex = p.kidHex; }
    catch (err) { witnessSigOk = false; try { p = parseSign1(bytes); } catch { entries.push({ seq: i, type: '?', hash: hex(h), witnessSigOk: false, prev: undefined, body: {} }); continue; } }
    if (!p.deterministic) warnings.push(`entry ${i}: payload not Core Deterministic Encoding (§5.1)`);
    const P = toJS(p.payload);
    const body = P.body || {};
    let principalOk;
    let nb = body;
    if (['MANDATE', 'CEILING', 'REVOCATION', 'APPROVAL'].includes(P.type)) {
      if (!body.cose) { principalOk = v.require_cose ? false : undefined; }
      else {
        principalOk = true;
        const typ = { MANDATE: 'application/aar-mandate+cbor', CEILING: 'application/aar-ceiling+cbor', APPROVAL: 'application/aar-approval+cbor', REVOCATION: undefined }[P.type];
        let inner;
        try { inner = verifySign1(Buffer.from(body.cose), pinnedKeys, { typ }); } catch { principalOk = false; }
        if (inner) {
          const signed = toJS(inner.payload);
          let expect;
          if (P.type === 'MANDATE') expect = body.mandate;
          if (P.type === 'CEILING') expect = { ceiling: body.amount, window_s: body.window_s, principal: signed.principal };
          if (P.type === 'APPROVAL') expect = { approve: body.receipt, principal: signed.principal };
          if (P.type === 'REVOCATION') expect = { mandate: body.mandate, ...signed };
          if (signed.principal !== undefined && signed.principal !== v.principal) principalOk = false;
          if (expect !== undefined && !cdeEncode(expect).equals(cdeEncode(signed))) principalOk = false;
          if (P.type === 'MANDATE') nb = { mandate: signed };
          if (P.type === 'CEILING') nb = { amount: signed.ceiling, window_s: signed.window_s };
          // §6.1 says kid = RFC 9679 thumbprint; vectors use SHA-256(pub)[:16]. Warning only.
          if (inner.prot.get(4) && Buffer.from(inner.prot.get(4)).length !== 32) warnings.push(`entry ${i}: principal kid is ${Buffer.from(inner.prot.get(4)).length} bytes, §6.1 requires an RFC 9679 thumbprint (32 bytes)`);
        }
      }
    }
    entries.push({ seq: P.seq, type: P.type, t: P.t, prev: P.prev === null ? null : P.prev ? hex(P.prev) : undefined, hash: hex(h), witnessSigOk, principalOk, body: nb, ledgerId: P.ledger ? hex(P.ledger) : undefined });
  }
  // ledger identifier §7.1
  if (witnessKidHex && entries[0]?.ledgerId) {
    const want = hex(sha256(Buffer.concat([Buffer.from('deus-aar/ledger/' + v.principal, 'utf8'), Buffer.from(witnessKidHex, 'hex')])));
    if (want !== entries[0].ledgerId) warnings.push('ledger identifier does not equal SHA-256("deus-aar/ledger/"||principal||witness-kid)');
  }
  const checkpoints = [];
  const parseCkpt = (hx) => {
    const b = Buffer.from(hx, 'hex');
    try { const p = verifySign1(b, witnessKeys, { typ: 'application/aar-checkpoint+cbor' }); const c = toJS(p.payload); return { seq: c.seq, head: hex(c.head), root: hex(c.root), sigOk: true }; }
    catch { let c = {}; try { c = toJS(parseSign1(b).payload); } catch {} return { seq: c.seq, sigOk: false }; }
  };
  if (v.checkpoint_hex) checkpoints.push(parseCkpt(v.checkpoint_hex));
  const presented = (v.presented || []).map((pr) => presentedCheck(pr, witnessKeys, leafHashes));
  return verifyLedger(entries, { witnessKey: witnessKidHex, operatorKeys: v.operator_keys || [], checkpoints, presented, leafHashes, warnings });
}

// A receipt that a tool reports as accepted (§10 step 7). Returns {id, reason?}
export function presentedCheck(pr, witnessKeys, leafHashes) {
  let aar;
  try { aar = verifySign1(Buffer.from(pr.aar_hex, 'hex'), witnessKeys, { typ: 'application/aar-receipt+cbor' }); }
  catch { return { id: '?', reason: 'WITNESS_SIG' }; }
  const cwt = aar.prot.get(15); const sub = cwt instanceof Map ? cwt.get(2) : undefined;
  if (!pr.proof) return { id: sub, reason: 'NO_INCLUSION' };
  // verifier view (§10 step 7): is the proven entry an entry of THIS ledger, for this receipt?
  const eh = sha256(Buffer.from(pr.proof.entry, 'hex'));
  let E = {};
  try { E = toJS(parseSign1(Buffer.from(pr.proof.entry, 'hex')).payload); } catch {}
  if (!leafHashes.some((h) => h.equals(eh)) || E.body?.id !== sub) return { id: sub, reason: 'OFFLOG_RECEIPT' };
  const r = inclusionCheck(aar, pr.proof, witnessKeys);
  if (r) return { id: sub, reason: r };
  return { id: sub };
}

// §8.4(9). Returns null if OK, else reason.
export function inclusionCheck(aar, proof, witnessKeys) {
  const P = toJS(aar.payload);
  const cwt = aar.prot.get(15); const sub = cwt instanceof Map ? cwt.get(2) : undefined;
  let ent, ck;
  try { ent = verifySign1(Buffer.from(proof.entry, 'hex'), witnessKeys); } catch { return 'INCLUSION_INVALID'; }
  try { ck = verifySign1(Buffer.from(proof.checkpoint, 'hex'), witnessKeys, { typ: 'application/aar-checkpoint+cbor' }); } catch { return 'INCLUSION_INVALID'; }
  const E = toJS(ent.payload), C = toJS(ck.payload);
  const eh = sha256(Buffer.from(proof.entry, 'hex'));
  if (E.type !== 'RECEIPT') return 'INCLUSION_INVALID';
  if (P.chain?.prev !== undefined && hex(P.chain.prev) !== hex(eh)) return 'INCLUSION_INVALID';   // "its hash equals chain.prev"
  if (P.chain?.seq !== undefined && Number(P.chain.seq) !== Number(E.seq)) return 'INCLUSION_INVALID';
  if (E.body?.id !== sub) return 'OFFLOG_RECEIPT';
  if (!verifyInclusion(eh, Number(E.seq), Number(C.seq) + 1, proof.path || [], Buffer.from(C.root))) return 'INCLUSION_INVALID';
  return null;
}
