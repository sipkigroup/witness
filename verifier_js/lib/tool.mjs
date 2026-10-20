// Tool acceptance (§8.4) and plain COSE checks for byte-level vectors.
// Reason codes: §8.4 codes where the text defines one. For a failing witness
// signature the text defines no tool-side code; we use WITNESS_SIG (the §10
// code for the same fact) and say so in the report (AMBIGUITY-8).
import { verifySign1, parseSign1, sha256, hex, toJS, cdeEncode, CoseError } from './cose.mjs';
import { inclusionCheck } from './verifier.mjs';

const TYP_AAR = 'application/aar-receipt+cbor';
const sigCode = (e) => (e instanceof CoseError ? ({ MALFORMED: 'MALFORMED', TYP_MISMATCH: 'MALFORMED' }[e.code] ?? 'WITNESS_SIG') : 'MALFORMED');

export function coseVerify(v) {
  try {
    const p = verifySign1(Buffer.from(v.cose_hex, 'hex'), v.keys, { typ: v.typ ?? TYP_AAR });
    if (!p.deterministic) return { result: 'reject', reason: 'MALFORMED', detail: 'payload not CDE (§5.1)' };
    return { result: 'ok' };
  } catch (e) { return { result: 'reject', reason: sigCode(e), detail: e.code + ': ' + e.message }; }
}

export function coseMandate(v) {
  // §4.2: a record signed by any key other than the pinned one -> KEY_MISMATCH.
  try {
    const p = verifySign1(Buffer.from(v.cose_hex, 'hex'), v.keys, { typ: 'application/aar-mandate+cbor' });
    const M = toJS(p.payload);
    if (v.mandate && (M.id !== v.mandate.id || M.principal !== v.mandate.principal || M.agent !== v.mandate.agent)) return { result: 'reject', reason: 'MANDATE_KEY' };
    return { result: 'ok' };
  } catch (e) {
    if (e instanceof CoseError && ['KID_UNKNOWN', 'SIG_INVALID', 'ALG_MISMATCH'].includes(e.code)) return { result: 'reject', reason: 'KEY_MISMATCH', detail: e.code };
    return { result: 'reject', reason: 'MALFORMED', detail: e.message };
  }
}

/** One tool with a replay store. presentations: [{cose_hex, request, now, proof, tool_id}] */
export class Tool {
  constructor(id, keys) { this.id = id; this.keys = keys; this.accepted = new Set(); }
  present({ cose_hex, request, now, proof }) {
    if (!cose_hex) return { result: 'reject', reason: 'NO_RECEIPT' };                     // 1
    let p;
    try { p = verifySign1(Buffer.from(cose_hex, 'hex'), this.keys, { typ: TYP_AAR }); }   // 2
    catch (e) { return { result: 'reject', reason: sigCode(e), detail: e.code + ': ' + e.message }; }
    if (!p.deterministic) return { result: 'reject', reason: 'MALFORMED', detail: 'payload not CDE (§5.1)' };
    const A = toJS(p.payload);
    // §4.3: independence "none" statements MUST NOT be treated as witness receipts (no §8.4 code; AMBIGUITY-15)
    if (A.independence === 'none') return { result: 'reject', reason: 'WITNESS_NOT_INDEPENDENT' };
    if (A.verdict?.decision !== 'allow') return { result: 'reject', reason: 'NOT_ALLOWED' }; // 3
    if (A.audience !== this.id) return { result: 'reject', reason: 'AUDIENCE' };            // 4
    const rh = sha256(cdeEncode(request));                                                 // 5 canonical request = CDE(request)
    if (!A.action?.binding_request_hash || hex(A.action.binding_request_hash) !== hex(rh)) return { result: 'reject', reason: 'REQUEST_MISMATCH' };
    // 6 replay identity: (iss, sub) of the CWT claims, NOT the COSE bytes (signature malleability)
    const cwt = p.prot.get(15);
    const id = cwt instanceof Map ? `${cwt.get(1)}|${cwt.get(2)}` : hex(sha256(p.payloadBytes));
    if (this.accepted.has(id)) return { result: 'reject', reason: 'REPLAY' };
    if (now > Number(A.expires)) return { result: 'reject', reason: 'RECEIPT_EXPIRED' };    // 7 "not after expires"
    // 9 (after 7): inclusion proof is mandatory in revision 4.1 text
    if (!proof) return { result: 'reject', reason: 'NO_INCLUSION' };
    const inc = inclusionCheck(p, proof, this.keys);
    if (inc) return { result: 'reject', reason: inc === 'OFFLOG_RECEIPT' ? 'INCLUSION_INVALID' : inc };
    // 8 reservation active: a stand-alone tool vector carries no ledger state -> assumed active
    this.accepted.add(id);
    return { result: 'accept' };
  }
}

export function coseTool(v) {
  const t = new Tool(v.tool_id, v.keys);
  if (v.presentations) return v.presentations.map((pr) => t.present({ cose_hex: pr.cose_hex ?? v.cose_hex, request: pr.request ?? v.request, now: pr.now ?? v.now, proof: pr.proof ?? v.proof }));
  return t.present({ cose_hex: v.cose_hex, request: v.request, now: v.now, proof: v.proof });
}
