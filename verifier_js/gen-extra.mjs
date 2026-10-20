#!/usr/bin/env node
// Generates verifier_js/extra-vectors/*.json — additional conformance cases.
// Each vector: expected result BY THE SPEC TEXT, `basis` = the § quoted,
// `ambiguity` = AMBIGUITY-N when the text allows another honest answer.
// Byte-level vectors use fresh test keys (private keys are NOT stored).
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { signSign1, cdeEncode, sha256, hex, cbor } from './lib/cose.mjs';
import { mth } from './lib/verifier.mjs';

const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'extra-vectors');
fs.mkdirSync(OUT, { recursive: true });
for (const f of fs.readdirSync(OUT)) if (f.endsWith('.json')) fs.unlinkSync(path.join(OUT, f));
const put = (v) => fs.writeFileSync(path.join(OUT, v.id + '.json'), JSON.stringify(v, null, 1).replace(/"__FLOAT100__"/g, '100.0'));

const baseM = () => ({ id: 'm1', principal: 'pk-principal', agent: 'agent-1', nbf: 0, exp: 86400, key_attestation: 'software',
  permissions: { message: { to: ['buh@firma1.example', 'partner@firma1.example'] }, file: { to: ['buh@firma1.example'] },
    disclosure: { to: ['buh@firma1.example'], data: [] }, purchase: { max_per_action: 15000, budget: 37500 }, sale: { min_price: 0 }, meeting: true, refund: true },
  forbidden_data: [], budget_window_s: 86400, named_circle: false });
const act = (o) => ({ class: 'message', agent: 'agent-1', t: 100, amount: 0, recipient: 'buh@firma1.example', data: [], ...o });
const D = (id, cls, title, m, a, exp, basis, extra = {}) => put({ id, class: cls, kind: 'decision', title, input: { mandate: m, action: a, ...(extra.input || {}) }, expected: exp, basis, ...(extra.ambiguity ? { ambiguity: extra.ambiguity } : {}) });

// ---------- decision ----------
{ const m = baseM(); m.permissions.purchase = { max_per_action: 2 * 10 ** 15, budget: 2 * 10 ** 15 };
  D('X01', 'valid', 'Amount exactly 10^15 is not "above 10^15"', m, act({ class: 'purchase', amount: 10 ** 15, recipient: '' }), { verdict: 'allow', reason: 'OK' }, '§5.2 "values above 10^15 ... MUST be rejected"');
  D('X02', 'invalid', 'Amount 10^15+1', m, act({ class: 'purchase', amount: 10 ** 15 + 1, recipient: '' }), { verdict: 'deny', reason: 'BAD_AMOUNT' }, '§5.2'); }
D('X03', 'invalid', 'Amount written as 100.0 (floating point literal)', baseM(), act({ class: 'purchase', amount: '__FLOAT100__', recipient: '' }), { verdict: 'deny', reason: 'BAD_AMOUNT' }, '§5.2 "Floating-point values ... MUST be rejected"', { ambiguity: 'AMBIGUITY-13' });
{ const m = baseM(); m.currency = 'USD';
  D('X04', 'invalid', 'Currency differs from mandate currency', m, act({ class: 'purchase', amount: 100, currency: 'EUR', recipient: '' }), { verdict: 'deny', reason: 'BAD_AMOUNT' }, '§5.2 "any currency other than the mandate\'s currency"'); }
D('X05', 'valid', 'Witness time == exp (closed interval)', baseM(), act({ t: 86400 }), { verdict: 'allow', reason: 'OK' }, '§6.4 step 4 "outside [M.nbf, M.exp]"');
{ const m = baseM(); m.nbf = 50;
  D('X06', 'invalid', 'Witness time == nbf-1', m, act({ t: 49 }), { verdict: 'deny', reason: 'EXPIRED' }, '§6.4 step 4'); }
D('X07', 'valid', 'committed + amount == budget exactly', baseM(), act({ class: 'purchase', amount: 1500, recipient: '' }), { verdict: 'allow', reason: 'OK' }, '§6.4 step 10 "committed(M) + amount > budget -> deny" (strict >)', { input: { ledger_state: { mandate_committed: 36000, principal_committed: 36000 } } });
{ const m = baseM(); m.permissions.message = { to: ['strasse@firma1.example'] };
  D('X08', 'valid', 'Full Unicode case folding: STRAßE == strasse', m, act({ recipient: 'STRAßE@firma1.example' }), { verdict: 'allow', reason: 'OK' }, '§5.4 "apply case folding" (Unicode CaseFolding C+F maps ß to ss)', { ambiguity: 'AMBIGUITY-10' }); }
D('X09', 'valid', 'White space inside the address is removed', baseM(), act({ recipient: ' buh @ firma1.example ' }), { verdict: 'allow', reason: 'OK' }, '§5.4 "remove all white space"');
{ const m = baseM(); m.permissions.file = { to: [] };
  D('X10', 'invalid', 'Explicit empty recipient list is a specification, not "unspecified"', m, act({ class: 'file', recipient: 'buh@firma1.example' }), { verdict: 'deny', reason: 'RECIPIENT' }, '§6.2 "An explicit list ... a recipient outside an explicit list ... is denied"', { ambiguity: 'AMBIGUITY-5' }); }
D('X11', 'invalid', 'Meeting without principal_present field', baseM(), act({ class: 'meeting', recipient: '' }), { verdict: 'deny', reason: 'UNATTENDED_MEETING' }, '§5.6 "low if principal present, else irreversible"', { ambiguity: 'AMBIGUITY-16' });
{ const m = baseM(); m.permissions.disclosure = { to: '*', data: ['address'] }; m.permissions.publish = { channels: ['blog:main'] };
  D('X12', 'invalid', 'Publish never carries protected data even if disclosure grants it to "*"', m, act({ class: 'publish', recipient: 'blog:main', data: ['address'] }), { verdict: 'deny', reason: 'DATA_FORBIDDEN' }, '§5.6 "publish ... any protected data is denied"', { ambiguity: 'AMBIGUITY-3' }); }
D('X13', 'invalid', 'Display name looks permitted, address is not', baseM(), act({ recipient: 'buh@firma1.example <evil@zlo.example>' }), { verdict: 'deny', reason: 'RECIPIENT' }, '§5.4 "if it contains Name <addr>, take addr"');
D('X14', 'invalid', 'Two <addr> parts: which one? fail closed', baseM(), act({ recipient: '<buh@firma1.example> <evil@zlo.example>' }), { verdict: 'deny', reason: 'RECIPIENT' }, '§5.4 (undefined for several <...>)', { ambiguity: 'AMBIGUITY-14' });
{ const m = baseM(); delete m.permissions.file; m.named_circle = true;
  D('X15', 'invalid', 'Named circle never turns unspecified file permission into allow', m, act({ class: 'file', recipient: 'partner@firma1.example' }), { verdict: 'defer', reason: 'ESCALATE_FILE' }, '§6.5 "never turns an unspecified file permission into an allowance"'); }
D('X16', 'invalid', 'Data class differing only in case ("City") is unregistered -> protected', baseM(), act({ data: ['City'] }), { verdict: 'deny', reason: 'DATA_FORBIDDEN' }, '§5.5 "Every unregistered data class MUST be treated as protected"', { ambiguity: 'AMBIGUITY-17' });
{ const m = baseM(); m.forbidden_data = ['city'];
  D('X17', 'invalid', 'forbidden_data beats a non-protected class', m, act({ data: ['city'] }), { verdict: 'deny', reason: 'DATA_FORBIDDEN' }, '§6.4 step 7'); }

// ---------- sequence ----------
const reg = { op: 'register_mandate', mandate: baseM(), signed_by: 'pk-principal' };
const S = (id, cls, title, ops, steps, basis, amb) => put({ id, class: cls, kind: 'sequence', title, input: { pinned_principal_key: 'pk-principal', ops }, expected: { steps }, basis, ...(amb ? { ambiguity: amb } : {}) });
S('X20', 'invalid', 'Replay of a non-monetary receipt', [reg, { op: 'authorize', id: 'r0', mandate: 'm1', action: act({}) }, { op: 'tool_present', receipt: 'r0' }, { op: 'tool_present', receipt: 'r0' }],
  [{ result: 'accept' }, { verdict: 'allow', reason: 'OK' }, { result: 'accept' }, { result: 'reject', reason: 'REPLAY' }], '§8.4 check 6');
{ const m = baseM(); m.permissions.purchase = { max_per_action: 10000, budget: null };
  S('X21', 'invalid', 'Deferred purchases hold reservations against the ceiling', [{ ...reg, mandate: m }, { op: 'register_ceiling', amount: 10000, window_s: 86400, signed_by: 'pk-principal' },
    { op: 'authorize', id: 'a0', mandate: 'm1', action: act({ class: 'purchase', amount: 6000, recipient: '' }) }, { op: 'authorize', id: 'a1', mandate: 'm1', action: act({ class: 'purchase', amount: 6000, recipient: '' }) }],
  [{ result: 'accept' }, { result: 'accept' }, { verdict: 'defer', reason: 'ESCALATE_MONEY' }, { verdict: 'deny', reason: 'CEILING' }], '§7.4 "allow or defer creates a reservation"; §12.3 "splitting into deferrals does not escape the budget"'); }
{ const m = baseM(); m.permissions.purchase = { max_per_action: 10000, budget: 10000 }; m.budget_window_s = 100;
  S('X22', 'invalid', 'Sliding window boundary (t - window, t]', [{ ...reg, mandate: m },
    { op: 'authorize', id: 'a0', mandate: 'm1', ttl: 1000, action: act({ class: 'purchase', amount: 8000, recipient: '', t: 100 }) }, { op: 'tool_present', receipt: 'a0' },
    { op: 'authorize', id: 'a1', mandate: 'm1', ttl: 1000, action: act({ class: 'purchase', amount: 8000, recipient: '', t: 150 }) },
    { op: 'authorize', id: 'a2', mandate: 'm1', ttl: 1000, action: act({ class: 'purchase', amount: 8000, recipient: '', t: 200 }) }],
  [{ result: 'accept' }, { verdict: 'allow', reason: 'OK' }, { result: 'accept' }, { verdict: 'deny', reason: 'BUDGET' }, { verdict: 'allow', reason: 'OK' }], '§7.3 "created in (t - budget_window_s, t]"'); }
S('X23', 'invalid', 'Action after revocation', [reg, { op: 'revoke', mandate: 'm1', signed_by: 'pk-principal' }, { op: 'authorize', id: 'r0', mandate: 'm1', action: act({}) }],
  [{ result: 'accept' }, { result: 'accept' }, { verdict: 'deny', reason: 'EXPIRED' }], '§6.7 "Actions evaluated after it are denied (EXPIRED)"');
S('X24', 'invalid', 'Revocation signed by a non-pinned key has no effect', [reg, { op: 'revoke', mandate: 'm1', signed_by: 'pk-operator' }, { op: 'authorize', id: 'r0', mandate: 'm1', action: act({}) }],
  [{ result: 'accept' }, { result: 'reject', reason: 'KEY_MISMATCH' }, { verdict: 'allow', reason: 'OK' }], '§4.2 "MUST NOT modify ledger state"');

// ---------- verification (abstract) ----------
const MAND = (h = 'h0') => ({ seq: 0, type: 'MANDATE', t: 0, body: { mandate: baseM(), signed_by: 'pk-principal' }, prev: null, hash: h });
const REC = (seq, id, amount, t, prev, hash, verdict = 'allow', extra = {}) => ({ seq, type: 'RECEIPT', t, body: { id, mandate: 'm1', action: act({ class: 'purchase', amount, recipient: '', t }), verdict, ...extra }, prev, hash });
const V = (id, cls, title, entries, exp, basis, amb, more = {}) => put({ id, class: cls, kind: 'verification', title, input: { witness_key: 'pk-witness', operator_keys: ['pk-operator'], pinned_principal_key: 'pk-principal', entries, ...more }, expected: exp, basis, ...(amb ? { ambiguity: amb } : {}) });
V('X30', 'invalid', 'Two failures: chain break at 2, witness signature at 3 (step-major order)',
  [MAND(), REC(1, 'r0', 1000, 100, 'h0', 'h1'), { seq: 2, type: 'CONSUME', t: 100, body: { receipt: 'r0' }, prev: 'hX', hash: 'h2' }, { ...REC(3, 'r1', 1000, 100, 'h2', 'h3'), witness_sig_valid: false }],
  { result: 'invalid', reason: 'WITNESS_SIG', at: 3 }, '§10 steps 2 and 3 are listed in order and each covers "every entry"', 'AMBIGUITY-4');
V('X31', 'invalid', 'REFUND does not reduce committed amount',
  [MAND(), REC(1, 'r0', 12000, 100, 'h0', 'h1'), REC(2, 'r1', 12000, 100, 'h1', 'h2'), REC(3, 'r2', 12000, 100, 'h2', 'h3'),
    { seq: 4, type: 'REFUND', t: 100, body: { receipt: 'r0', amount: 12000 }, prev: 'h3', hash: 'h4' }, REC(5, 'r3', 12000, 100, 'h4', 'h5')],
  { result: 'invalid', reason: 'VERDICT_NOT_REPRODUCIBLE', at: 5 }, '§7.3 "A REFUND entry ... MUST NOT reduce committed amounts"');
V('X32', 'invalid', 'RELEASE cause expired before expiry',
  [MAND(), REC(1, 'r0', 12000, 100, 'h0', 'h1', 'allow', { ttl: 300 }), { seq: 2, type: 'RELEASE', t: 200, body: { receipt: 'r0', cause: 'expired' }, prev: 'h1', hash: 'h2' }],
  { result: 'invalid', reason: 'RELEASE_INVALID', at: 2 }, '§7.4 "a RELEASE with cause expired before expiry (RELEASE_INVALID)"');
V('X33', 'invalid', 'Double CONSUME of one receipt',
  [MAND(), REC(1, 'r0', 12000, 100, 'h0', 'h1'), { seq: 2, type: 'CONSUME', t: 100, body: { receipt: 'r0' }, prev: 'h1', hash: 'h2' }, { seq: 3, type: 'CONSUME', t: 100, body: { receipt: 'r0' }, prev: 'h2', hash: 'h3' }],
  { result: 'invalid', reason: 'CONSUME_INVALID', at: 3 }, '§10 step 6 "unconsumed"');
V('X34', 'invalid', 'CONSUME after expiry (also RELEASE_MISSING at the same entry; step 6 precedes step 7)',
  [MAND(), REC(1, 'r0', 12000, 100, 'h0', 'h1', 'allow', { ttl: 300 }), { seq: 2, type: 'CONSUME', t: 1000, body: { receipt: 'r0' }, prev: 'h1', hash: 'h2' }],
  { result: 'invalid', reason: 'CONSUME_INVALID', at: 2 }, '§10 step 6 "unexpired"; §7.4', 'AMBIGUITY-4');
V('X35', 'invalid', 'RELEASE caused by an agent statement',
  [MAND(), REC(1, 'r0', 12000, 100, 'h0', 'h1', 'allow', { ttl: 3000 }), { seq: 2, type: 'RELEASE', t: 100, body: { receipt: 'r0', cause: 'agent' }, prev: 'h1', hash: 'h2' }],
  { result: 'invalid' }, '§7.4 "Agent and operator statements MUST NOT release a reservation" (no verifier code; causes are not enumerated)', 'AMBIGUITY-18');
V('X36', 'invalid', 'Ledger starting at seq 1', [{ ...MAND(), seq: 1 }], { result: 'invalid', reason: 'CHAIN_BREAK' }, '§7.1 "seq: 0, 1, 2, ... no gaps"', 'AMBIGUITY-19');
V('X37', 'invalid', 'Logged deny NO_MANDATE although the mandate exists', [MAND(), REC(1, 'r0', 100, 100, 'h0', 'h1', 'deny', { reason: 'NO_MANDATE' })],
  { result: 'invalid', reason: 'VERDICT_NOT_REPRODUCIBLE', at: 1 }, '§10 step 5: exception only for an unknown mandate');

// ---------- byte level ----------
function keypair(alg) {
  const kp = alg === 'EdDSA' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = kp.publicKey.export({ format: 'jwk' });
  const pub = alg === 'EdDSA' ? Buffer.from(jwk.x, 'base64url') : Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const kid = hex(sha256(pub)).slice(0, 32);
  return { alg, priv: kp.privateKey, pub: hex(pub), kid, keys: { [kid]: { alg, pub: hex(pub) } } };
}
const W = keypair('EdDSA');
const W2 = keypair('ES256');
const P1 = keypair('EdDSA');
const u8 = (b) => new Uint8Array(b);
const request = { class: 'message', agent: 'agent-1', t: 100, amount: 0, recipient: 'buh@firma1.example', data: [] };
const ledgerId = (w) => u8(sha256(Buffer.concat([Buffer.from('deus-aar/ledger/p1'), Buffer.from(w.kid, 'hex')])));
function buildLedger(w, sub = 'r0', expiresTtl = 300) {
  const mandate = { id: 'm1', exp: 1000000000, nbf: 0, agent: 'agent-1', principal: 'p1', permissions: { message: { to: ['buh@firma1.example'] } }, named_circle: false, forbidden_data: [], budget_window_s: 86400, key_attestation: 'software' };
  const mc = signSign1({ alg: 'EdDSA', kid: P1.kid, priv: P1.priv, typ: 'application/aar-mandate+cbor', payload: mandate });
  const e0 = signSign1({ alg: w.alg, kid: w.kid, priv: w.priv, typ: 'application/aar-ledger-entry+cbor', payload: { t: 100, seq: 0, body: { pin: { source: 'test-registry', principal: 'p1' }, cose: u8(mc), mandate, signed_by: null }, prev: null, type: 'MANDATE', ledger: ledgerId(w) } });
  const e1 = signSign1({ alg: w.alg, kid: w.kid, priv: w.priv, typ: 'application/aar-ledger-entry+cbor', payload: { t: 100, seq: 1, body: { id: sub, ttl: expiresTtl, action: request, reason: 'OK', mandate: 'm1', verdict: 'allow', audience: 'tool-A' }, prev: u8(sha256(e0)), type: 'RECEIPT', ledger: ledgerId(w) } });
  const leaves = [sha256(e0), sha256(e1)];
  const ck = signSign1({ alg: w.alg, kid: w.kid, priv: w.priv, typ: 'application/aar-checkpoint+cbor', payload: { t: 100, seq: 1, head: u8(leaves[1]), root: u8(mth(leaves)), ledger: ledgerId(w) } });
  const proof = { entry: hex(e1), path: [['L', hex(sha256(Buffer.concat([Buffer.from([0]), leaves[0]])))]], checkpoint: hex(ck) };
  return { e0, e1, ck, proof };
}
function aarPayload(over = {}) {
  return { spec: 'deus-aar/0.1', independence: 'separate-party', operator: 'op-1', audience: 'tool-A',
    action: { class: 'message', agent: 'agent-1', recipient: 'buh@firma1.example', data: [], amount: 0, currency: 'USD', params_hash: u8(Buffer.alloc(32)), binding_request_hash: u8(sha256(cdeEncode(request))) },
    mandate: { ref: u8(Buffer.alloc(32, 1)), principal_kid: u8(Buffer.from(P1.kid, 'hex')), key_attestation: 'software' },
    verdict: { decision: 'allow', reason: 'OK', risk: 'low' }, expires: 400, chain: { ledger: u8(Buffer.alloc(32, 2)), seq: 1 }, ...over };
}
const cwt = (sub = 'r0') => [15, new Map([[1, 'witness-1'], [2, sub], [6, 100]])];
const aar = (w, opts = {}) => signSign1({ alg: w.alg, kid: w.kid, priv: w.priv, typ: 'application/aar-receipt+cbor', extraProt: [cwt()], payload: aarPayload(opts.over), ...opts });
const B = (id, cls, kind, title, obj, exp, basis, amb) => put({ id, class: cls, kind, title, keys: W.keys, typ: 'application/aar-receipt+cbor', ...obj, expected: exp, basis, ...(amb ? { ambiguity: amb } : {}) });

const good = aar(W);
B('X40', 'invalid', 'cose-verify', 'Truncated COSE_Sign1 (malformed CBOR)', { cose_hex: hex(good.subarray(0, good.length - 10)) }, { result: 'reject' }, 'RFC 8949 well-formedness; §8.1');
{ // duplicate key "audience" in payload: hand-assembled map
  const p = aarPayload(); const entries = Object.entries(p);
  const enc = (v) => Buffer.from(cbor.encode(v, cbor.cdeEncodeOptions));
  const parts = [Buffer.from([0xa0 + entries.length + 1])];
  for (const [k, v] of entries) parts.push(enc(k), enc(v));
  parts.push(enc('audience'), enc('tool-B'));
  const pb = Buffer.concat(parts);
  B('X41', 'invalid', 'cose-verify', 'Duplicate map key in payload (validly signed)', { cose_hex: hex(signSign1({ alg: 'EdDSA', kid: W.kid, priv: W.priv, typ: 'application/aar-receipt+cbor', extraProt: [cwt()], payloadBytes: pb })) }, { result: 'reject' }, 'RFC 8949 §5.6 (duplicate keys: invalid); §5.1 deterministic encoding', 'AMBIGUITY-20');
  // non-deterministic key order (reverse) — otherwise valid
  const parts2 = [Buffer.from([0xa0 + entries.length])];
  for (const [k, v] of [...entries].reverse()) parts2.push(enc(k), enc(v));
  B('X42', 'invalid', 'cose-verify', 'Payload map not in Core Deterministic order (validly signed)', { cose_hex: hex(signSign1({ alg: 'EdDSA', kid: W.kid, priv: W.priv, typ: 'application/aar-receipt+cbor', extraProt: [cwt()], payloadBytes: Buffer.concat(parts2) })) }, { result: 'reject' }, '§5.1 "All signed payloads are CBOR maps ... encoded with Core Deterministic Encoding"', 'AMBIGUITY-20');
}
B('X43', 'invalid', 'cose-verify', 'alg only in the unprotected header', { cose_hex: hex(signSign1({ alg: 'EdDSA', kid: W.kid, priv: W.priv, payload: aarPayload(), protOverride: new Map([[4, u8(Buffer.from(W.kid, 'hex'))], cwt(), [16, 'application/aar-receipt+cbor']]), unprot: new Map([[1, -8]]) })) }, { result: 'reject' }, '§8.1 "protected alg"');
B('X44', 'valid', 'cose-verify', 'Untagged COSE_Sign1 (otherwise valid)', { cose_hex: hex(aar(W, { tag: false })) }, { result: 'ok' }, 'RFC 9052 §2: tag optional when context determines the type; §8.1 silent', 'AMBIGUITY-21');
{ const g = cbor.decode(good, { preferMap: true }); const arr = [u8(g.contents[0]), g.contents[1], null, u8(g.contents[3])];
  B('X45', 'invalid', 'cose-verify', 'Detached payload', { cose_hex: hex(Buffer.from(cbor.encode(new cbor.Tag(18, arr)))) }, { result: 'reject' }, '§8.1 "payload: the aar map below, attached"'); }
{ const L = buildLedger(W);
  const base = { tool_id: 'tool-A', request, proof: L.proof };
  B('X46', 'valid', 'cose-tool', 'now == expires is not "after expires"', { ...base, cose_hex: hex(good), now: 400 }, { result: 'accept' }, '§8.4 check 7 "witness time is not after expires"');
  B('X47', 'invalid', 'cose-tool', 'independence "none" statement presented to a tool', { ...base, cose_hex: hex(aar(W, { over: { independence: 'none' } })), now: 200 }, { result: 'reject' }, '§4.3 "verifiers MUST NOT treat them as witness receipts"; §2 Tool "Executes only against a valid AAR"', 'AMBIGUITY-15');
  B('X48', 'invalid', 'cose-tool', 'Inclusion path with wrong side label', { ...base, cose_hex: hex(good), now: 200, proof: { ...L.proof, path: [['R', L.proof.path[0][1]]] } }, { result: 'reject', reason: 'INCLUSION_INVALID' }, '§8.4(9)', 'AMBIGUITY-22');
}
{ // ES256 signature malleability: (r, s) -> (r, n - s) is also valid; replay store must not key on bytes
  const L = buildLedger(W2);
  const a = aar(W2);
  const d = cbor.decode(a, { preferMap: true }); const arr = [u8(d.contents[0]), d.contents[1], u8(d.contents[2]), u8(d.contents[3])]; const sig = Buffer.from(arr[3]);
  const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const s = BigInt('0x' + sig.subarray(32).toString('hex'));
  const s2 = (n - s).toString(16).padStart(64, '0');
  arr[3] = u8(Buffer.concat([sig.subarray(0, 32), Buffer.from(s2, 'hex')]));
  const mall = Buffer.from(cbor.encode(new cbor.Tag(18, arr)));
  put({ id: 'X49', class: 'invalid', kind: 'cose-tool', title: 'Replay of the same AAR with a malleated ES256 signature (r, n-s)', keys: W2.keys, tool_id: 'tool-A', request, proof: L.proof, now: 200,
    presentations: [{ cose_hex: hex(a) }, { cose_hex: hex(mall) }],
    expected: { steps: [{ result: 'accept' }, { result: 'reject', reason: 'REPLAY' }] }, basis: '§8.4 check 6 "this AAR has not been accepted before" (identity of "this AAR" undefined)', ambiguity: 'AMBIGUITY-7' });
}
{ // ledger transplant: entry 1 carries another ledger id
  const L = buildLedger(W);
  const forged = signSign1({ alg: 'EdDSA', kid: W.kid, priv: W.priv, typ: 'application/aar-ledger-entry+cbor', payload: { t: 100, seq: 1, body: { id: 'r0', ttl: 300, action: request, reason: 'OK', mandate: 'm1', verdict: 'allow', audience: 'tool-A' }, prev: u8(sha256(L.e0)), type: 'RECEIPT', ledger: u8(Buffer.alloc(32, 9)) } });
  put({ id: 'X50', class: 'invalid', kind: 'cose-ledger', title: 'Entry transplanted from another ledger (ledger id differs)', keys: W.keys,
    registry: { source: 'vector-registry', principals: { p1: { alg: 'EdDSA', pub: P1.pub, name: 'p1-key' } } }, principal: 'p1', require_cose: true,
    ledger_hex: [hex(L.e0), hex(forged)], expected: { result: 'invalid' }, basis: '§12.4 "Ledger entries are bound to the ledger identifier" (no verifier step or code)', ambiguity: 'AMBIGUITY-23' });
  put({ id: 'X51', class: 'valid', kind: 'cose-ledger', title: 'Honest 2-entry ledger built by verifier_js (cross-check for implementation A)', keys: W.keys,
    registry: { source: 'vector-registry', principals: { p1: { alg: 'EdDSA', pub: P1.pub, name: 'p1-key' } } }, principal: 'p1', require_cose: true,
    ledger_hex: [hex(L.e0), hex(L.e1)], checkpoint_hex: hex(L.ck), expected: { result: 'valid', anchor: 'none' }, basis: '§7.1, §9.1, §10' });
}
console.log('written', fs.readdirSync(OUT).length, 'vectors to', OUT);
