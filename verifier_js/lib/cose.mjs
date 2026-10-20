// COSE_Sign1 (RFC 9052) on top of the third-party `cbor2` codec and OpenSSL
// signatures via node:crypto. Only Sig_structure assembly is written here.
import { createRequire } from 'module';
import crypto from 'crypto';
const require = createRequire(import.meta.url);
const cbor = require('cbor2');

const DEC = { preferMap: true, rejectDuplicateKeys: true };
export const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
export const hex = (b) => Buffer.from(b).toString('hex');
export const cdeEncode = (v) => Buffer.from(cbor.encode(plain(v), cbor.cdeEncodeOptions));
function plain(x) { if (Buffer.isBuffer(x)) return new Uint8Array(x); if (x instanceof Map) return new Map([...x].map(([k, v]) => [k, plain(v)])); if (Array.isArray(x)) return x.map(plain); if (x && typeof x === 'object' && !(x instanceof Uint8Array) && x.constructor === Object) { const o = {}; for (const k of Object.keys(x)) o[k] = plain(x[k]); return o; } return x; }
export const decode = (b, extra = {}) => cbor.decode(Buffer.from(b), { ...DEC, ...extra });
export const encode = (v) => Buffer.from(cbor.encode(v));

export const ALG = { [-8]: 'EdDSA', [-7]: 'ES256' };

export class CoseError extends Error { constructor(code, msg) { super(msg || code); this.code = code; } }

// Convert decoded CBOR (Maps with text keys) into plain JS objects for payloads.
export function toJS(x) {
  if (x instanceof Map) { const o = {}; for (const [k, v] of x) o[String(k)] = toJS(v); return o; }
  if (Array.isArray(x)) return x.map(toJS);
  if (typeof x === 'number' && !Number.isInteger(x)) return { __float: x };
  return x;
}

/** Parse COSE_Sign1 bytes. Returns {protBytes, prot(Map), unprot, payloadBytes, payload(Map), sig, tagged} */
export function parseSign1(bytes, { requireTag = false } = {}) {
  let d;
  try { d = decode(bytes, { keepTags: false }); } catch (e) { throw new CoseError('MALFORMED', 'CBOR: ' + e.message); }
  let tagged = false;
  if (d && typeof d === 'object' && d.tag !== undefined && 'contents' in d) {
    if (Number(d.tag) !== 18) throw new CoseError('MALFORMED', 'tag ' + d.tag + ' is not COSE_Sign1');
    d = d.contents; tagged = true;
  }
  if (requireTag && !tagged) throw new CoseError('MALFORMED', 'untagged');
  if (!Array.isArray(d) || d.length !== 4) throw new CoseError('MALFORMED', 'not COSE_Sign1');
  const [protBytes, unprot, payloadBytes, sig] = d;
  if (!(protBytes instanceof Uint8Array)) throw new CoseError('MALFORMED', 'protected not bstr');
  if (!(unprot instanceof Map)) throw new CoseError('MALFORMED', 'unprotected not map');
  if (!(sig instanceof Uint8Array)) throw new CoseError('MALFORMED', 'signature not bstr');
  if (payloadBytes === null || payloadBytes === undefined) throw new CoseError('MALFORMED', 'detached payload (§8.1 requires attached)');
  if (!(payloadBytes instanceof Uint8Array)) throw new CoseError('MALFORMED', 'payload not bstr');
  let prot;
  try { prot = protBytes.length ? decode(protBytes) : new Map(); } catch (e) { throw new CoseError('MALFORMED', 'protected: ' + e.message); }
  if (!(prot instanceof Map)) throw new CoseError('MALFORMED', 'protected not map');
  let payload;
  try { payload = decode(payloadBytes); } catch (e) { throw new CoseError('MALFORMED', 'payload: ' + e.message); }
  // §5.1: payloads MUST be Core Deterministic Encoding. Re-encode and compare.
  let deterministic = true;
  try { deterministic = cdeEncode(payload).equals(Buffer.from(payloadBytes)); } catch { deterministic = false; }
  return { protBytes: Buffer.from(protBytes), prot, unprot, payloadBytes: Buffer.from(payloadBytes), payload, sig: Buffer.from(sig), tagged, deterministic };
}

function keyObject(k) {
  const pub = Buffer.from(k.pub, 'hex');
  if (k.alg === 'EdDSA') return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url') }, format: 'jwk' });
  if (k.alg === 'ES256') {
    if (pub[0] !== 4 || pub.length !== 65) throw new CoseError('MALFORMED', 'ES256 key must be uncompressed point');
    return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') }, format: 'jwk' });
  }
  throw new CoseError('ALG', 'unsupported key alg ' + k.alg);
}

const u8 = (b) => new Uint8Array(b.buffer ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b);
export function sigStructure(protBytes, payloadBytes) {
  // cbor2 serialises Node Buffers via toJSON; pass plain Uint8Arrays.
  return encode(['Signature1', u8(protBytes), new Uint8Array(0), u8(payloadBytes)]);
}

/**
 * Verify under a key set {kidHex: {alg, pub}}. Returns parsed object.
 * Failure codes (internal): KID_UNKNOWN, ALG_MISMATCH, SIG_INVALID, TYP_MISMATCH, MALFORMED, ALG_UNPROTECTED.
 */
export function verifySign1(bytes, keys, { typ } = {}) {
  const p = parseSign1(bytes);
  if (!p.prot.has(1)) throw new CoseError(p.unprot.has(1) ? 'ALG_UNPROTECTED' : 'MALFORMED', 'alg not in protected header');
  const alg = ALG[p.prot.get(1)];
  if (!alg) throw new CoseError('ALG_MISMATCH', 'unsupported alg ' + p.prot.get(1));
  const kid = p.prot.get(4) ?? p.unprot.get(4);
  if (!(kid instanceof Uint8Array)) throw new CoseError('KID_UNKNOWN', 'no kid');
  const k = keys[hex(kid)];
  if (!k) throw new CoseError('KID_UNKNOWN', 'kid not in key set');
  if (k.alg !== alg) throw new CoseError('ALG_MISMATCH', `header ${alg} vs key ${k.alg}`);
  const data = sigStructure(p.protBytes, p.payloadBytes);
  let ok = false;
  try {
    const ko = keyObject(k);
    ok = alg === 'EdDSA' ? crypto.verify(null, data, ko, p.sig) : crypto.verify('sha256', data, { key: ko, dsaEncoding: 'ieee-p1363' }, p.sig);
  } catch { ok = false; }
  if (!ok) throw new CoseError('SIG_INVALID', 'signature does not verify');
  if (typ !== undefined && p.prot.get(16) !== typ) throw new CoseError('TYP_MISMATCH', `typ ${p.prot.get(16)} != ${typ}`);
  p.kidHex = hex(kid); p.alg = alg;
  return p;
}

// ---- signing helpers (used only by gen-extra.mjs for our own vectors) ----
export function signSign1({ alg, kid, priv, typ, extraProt = [], payload, payloadBytes, unprot = new Map(), tag = true, protOverride }) {
  const prot = protOverride ?? new Map([[1, alg === 'EdDSA' ? -8 : -7], [4, u8(Buffer.from(kid, 'hex'))], ...extraProt, ...(typ ? [[16, typ]] : [])]);
  const protBytes = Buffer.from(cbor.encode(prot, cbor.cdeEncodeOptions));
  const pb = payloadBytes ?? cdeEncode(payload);
  const data = sigStructure(protBytes, pb);
  const sig = alg === 'EdDSA' ? crypto.sign(null, data, priv) : crypto.sign('sha256', data, { key: priv, dsaEncoding: 'ieee-p1363' });
  const arr = [u8(protBytes), unprot, u8(pb), u8(sig)];
  return Buffer.from(cbor.encode(tag ? new cbor.Tag(18, arr) : arr));
}
export { cbor };
