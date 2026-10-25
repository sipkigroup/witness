// verifier_js — class `http` (spec/PROPOSAL-08-http.md, PH-4): canonical form and matching of request targets and rules.
// Clean-room port written from the PROPOSAL text; nothing is imported from the Python side. Pure functions, no regular
// expression is applied to anything the agent or the owner wrote except fixed character-class tests on single tokens.
export const MAX_RULES = 200, MAX_RULE_LEN = 512, MAX_TARGET_LEN = 8192, DEFAULT_PORT = 443;

const UNRESERVED = new Set([...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'].map((c) => c.charCodeAt(0)));
const PCHAR_RAW = new Set([...UNRESERVED, ...[...`!$&'()*+,;=:@`].map((c) => c.charCodeAt(0))]);   // RFC 3986 pchar minus pct-encoded
const FORBIDDEN_PCT = (b) => b === 0x2f || b === 0x5c || b === 0x25 || b === 0x7f || b < 0x20;       // "/", "\", "%" (double encoding), controls
const HOST_CH = /^[a-z0-9_-]$/;
const HEX = /^[0-9A-Fa-f]$/;
const BAD_CAT = /^[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]$/u;   // control, format, surrogate, private, unassigned, line/paragraph separator
const ascii = (s) => { for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false; return true; };
const allDigits = (s) => s.length > 0 && /^[0-9]+$/.test(s);
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function canonMethod(m) {
  return typeof m === 'string' && m.length >= 1 && m.length <= 16 && /^[A-Za-z]+$/.test(m) ? m.toUpperCase() : null;
}
function port(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 5 || !/^[0-9]+$/.test(s) || s[0] === '0') return null;
  const p = Number(s);
  return p >= 1 && p <= 65535 ? p : null;
}
export function canonHost(h, wildcard = false) {
  if (typeof h !== 'string' || h === '' || !ascii(h)) return null;
  h = h.toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  let star = false;
  if (wildcard && h.startsWith('*.')) { star = true; h = h.slice(2); }
  if (h === '' || h.length > 253) return null;
  const labels = h.split('.');
  for (const lb of labels) {
    if (lb.length < 1 || lb.length > 63) return null;
    for (const c of lb) if (!HOST_CH.test(c)) return null;
  }
  if (labels.every(allDigits)) {          // an address: canonical dotted quad only, never a wildcard
    if (star || labels.length !== 4 || labels.some((lb) => (lb.length > 1 && lb[0] === '0') || Number(lb) > 255)) return null;
  } else if (allDigits(labels[labels.length - 1])) return null;
  if (star && labels.length < 2) return null;
  return (star ? '*.' : '') + h;
}
export function canonSegment(seg) {
  if (typeof seg !== 'string') return null;
  const out = [], raw = [];
  let i = 0;
  while (i < seg.length) {
    const c = seg[i];
    if (c === '%') {
      const hx = seg.slice(i + 1, i + 3);
      if (hx.length !== 2 || !HEX.test(hx[0]) || !HEX.test(hx[1])) return null;
      const b = parseInt(hx, 16);
      if (FORBIDDEN_PCT(b)) return null;
      raw.push(b);
      out.push(UNRESERVED.has(b) ? String.fromCharCode(b) : '%' + hx.toUpperCase());
      i += 3; continue;
    }
    const o = seg.charCodeAt(i);
    if (o > 127 || !PCHAR_RAW.has(o)) return null;
    raw.push(o); out.push(c); i++;
  }
  let text;
  try { text = strictUtf8.decode(Uint8Array.from(raw)); } catch { return null; }   // strict: overlong forms, surrogates, bad sequences
  if (text.normalize('NFKC') !== text) return null;
  for (const ch of text) if (BAD_CAT.test(ch)) return null;
  const semi = text.indexOf(';');
  const head = semi < 0 ? text : text.slice(0, semi);
  if (head === '.' || head === '..') return null;                                  // dot segment, also "..;x" and encoded forms
  return out.join('');
}
export function canonPath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.length > MAX_TARGET_LEN) return null;
  const segs = path.slice(1).split('/'), out = [];
  for (let k = 0; k < segs.length; k++) {
    if (segs[k] === '') { if (k !== segs.length - 1) return null; out.push(''); continue; }
    const c = canonSegment(segs[k]);
    if (c === null || c === '') return null;
    out.push(c);
  }
  return out;
}
export function canonTarget(t) {
  if (typeof t !== 'string' || t.length > MAX_TARGET_LEN) return null;
  const sp = t.indexOf(' ');
  if (sp <= 0) return null;
  const m = canonMethod(t.slice(0, sp)), rest = t.slice(sp + 1), sl = rest.indexOf('/');
  if (m === null || sl <= 0) return null;
  const auth = rest.slice(0, sl), path = rest.slice(sl);
  const colon = auth.lastIndexOf(':');
  if (colon < 0) return null;                                                      // the request side has no default port
  const host = canonHost(auth.slice(0, colon)), p = port(auth.slice(colon + 1)), segs = canonPath(path);
  if (host === null || p === null || segs === null) return null;
  return { m, host, port: p, segs };
}
export function parseRule(r) {
  if (typeof r !== 'string' || r.length === 0 || r.length > MAX_RULE_LEN || r.includes(',')) return null;
  const sp = r.indexOf(' ');
  if (sp <= 0) return null;
  const mt = r.slice(0, sp), rest = r.slice(sp + 1);
  const m = mt === '*' ? '*' : canonMethod(mt), sl = rest.indexOf('/');
  if (m === null || sl <= 0 || rest.includes(' ')) return null;
  const auth = rest.slice(0, sl), path = rest.slice(sl);
  let hostText, p;
  if (auth.includes(':')) { const c = auth.lastIndexOf(':'); hostText = auth.slice(0, c); p = port(auth.slice(c + 1)); } else { hostText = auth; p = DEFAULT_PORT; }
  const host = canonHost(hostText, true);
  if (host === null || p === null) return null;
  const segs = path.slice(1).split('/'), out = [];
  for (let k = 0; k < segs.length; k++) {
    const s = segs[k], last = k === segs.length - 1;
    if (s === '*' || s === '**') { if (s === '**' && !last) return null; out.push(s); }
    else if (s === '') { if (!last) return null; out.push(''); }
    else { const c = canonSegment(s); if (c === null || c.includes('*')) return null; out.push(c); }
  }
  return { m, host, port: p, segs: out };
}
export const ruleText = (p) => `${p.m} ${p.host}${p.port === DEFAULT_PORT ? '' : ':' + p.port}/${p.segs.join('/')}`;
export function canonRule(r) {
  const p = parseRule(r);
  if (p === null) return null;
  const t = ruleText(p);
  return t.length <= MAX_RULE_LEN ? t : null;
}
export const isCanonicalRule = (r) => typeof r === 'string' && canonRule(r) === r;
function hostOk(rh, h) {
  if (rh.startsWith('*.')) { const suf = rh.slice(1); return h.endsWith(suf) && h.length > suf.length; }
  return rh === h;
}
export function ruleCovers(rule, tgt) {
  if ((rule.m !== '*' && rule.m !== tgt.m) || rule.port !== tgt.port || !hostOk(rule.host, tgt.host)) return false;
  const rs = rule.segs, segs = tgt.segs;
  let pre;
  if (rs.length && rs[rs.length - 1] === '**') { pre = rs.slice(0, -1); if (segs.length <= pre.length) return false; }
  else { pre = rs; if (segs.length !== rs.length) return false; }
  for (let k = 0; k < pre.length; k++) {
    if (pre[k] === '*') { if (segs[k] === '') return false; } else if (pre[k] !== segs[k]) return false;
  }
  return true;
}
/** Does any CANONICAL rule of the list cover the request target? A non-canonical entry never matches (fail closed). */
export function allowed(rules, target) {
  const tgt = canonTarget(target);
  if (tgt === null || !Array.isArray(rules)) return false;
  return rules.some((r) => isCanonicalRule(r) && ruleCovers(parseRule(r), tgt));
}
/** permissions.http well-formed? (PH-3) null/false ok; a map {allow: null | [<=200 unique canonical rules], unlisted: null|ask|deny} */
export function permWellFormed(p) {
  if (p === null || p === undefined || p === false) return true;
  if (typeof p !== 'object' || Array.isArray(p)) return false;
  if (Object.keys(p).some((k) => k !== 'allow' && k !== 'unlisted')) return false;
  if (p.unlisted !== undefined && p.unlisted !== null && p.unlisted !== 'ask' && p.unlisted !== 'deny') return false;
  const a = p.allow;
  if (a === undefined || a === null) return true;
  return Array.isArray(a) && a.every((r) => typeof r === 'string') && a.length <= MAX_RULES && new Set(a).size === a.length && a.every(isCanonicalRule);
}
