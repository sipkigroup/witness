// verifier_js — independent clean-room reading of draft-deus-aar-00 (rev 4.1 text).
// Decision function: Section 6.4 (normative) + Sections 5.2-5.6, 6.2, 6.5.
// Every branch cites the paragraph it implements. Where the text gives no
// answer, the code fails closed with reason UNDEFINED_BY_SPEC and the place
// is listed as an AMBIGUITY in OTCHET-INTEROP.

export const REGISTERED = new Set(['message', 'file', 'disclosure', 'purchase', 'sale',
  'refund', 'meeting', 'delete', 'publish', 'http']);    // §5.6 table + PROPOSAL-08-http (0.2.43)
import { allowed as httpAllowed } from './httpcanon.mjs';
export const NON_PROTECTED = new Set(['city']);          // §5.5
export const isProtected = (c) => !NON_PROTECTED.has(c); // §5.5 "every unregistered ... protected"
export const MAX_AMOUNT = 10n ** 15n;                    // §5.2

// §5.4 canonicalisation. "case folding" is implemented as full Unicode case
// folding approximated by toUpperCase().toLowerCase() (maps ß -> ss, ς -> σ).
export function canonRecipient(r) {
  if (typeof r !== 'string') return null;
  let s = r;
  const all = [...s.matchAll(/<([^<>]*)>/g)];   // "Name <addr>" -> addr
  if (all.length > 1) return null;              // several <addr>: fail closed (AMBIGUITY-14)
  if (all.length === 1) s = all[0][1];
  s = s.normalize('NFKC');
  s = s.toUpperCase().toLowerCase();         // full case folding (approx.)
  s = s.replace(/\s+/gu, '');                // remove all white space
  return s;
}
const domainOf = (canon) => { const i = canon.lastIndexOf('@'); return i < 0 ? null : canon.slice(i + 1); };

// recipients = { "to": "*" / [* tstr] / null, ? "domains": [* tstr] }   (§6.1)
// "unspecified recipients": to is null/absent AND no domains key.
// An explicit empty list is an explicit (empty) specification.
export function recipientsUnspecified(p) {
  if (p === undefined || p === null || p === true) return true;
  const toUnspec = p.to === undefined || p.to === null;
  return toUnspec && (p.domains === undefined || p.domains === null);
}
export function recipientMatches(p, recipient) {
  const c = canonRecipient(recipient);
  if (c === null) return false;
  if (p.to === '*') return true;
  if (Array.isArray(p.to) && p.to.map(canonRecipient).includes(c)) return true;
  if (Array.isArray(p.domains)) {
    const d = domainOf(c);
    if (d !== null && p.domains.map(canonRecipient).includes(d)) return true; // exact domain, §5.4
  }
  return false;
}

// Numbers: JSON vectors are parsed with source access so 1.0 stays a float
// (see run.mjs). A float is represented as {__float: <number>}.
export function amountValid(a) {
  if (a && typeof a === 'object' && '__float' in a) return false;   // floating point -> BAD_AMOUNT
  if (typeof a === 'bigint') return a >= 0n && a <= MAX_AMOUNT;
  if (typeof a !== 'number' || !Number.isInteger(a)) return false;
  return a >= 0 && BigInt(a) <= MAX_AMOUNT;                          // "above 10^15" -> reject
}
const num = (a) => (typeof a === 'bigint' ? Number(a) : a);

// §5.6 risk level, computed from the action content.
export function riskOf(A) {
  const prot = (A.data || []).some(isProtected);
  switch (A.class) {
    case 'message': return prot ? 'disclosure' : 'low';
    case 'file': return 'disclosure';
    case 'disclosure': return prot ? 'disclosure' : 'low';
    case 'purchase': case 'sale': case 'refund': return 'monetary';
    case 'meeting': return A.principal_present === true ? 'low' : 'irreversible';
    case 'delete': return A.reversible === true ? 'low' : 'irreversible';   // "reversible flag, default false"
    case 'publish': case 'http': return 'disclosure';
    default: return 'irreversible';
  }
}

const deny = (reason, risk) => ({ verdict: 'deny', reason, risk });
const defer = (reason, risk) => ({ verdict: 'defer', reason, risk });
const allow = (reason, risk) => ({ verdict: 'allow', reason, risk });

// Named circle §6.5: recipient in an EXPLICIT list of another of message/file/disclosure.
function inCircle(M, cls, recipient) {
  if (M.named_circle !== true) return false;
  for (const other of ['message', 'file', 'disclosure']) {
    if (other === cls) continue;
    const p = M.permissions?.[other];
    if (!p || p === false) continue;
    if (!Array.isArray(p.to)) continue;                 // "explicit list"
    if (p.to.map(canonRecipient).includes(canonRecipient(recipient))) return true;
  }
  return false;
}

/**
 * evaluate(M, A, S, opts)
 *  M: mandate object or null; A: action; S: { committedM, committedP, ceiling }
 *  opts: { now (witness time), mandateSigValid (bool), revoked (bool) }
 */
export function evaluate(M, A, S = {}, opts = {}) {
  const now = opts.now ?? A.t;
  const risk = riskOf(A);
  // 1
  if (!M) return deny('NO_MANDATE', risk);
  // 2
  if (opts.mandateSigValid === false) return deny('MANDATE_SIG', risk);
  // 3
  if (A.agent !== M.agent) return deny('AGENT_MISMATCH', risk);
  // 4 closed interval [nbf, exp]
  if (opts.revoked || num(now) < num(M.nbf) || num(now) > num(M.exp)) return deny('EXPIRED', risk);
  // 5
  if (!REGISTERED.has(A.class)) return deny('CLASS_UNKNOWN', risk);
  // 6 §5.2 (currency compared only when both sides state one; see AMBIGUITY)
  if (!amountValid(A.amount)) return deny('BAD_AMOUNT', risk);
  if (A.currency !== undefined && M.currency !== undefined && A.currency !== M.currency)
    return deny('BAD_AMOUNT', risk);
  const data = A.data || [];
  // 7
  if (data.some((d) => (M.forbidden_data || []).includes(d))) return deny('DATA_FORBIDDEN', risk);
  const perms = M.permissions || {};
  // CDDL allows only absent/false/spec; a JSON null is read as absent (AMBIGUITY-11)
  const P = perms[A.class] === null ? undefined : perms[A.class];
  // 8
  if (P === false) return deny('CLASS_DENIED', risk);
  // 9 (normative text: meeting -> UNATTENDED_MEETING, anything else -> CLASS_UNKNOWN)
  if (risk === 'irreversible') return deny(A.class === 'meeting' ? 'UNATTENDED_MEETING' : 'CLASS_UNKNOWN', risk);

  // 10 class rule
  const amt = num(A.amount);
  const prot = data.some(isProtected);
  let R;
  const recipientRule = (p, cls, unspecifiedResult) => {
    if (p === undefined || recipientsUnspecified(p)) return unspecifiedResult;
    if (recipientMatches(p, A.recipient)) return allow('OK', risk);
    if (inCircle(M, cls, A.recipient)) return allow('OK_CIRCLE', risk);
    return deny('RECIPIENT', risk);
  };
  switch (A.class) {
    case 'meeting':
      R = P === true ? allow('OK', risk) : allow('OK_UNSPECIFIED', risk); break;
    case 'message':
      R = recipientRule(perms.message, 'message', allow('OK_UNSPECIFIED', risk)); break;
    case 'disclosure':
      if (!prot) { R = recipientRule(perms.message, 'message', allow('OK_UNSPECIFIED', risk)); break; }
      // Text gives no class rule for disclosure WITH protected data: R is neutral
      // and step 12 decides (AMBIGUITY-1).
      R = allow('OK', risk); break;
    case 'file':
      if (P === undefined || recipientsUnspecified(P)) { R = defer('ESCALATE_FILE', risk); break; }
      R = recipientRule(P, 'file', defer('ESCALATE_FILE', risk)); break;
    case 'refund':
      R = (P === true || (P && typeof P === 'object')) ? allow('OK', risk) : defer('ESCALATE_MONEY', risk); break;
    case 'sale':
      if (P === undefined || P === true || P.min_price === undefined || P.min_price === null) { R = defer('ESCALATE_MONEY', risk); break; }
      R = amt < num(P.min_price) ? deny('PRICE', risk) : allow('OK', risk); break;
    case 'purchase': {
      const p = (P && typeof P === 'object') ? P : {};
      const max = p.max_per_action, budget = p.budget, ceil = S.ceiling;
      if (max !== undefined && max !== null && amt > num(max)) { R = deny('PER_ACTION_LIMIT', risk); break; }
      if (budget !== undefined && budget !== null && (S.committedM || 0) + amt > num(budget)) { R = deny('BUDGET', risk); break; }
      if (ceil !== undefined && ceil !== null && (S.committedP || 0) + amt > num(ceil)) { R = deny('CEILING', risk); break; }
      if (P === undefined || max === undefined || max === null || budget === undefined || budget === null) { R = defer('ESCALATE_MONEY', risk); break; }
      R = allow('OK', risk); break;
    }
    case 'delete': {
      // Reached only when reversible (irreversible is denied at step 9).
      // §5.6: "delete needs a resource target in the mandate". No CDDL, no code.
      if (P === undefined) { R = deny('UNDEFINED_BY_SPEC', risk); break; }
      const targets = Array.isArray(P.targets) ? P.targets : null;   // field name only known from vectors
      if (!targets) { R = deny('UNDEFINED_BY_SPEC', risk); break; }
      // §5.4: "Comparison is exact on the canonical form" — no wildcard syntax exists in the text.
      R = targets.map(canonRecipient).includes(canonRecipient(A.recipient)) ? allow('OK', risk) : deny('RECIPIENT', risk);
      break;
    }
    case 'publish': {
      // §5.6: "any protected data is denied", "needs a permitted channel".
      if (prot) { R = deny('DATA_FORBIDDEN', risk); break; }
      if (P === undefined) { R = deny('UNDEFINED_BY_SPEC', risk); break; }
      const ch = Array.isArray(P.channels) ? P.channels : null;
      if (!ch) { R = deny('UNDEFINED_BY_SPEC', risk); break; }
      R = ch.map(canonRecipient).includes(canonRecipient(A.recipient)) ? allow('OK', risk) : deny('RECIPIENT', risk);
      break;
    }
    case 'http': {
      // PROPOSAL-08-http PH-5: protected data first (step 12 does not apply); `true` is malformed; listed -> allow; unlisted deny -> RESOURCE; else ask.
      if (prot) { R = deny('DATA_FORBIDDEN', risk); break; }
      if (P === true) { R = deny('CLASS_DENIED', risk); break; }
      const hp = P && typeof P === 'object' && !Array.isArray(P) ? P : {};
      if (Array.isArray(hp.allow) && httpAllowed(hp.allow, A.recipient)) { R = allow('OK', risk); break; }
      R = hp.unlisted === 'deny' ? deny('RESOURCE', risk) : defer('ESCALATE_HTTP', risk);
      break;
    }
    default:
      R = deny('CLASS_UNKNOWN', risk);
  }
  // 11
  if (R.verdict === 'deny') return R;
  // 12 protected-data rule, every class
  let D = null;
  if (prot) {
    const dp = perms.disclosure;
    if (dp === false) D = deny('DATA_FORBIDDEN', risk);
    else if (dp === undefined || dp === null || dp === true || dp.data === null || dp.data === undefined) D = deny('DATA_NOT_PERMITTED', risk);
    else if (data.filter(isProtected).some((c) => !dp.data.includes(c))) D = deny('DATA_FORBIDDEN', risk);
    else if (recipientsUnspecified(dp)) D = defer('ESCALATE_DATA', risk);
    else if (!recipientMatches(dp, A.recipient)) D = deny('RECIPIENT', risk);   // circle never applies
  }
  // 13
  if (D && D.verdict === 'deny') return D;
  if (D && D.verdict === 'defer' && R.verdict === 'allow') return D;
  return R;
}
