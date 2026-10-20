#!/usr/bin/env node
// Runs every vector (spec/vectors abstract + cose/ byte-level + verifier_js/extra-vectors)
// through verifier_js and prints a match table. Usage: node run.mjs [--json out.json]
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { evaluate } from './lib/evaluate.mjs';
import { Witness } from './lib/witness.mjs';
import { verifyAbstract, verifyCoseLedger } from './lib/verifier.mjs';
import { coseVerify, coseMandate, coseTool } from './lib/tool.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC = path.join(HERE, '..', 'spec', 'vectors');

// JSON with source access: a number literal containing '.', 'e' or 'E' is a float.
const parse = (txt) => JSON.parse(txt, function (k, v, ctx) {
  if (typeof v === 'number' && ctx && typeof ctx.source === 'string' && /[.eE]/.test(ctx.source)) return { __float: v };
  return v;
});
const load = (f) => parse(fs.readFileSync(f, 'utf8'));

function runDecision(v) {
  const i = v.input;
  const ls = i.ledger_state || {};
  const S = { committedM: ls.mandate_committed || 0, committedP: ls.principal_committed || 0, ceiling: ls.ceiling ?? null };
  const r = evaluate(i.mandate, i.action, S, { now: i.now ?? i.action.t, mandateSigValid: i.mandate_signature_valid, revoked: i.revoked });
  return { got: { verdict: r.verdict, reason: r.reason }, outcome: r.verdict === v.expected.verdict, full: r.verdict === v.expected.verdict && r.reason === v.expected.reason };
}
function stepOut(s) { return s.verdict ?? s.result; }
function runSequence(v) {
  const w = new Witness(v.input.pinned_principal_key);
  const got = v.input.ops.map((o) => w.op(o));
  const exp = v.expected.steps;
  let outcome = got.length === exp.length, full = outcome; const diffs = [];
  exp.forEach((e, k) => {
    const g = got[k] || {};
    const o = (e.result === undefined || g.result === e.result) && (e.verdict === undefined || g.verdict === e.verdict);
    const f = o && (e.reason === undefined || g.reason === e.reason);
    if (!o) outcome = false; if (!f) { full = false; diffs.push(`step ${k}: got ${stepOut(g)}/${g.reason ?? ''} want ${stepOut(e)}/${e.reason ?? ''}`); }
  });
  return { got, outcome, full, diffs };
}
function cmpVerification(r, e) {
  const outcome = r.result === e.result;
  let full = outcome && (e.reason === undefined || r.reason === e.reason) && (e.at === undefined || r.at === e.at)
    && (e.anchor === undefined || r.anchor === e.anchor) && (e.receipt === undefined || r.receipt === e.receipt);
  return { outcome, full };
}
function runVerification(v) { const r = verifyAbstract(v.input); return { got: r, ...cmpVerification(r, v.expected) }; }
function runCose(v) {
  let r;
  switch (v.kind) {
    case 'cose-verify': r = coseVerify(v); break;
    case 'cose-mandate': r = coseMandate(v); break;
    case 'cose-tool': r = coseTool(v); break;
    case 'cose-ledger': r = verifyCoseLedger(v); return { got: r, ...cmpVerification(r, v.expected) };
    default: return { got: { error: 'unknown kind ' + v.kind }, outcome: false, full: false };
  }
  if (Array.isArray(r)) {
    const exp = v.expected.steps; let outcome = true, full = true;
    exp.forEach((e, k) => { const g = r[k] || {}; if (g.result !== e.result) outcome = false; if (g.result !== e.result || (e.reason !== undefined && g.reason !== e.reason)) full = false; });
    return { got: r, outcome, full };
  }
  const outcome = r.result === v.expected.result || (v.expected.result === 'ok' && r.result === 'accept');
  return { got: r, outcome, full: outcome && (v.expected.reason === undefined || r.reason === v.expected.reason) };
}

function run(v) {
  try {
    if (v.kind === 'decision') return runDecision(v);
    if (v.kind === 'sequence') return runSequence(v);
    if (v.kind === 'verification') return runVerification(v);
    return runCose(v);
  } catch (e) { return { got: { error: String(e.stack || e) }, outcome: false, full: false }; }
}

const groups = [
  ['abstract', fs.readdirSync(SPEC).filter((f) => /^[DSV]\d+\.json$/.test(f)).sort().map((f) => path.join(SPEC, f))],
  ['byte', fs.readdirSync(path.join(SPEC, 'cose')).filter((f) => /^C\d+\.json$/.test(f)).sort().map((f) => path.join(SPEC, 'cose', f))],
  ['extra', fs.existsSync(path.join(HERE, 'extra-vectors')) ? fs.readdirSync(path.join(HERE, 'extra-vectors')).filter((f) => f.endsWith('.json')).sort().map((f) => path.join(HERE, 'extra-vectors', f)) : []],
];
const all = [];
for (const [g, files] of groups) {
  let o = 0, f = 0;
  console.log(`\n## ${g} (${files.length})`);
  console.log('| id | class | expected | verifier_js | outcome | full |');
  console.log('|---|---|---|---|---|---|');
  for (const file of files) {
    const v = load(file);
    const r = run(v);
    if (r.outcome) o++; if (r.full) f++;
    const exp = v.expected.steps ? `${v.expected.steps.length} steps` : `${v.expected.verdict ?? v.expected.result} ${v.expected.reason ?? ''}${v.expected.at !== undefined ? '@' + v.expected.at : ''}${v.expected.anchor ? ' ' + v.expected.anchor : ''}`;
    const got = Array.isArray(r.got) ? r.got.map((x) => (x.verdict ?? x.result) + (x.reason ? ' ' + x.reason : '')).join('; ') :
      r.diffs ? (r.diffs.length ? r.diffs.join('; ') : 'all steps equal') :
      r.got.error ? 'ERROR ' + r.got.error.split('\n')[0] : `${r.got.verdict ?? r.got.result} ${r.got.reason ?? ''}${r.got.at !== undefined ? '@' + r.got.at : ''}${r.got.anchor && r.got.result === 'valid' ? ' ' + r.got.anchor : ''}`;
    console.log(`| ${v.id} | ${v.class} | ${exp} | ${got} | ${r.outcome ? 'yes' : 'NO'} | ${r.full ? 'yes' : 'NO'} |`);
    all.push({ group: g, id: v.id, class: v.class, kind: v.kind, expected: v.expected, got: r.got, outcome: r.outcome, full: r.full, diffs: r.diffs });
  }
  console.log(`\n**${g}: outcome ${o}/${files.length}, outcome+reason ${f}/${files.length}**`);
}
const oi = process.argv.indexOf('--json');
if (oi > 0) fs.writeFileSync(process.argv[oi + 1], JSON.stringify(all, (k, v) => (typeof v === 'bigint' ? Number(v) : v instanceof Uint8Array ? Buffer.from(v).toString('hex') : v), 1));
