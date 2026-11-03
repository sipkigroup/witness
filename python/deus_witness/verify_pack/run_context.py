"""0.2.85: checks runs/<id>.cose of an evidence pack -- the CI run context the witness signed (server app/runctx.py).

For each file: the witness signature (typ application/dw-run-context+cbor, the pack's witness key), the id = the file name, the ledger
id = this pack's ledger, the ledger position (`at_head` = hash of the entry at `at_seq`), and every linked decision (`receipts`: each
[rid, seq] must be the RECEIPT entry with that id at that seq, not after `at_seq`). Any failure is INVALID (RUN_CONTEXT_SIG,
RUN_CONTEXT_MALFORMED, RUN_CONTEXT_CHAIN, RUN_CONTEXT_LINK). A file under runs/ that is not <id>.cose is `warning RUN_EXTRA_FILE`.
The claimed values (repository, commit, run id, workflow, actor, start) are printed as DECLARED by the CI job: the signature proves the
witness received them at its time t, not that they are true (the `trust:` line says so).
0.2.86: a record with `verified: "github-oidc"` was made from a GitHub Actions OIDC token the witness checked (RS256 signature against
GitHub's JWKS, issuer, audience = the witness origin, validity); its repository / commit / run / attempt / workflow / actor / ref are
printed as VERIFIED with the kid of GitHub's key and the token's SHA-256. The token is not in the pack: offline, this checks the
WITNESS's signature over "I verified a GitHub token with these claims", not GitHub's signature. A record made with a test key set
(oidc.jwks "test-file") is printed as TEST JWKS (warning RUN_CONTEXT_TEST_JWKS): it proves nothing about GitHub.
0.2.87: the same bytes are the deus-witness client's checker (deus_witness/verify_pack/run_context.py, from client 0.2.55; a test keeps
the two copies identical). The client calls run_lines(..., tolerant=True): a member this checker does not know (a later server's record),
in the record or in `oidc`, or a `verified` method it does not know, is `warning RUN_CONTEXT_UNKNOWN_FIELD` (the values of an unknown
method are printed as DECLARED), not INVALID; the signature, the ledger position and every linked decision are still checked. The pack's
own copy (verify/, shipped with the server that made the records) stays strict: there an unknown member is RUN_CONTEXT_MALFORMED.
`repository_id` / `repository_owner_id` (taken from the token) are printed with a verified record."""
import glob
import os
import re

TYP_RUN = "application/dw-run-context+cbor"
V = "dw-run-context-1"
_ID = re.compile(r"rc_[A-Z2-7]{16}")
KEYS = {"v", "type", "id", "account", "agent", "ledger", "at_seq", "at_head", "t", "claimed", "claimed_by", "note", "link", "receipts",
        "truncated", "window", "verified", "oidc"}
OIDC_ISS = "https://token.actions.githubusercontent.com"
OIDC_KEYS = {"iss", "aud", "kid", "jwk_sha256", "jwks", "token_sha256", "iat", "exp"}
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _shape(p, tolerant=False, unknown=None):
    """-> None or the first offending member. tolerant: members not in KEYS / OIDC_KEYS and an unknown `verified` method are appended
    to `unknown` (a list) instead of failing."""
    if not isinstance(p, dict):
        return "members"
    extra = sorted(str(k)[:40] for k in set(p) - KEYS)
    if extra:
        if not tolerant:
            return "members"
        unknown.extend(extra)
    if p.get("v") != V or p.get("type") != "RUN_CONTEXT":
        return "v/type"
    for k in ("id", "account", "agent", "claimed_by", "note"):
        if not isinstance(p.get(k), str):
            return k
    if not isinstance(p.get("ledger"), bytes) or not isinstance(p.get("at_head"), bytes) or not _uint(p.get("at_seq")) or not _uint(p.get("t")):
        return "ledger/at_seq/at_head/t"
    if not isinstance(p.get("claimed"), dict) or not p["claimed"]:
        return "claimed"
    if p.get("link") not in ("session", "window", "none") or not isinstance(p.get("truncated"), bool):
        return "link/truncated"
    r = p.get("receipts")
    if not isinstance(r, list) or not all(isinstance(x, list) and len(x) == 2 and isinstance(x[0], str) and _uint(x[1]) for x in r):
        return "receipts"
    w = p.get("window")
    if w is not None and not (isinstance(w, list) and len(w) == 2 and _uint(w[0]) and _uint(w[1])):
        return "window"
    if tolerant and isinstance(p.get("verified"), str) and p["verified"] != "github-oidc":
        unknown.append("verified=%s" % p["verified"][:40])           # a later verification method: its values are shown as declared
        return None
    if "verified" in p or "oidc" in p:               # 0.2.86: both or neither
        o = p.get("oidc")
        if p.get("verified") != "github-oidc" or not isinstance(o, dict) or not OIDC_KEYS <= set(o):
            return "verified/oidc"
        if set(o) - OIDC_KEYS:
            if not tolerant:
                return "verified/oidc"
            unknown.extend("oidc.%s" % k for k in sorted(str(x)[:40] for x in set(o) - OIDC_KEYS))
        if o["iss"] != OIDC_ISS or o["jwks"] not in ("github", "test-file") or not all(isinstance(o[k], str) for k in ("aud", "kid", "jwk_sha256")) \
                or not isinstance(o["token_sha256"], str) or not _HEX64.fullmatch(o["token_sha256"]) or not _uint(o["iat"]) or not _uint(o["exp"]):
            return "oidc"
        c = p["claimed"]
        if not all(isinstance(c.get(k), str) for k in ("repository", "commit", "run_id", "run_attempt", "actor")):
            return "claimed (verified)"
    return None


def _show(v):
    return "-" if v is None else str(v)[:120]


def _ids(c):
    ids = [(n, c.get(k)) for k, n in (("repository_id", "repository id"), ("repository_owner_id", "owner id")) if c.get(k) is not None]
    return ", %s" % ", ".join("%s %s" % (n, _show(v)) for n, v in ids) if ids else ""


def run_lines(root, wk, entries, cose, tolerant=False):
    """-> (lines, bad, n_checked). `entries` = the ledger entries as verify.load_entries gives them (verified chain).
    tolerant (the client): unknown members are a warning, not INVALID (see the module text)."""
    files = sorted(glob.glob(os.path.join(root, "runs", "*")))
    if not files:
        return [], False, 0
    by_seq = {e["seq"]: e for e in entries}
    lid = entries[0].get("ledger") if entries else None
    lines, bad, n = [], False, 0
    for f in files:
        name = os.path.basename(f)
        if not (name.endswith(".cose") and _ID.fullmatch(name[:-5])):
            lines.append("run context: warning RUN_EXTRA_FILE runs/%s (not read: it is no evidence)" % name)
            continue
        n += 1
        try:
            p = cose.loads(cose.verify1(open(f, "rb").read(), [wk], TYP_RUN)[0])
        except Exception:      # noqa: BLE001  (not COSE, not the witness key, altered bytes)
            lines.append("run context %s: INVALID RUN_CONTEXT_SIG (not signed by the witness key of this pack, or altered)" % name[:-5])
            bad = True
            continue
        unknown = []
        why = _shape(p, tolerant, unknown)
        if why or p["id"] != name[:-5]:
            lines.append("run context %s: INVALID RUN_CONTEXT_MALFORMED (%s)" % (name[:-5], why or "id is not the file name"))
            bad = True
            continue
        e = by_seq.get(p["at_seq"])
        if p["ledger"] != lid or e is None or e["hash"] != p["at_head"] or e.get("t", 0) > p["t"]:
            lines.append("run context %s: INVALID RUN_CONTEXT_CHAIN (not at seq %d of this ledger: another ledger, or a ledger that was rewritten)"
                         % (p["id"], p["at_seq"]))
            bad = True
            continue
        broken = [r for r, s in p["receipts"]
                  if s > p["at_seq"] or by_seq.get(s) is None or by_seq[s]["type"] != "RECEIPT" or not isinstance(by_seq[s]["body"], dict)
                  or by_seq[s]["body"].get("id") != r]
        if broken:
            lines.append("run context %s: INVALID RUN_CONTEXT_LINK (%d linked decision(s) are not that RECEIPT entry: %s)"
                         % (p["id"], len(broken), ", ".join(broken[:5])))
            bad = True
            continue
        rids = {r for r, _s in p["receipts"]}
        appr = {}
        for x in entries:
            if x["type"] == "APPROVAL" and isinstance(x["body"], dict) and x["body"].get("receipt") in rids:
                appr[x["body"]["receipt"]] = bool(x["body"].get("approved"))
        verdicts = {}
        for r, s in p["receipts"]:
            v = by_seq[s]["body"].get("verdict")
            verdicts[v] = verdicts.get(v, 0) + 1
        if unknown:
            lines.append("run context %s: warning RUN_CONTEXT_UNKNOWN_FIELD %s (from a later server: this checker does not read them; the "
                         "signature, ledger position and links are checked)" % (p["id"], ", ".join(unknown[:10])))
        c = p["claimed"]
        if p.get("verified") == "github-oidc":
            o = p["oidc"]
            test = o["jwks"] == "test-file"
            if test:
                lines.append("run context %s: warning RUN_CONTEXT_TEST_JWKS (verified against a TEST key set, not GitHub's: it proves nothing about "
                             "GitHub)" % p["id"])
            lines.append("run context %s: signed by the witness at seq %d; VERIFIED by the witness from a GitHub OIDC token%s (iss %s, aud %s, kid %s, "
                         "token sha256 %s, valid %s..%s): repository %s, commit %s, run %s (attempt %s), workflow %s, workflow_ref %s, actor %s, ref %s%s; "
                         "DECLARED by the CI job: started %s, sessions %s"
                         % (p["id"], p["at_seq"], " [TEST JWKS]" if test else "", o["iss"], _show(o["aud"]), _show(o["kid"]), o["token_sha256"][:16],
                            o["iat"], o["exp"], _show(c.get("repository")), _show(c.get("commit")), _show(c.get("run_id")), _show(c.get("run_attempt")),
                            _show(c.get("workflow")), _show(c.get("workflow_ref")), _show(c.get("actor")), _show(c.get("ref")), _ids(c),
                            _show(c.get("started_at")), ",".join(c.get("session_ids") or []) or "-"))
        else:
            lines.append("run context %s: signed by the witness at seq %d; DECLARED by the CI job: repository %s, commit %s, run %s (attempt %s), "
                         "workflow %s, actor %s, started %s, sessions %s"
                         % (p["id"], p["at_seq"], _show(c.get("repository")), _show(c.get("commit")), _show(c.get("run_id")), _show(c.get("run_attempt")),
                            _show(c.get("workflow")), _show(c.get("actor")), _show(c.get("started_at")), ",".join(c.get("session_ids") or []) or "-"))
        lines.append("run context %s: %d decision(s) linked by %s%s (%s); owner answers among them: %d approved, %d refused"
                     % (p["id"], len(p["receipts"]), p["link"], " %s..%s" % tuple(p["window"]) if p.get("window") else "",
                        ", ".join("%s %d" % kv for kv in sorted(verdicts.items())) or "none", sum(appr.values()), len(appr) - sum(appr.values()))
                     + ("; TRUNCATED to the newest %d" % len(p["receipts"]) if p["truncated"] else ""))
    return lines, bad, n
