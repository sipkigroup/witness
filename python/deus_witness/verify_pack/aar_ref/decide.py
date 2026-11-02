"""Sections 5-6 of draft-deus-aar-01. Pure functions, no I/O.

Registered action classes: message file disclosure purchase sale meeting refund delete publish.
Any other class: deny CLASS_UNKNOWN (fail closed).

delete  permission: absent/None | False | {"targets": [str...], "allow_irreversible": bool}
        action.recipient = resource id (opaque, byte-exact; NOT canonicalised); action.reversible = bool (default false).
        target match: exact, or an entry of length >= 2 ending in "*" is a prefix match; a wildcard never matches an id with a
        "." or ".." path segment.   absent: reversible -> defer ESCALATE_DELETE, irreversible -> deny IRREVERSIBLE_DELETE.
publish permission: absent/None | False | {"channels": [str...]}   (action.recipient = channel id)
        any protected data -> deny DATA_FORBIDDEN (before everything else in the class rule); absent -> defer ESCALATE_PUBLISH.
command permission (extension): absent/None | False | {"allow": [str...], "unlisted": "ask"|"allow"|"deny"}
        action.recipient = command identifier (opaque, byte-exact, e.g. "ls", "git status"); action.dangerous = bool (default false).
        protected data -> deny DATA_FORBIDDEN; dangerous -> defer ESCALATE_COMMAND_DANGER (deny RESOURCE under unlisted "deny"; a list entry
        never covers a dangerous command); listed (Section 5.6.1 match) -> allow OK; extension: covered by the ALLOWANCE that action.allowance
        names (same mandate, command byte-exact, action.project byte-exact, witness time in [nbf, exp], not ended) -> allow OK_ALLOWANCE;
        else unlisted: absent/"ask" -> defer ESCALATE_COMMAND, "allow" -> allow OK_UNSPECIFIED, "deny" -> deny RESOURCE.
        extension (0.2.13): action.exec_changed (a non-empty list of files the line executes that changed since the principal confirmed them)
        -> defer ESCALATE_EXEC_CHANGED after the danger check and BEFORE the list, an allowance and `unlisted` (none of them covers it).
http permission (extension-http, 0.2.43): absent/None | False | {"allow": [canonical rule...], "unlisted": "ask"|"deny"}
        action.recipient = request target "<METHOD> <host>:<port><path>" (httpcanon.py). protected data -> deny DATA_FORBIDDEN; a rule of
        `allow` covers the canonical target -> allow OK; else unlisted "deny" -> deny RESOURCE, otherwise defer ESCALATE_HTTP. A target that
        cannot be canonicalised (dot segments, encoded "/", non-ASCII host ...) is never covered by a rule.
purchase permission: absent/None | False | {"max_per_action": uint, "budget": uint, "min_per_action": uint, "allowed_payees": [str...]}
        (0.2.83: min_per_action, allowed_payees; absent = as before). action.recipient = payee identifier. allowed_payees set and the
        recipient not in it (byte-exact) -> deny RECIPIENT; amount above max_per_action or below min_per_action -> deny PER_ACTION_LIMIT;
        then budget, ceiling, escalation as before.
Witness time is a PARAMETER of decide() (Section 5.3); action["t"] is only the harness shorthand used by abstract vectors.
"""
import re
import unicodedata

from . import httpcanon

CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass", "command", "http")   # -05: pass (Section 8.6); extension: command; extension-http: http
NON_PROTECTED = ("city",)


_WS = re.compile("[\t-\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]")   # Unicode White_Space
MAX_AMOUNT = 10 ** 15
MONETARY = ("purchase", "sale", "refund")


def _nfkc_cf(s):
    """toNFKC_Casefold (Unicode 3.13): NFKC, full case folding, NFKC, drop default-ignorable code points (Cf, variation selectors)."""
    s = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", str(s)).casefold())
    return "".join(c for c in s if unicodedata.category(c) != "Cf" and not 0xFE00 <= ord(c) <= 0xFE0F)


_MAILBOX = re.compile(r"[^@,;:<>()\[\]\"\\]+@[^@,;:<>()\[\]\"\\]+")


def canon_addr(s):
    """Section 5.4. -> canonical string, or None when the recipient is syntactically invalid (never matches)."""
    s = str(s)
    if "<" in s or ">" in s:
        m = re.fullmatch(r"[^<>]*<([^<>]+)>[^<>]*", s)
        if not m:
            return None
        s = m.group(1)
    s = _WS.sub("", _nfkc_cf(s))
    # ERRATA-04 E1 (review R-01): one mailbox only. Exactly one "@", non-empty local part and domain, no list/quote/comment/route characters.
    return s if _MAILBOX.fullmatch(s) else None


def canon_domain(s):
    return _WS.sub("", _nfkc_cf(s))


def protected(data):
    return sorted({x for x in data if x not in NON_PROTECTED})


def risk(a):
    c = a["class"]
    if c in ("purchase", "sale", "refund"):
        return "monetary"
    if c in ("file", "publish", "http"):
        return "disclosure"
    if c in ("message", "disclosure"):
        return "disclosure" if protected(a.get("data", [])) else "low"
    if c == "meeting":
        return "low" if a.get("principal_present") is True else "irreversible"      # -02 (C-22): only the boolean true counts
    if c == "delete":
        return "low" if a.get("reversible") is True else "irreversible"
    if c == "pass":
        return "low"                                       # -05 5.6: outside the mandate by the signed tool map
    if c == "command":
        return "irreversible" if a.get("dangerous") is True else "low"      # extension: only the boolean true counts
    return "irreversible"


def _circle(P):
    out = set()
    for n in ("message", "file", "disclosure"):
        p = P.get(n)
        if isinstance(p, dict) and isinstance(p.get("to"), list):
            out |= {canon_addr(x) for x in p["to"]}
    return out


def _recipient(p, rcpt, circ=frozenset()):
    if p.get("to") == "*":
        return True
    if p.get("to") is None and p.get("domains") is None:      # Section 6.2: unspecified iff `to` null/absent and `domains` absent
        return None
    a = canon_addr(rcpt)
    if a is None:
        return False
    if a in {canon_addr(x) for x in (p.get("to") or [])}:
        return True
    dom = a.rsplit("@", 1)[-1] if "@" in a else None
    if dom is not None and dom in {canon_domain(d) for d in (p.get("domains") or [])}:
        return True
    return "circle" if a in circ else False


def _res_match(entries, target):
    """Section 5.6.1: exact byte match, or entry of length >= 2 ending in "*" = prefix; wildcards never match "." / ".." segments."""
    target = str(target)
    segs = target.split("/")
    for e in entries or []:
        if not isinstance(e, str):
            continue
        if e == target:
            return True
        if len(e) >= 2 and e.endswith("*") and target.startswith(e[:-1]) and "." not in segs and ".." not in segs:
            return True
    return False


def _protected_rule(P, a):
    pd = protected(a.get("data", []))
    if not pd:
        return None
    rp = P.get("disclosure")
    if rp is False:
        return ("deny", "DATA_FORBIDDEN")
    if rp is None or rp.get("data") is None:
        return ("deny", "DATA_NOT_PERMITTED")
    if not set(pd) <= set(rp["data"]):
        return ("deny", "DATA_FORBIDDEN")
    r = _recipient(rp, a.get("recipient", ""))
    if r is None:
        return ("defer", "ESCALATE_DATA")
    return None if r is True else ("deny", "RECIPIENT")


def _per_class(M, P, perm, a, st):
    c, amt = a["class"], a.get("amount", 0)
    circ = _circle(P) if M.get("named_circle") else frozenset()
    if perm is not None and perm is not True and not isinstance(perm, dict) and c not in ("meeting", "refund"):
        return ("deny", "CLASS_DENIED")                 # malformed permission value: fail closed
    if c in ("message", "file", "disclosure") and canon_addr(a.get("recipient", "")) is None:
        return ("deny", "RECIPIENT")                    # -02 (C-8): an invalid recipient matches nothing, whatever the permission ('*', unspecified)
    if c == "meeting":
        return ("allow", "OK" if perm is True else "OK_UNSPECIFIED")
    ao = M.get("ask_over") or {}
    if c == "pass":
        if protected(a.get("data", [])):
            return ("deny", "DATA_FORBIDDEN")            # -05 8.6: as for publish, before anything else; step 12 does not apply
        return ("allow", "OK_PASS")                      # step 4a has already required a signed tool map
    if c == "command":
        return _command_rule(perm, a, st)
    if c == "http":
        return _http_rule(perm, a)
    if c == "delete":
        rev = a.get("reversible") is True
        if perm is None:
            return ("defer", "ESCALATE_DELETE") if rev else ("deny", "IRREVERSIBLE_DELETE")
        if not _res_match(perm.get("targets"), a.get("recipient", "")):
            return ("deny", "RESOURCE")
        if not rev and not perm.get("allow_irreversible"):
            return ("deny", "IRREVERSIBLE_DELETE")
        return ("allow", "OK")
    if c == "publish":
        if protected(a.get("data", [])):
            return ("deny", "DATA_FORBIDDEN")
        if perm is None or perm.get("channels") is None:
            return ("defer", "ESCALATE_PUBLISH")
        return ("allow", "OK") if _res_match(perm["channels"], a.get("recipient", "")) else ("deny", "RESOURCE")
    if c in ("message", "disclosure"):
        p = perm
        if c == "disclosure" and not protected(a.get("data", [])):
            p = P.get("message")
            if p is False:
                return ("deny", "CLASS_DENIED")
        if p is None:
            return ("allow", "OK_UNSPECIFIED")
        r = _recipient(p, a.get("recipient", ""), circ)
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", {True: "OK", "circle": "OK_CIRCLE", None: "OK_UNSPECIFIED"}[r])
    if c == "file":
        if perm is None:
            return ("defer", "ESCALATE_FILE")
        r = _recipient(perm, a.get("recipient", ""), circ)
        if r is None:
            return ("defer", "ESCALATE_FILE")
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", "OK" if r is True else "OK_CIRCLE")
    if c == "refund":
        if perm is not True:
            return ("defer", "ESCALATE_MONEY")
        if ao.get("amount") is not None and amt > ao["amount"]:
            return ("defer", "ESCALATE_MONEY")           # -05 6.9: above ask_over.amount the principal is asked
        return ("allow", "OK")
    if c == "sale":
        if perm is None or perm.get("min_price") is None:
            return ("defer", "ESCALATE_MONEY")
        return ("deny", "PRICE") if amt < perm["min_price"] else ("allow", "OK")
    p = perm or {}
    mx, bd = p.get("max_per_action"), p.get("budget")
    if p.get("allowed_payees") is not None and a.get("recipient", "") not in p["allowed_payees"]:
        return ("deny", "RECIPIENT")                     # 0.2.83: a payee list names the only payees (byte-exact, no canonical form, no wildcard)
    if mx is not None and amt > mx:
        return ("deny", "PER_ACTION_LIMIT")
    if p.get("min_per_action") is not None and amt < p["min_per_action"]:
        return ("deny", "PER_ACTION_LIMIT")              # 0.2.83: below the signed lower bound of one purchase (VI amount_range.min)
    if bd is not None and st.get("mandate_committed", 0) + amt > bd:
        return ("deny", "BUDGET")
    ce = st.get("ceiling")
    if ce is not None and st.get("principal_committed", 0) + amt > ce:
        return ("deny", "CEILING")
    if perm is None or mx is None or bd is None:
        return ("defer", "ESCALATE_MONEY")
    if ao.get("amount") is not None and amt > ao["amount"]:
        return ("defer", "ESCALATE_MONEY")               # -05 6.9: up to X the witness decides, above X it asks, above max_per_action it denies
    if ao.get("committed") is not None and st.get("mandate_committed", 0) + amt > ao["committed"]:
        return ("defer", "ESCALATE_MONEY")
    return ("allow", "OK")


def _command_rule(perm, a, st=None):
    """extension (class `command`, a shell command line run on the agent's machine). The allow list names commands that need no question,
    it is NOT the scope of the authority: an unlisted command is asked (defer), unless the principal said otherwise in `unlisted`."""
    if protected(a.get("data", [])):
        return ("deny", "DATA_FORBIDDEN")                # as publish / pass: before everything else; step 12 does not apply
    if perm is True:
        return ("deny", "CLASS_DENIED")                  # `true` is not a command permission (CDDL): fail closed
    p = perm or {}
    unlisted = p.get("unlisted")
    if a.get("dangerous") is True:                       # the list never covers a dangerous command (rm -rf, dd, mkfs, force-push, curl | sh ...)
        return ("deny", "RESOURCE") if unlisted == "deny" else ("defer", "ESCALATE_COMMAND_DANGER")
    if _exec_changed(a):                                 # extension (0.2.13): a file this command executes changed since the owner last confirmed it:
        return ("defer", "ESCALATE_EXEC_CHANGED")        # no list entry, no allowance and no `unlisted` value covers it; the owner decides
    if p.get("allow") is not None and _res_match(p["allow"], a.get("recipient", "")):
        return ("allow", "OK")
    if "allowance" in a and _allowance_covers((st or {}).get("allowances") or {}, a, (st or {}).get("now")):
        return ("allow", "OK_ALLOWANCE")
    if a.get("sandboxed") is True and p.get("sandboxed") == "allow":
        return ("allow", "OK_SANDBOXED")                 # V3: the principal signed "runners in a strict Claude Code sandbox need no question";
                                                         # the gateway sets action.sandboxed only for a runner under a strict sandbox fact
    if unlisted == "allow":
        return ("allow", "OK_UNSPECIFIED")
    if unlisted == "deny":
        return ("deny", "RESOURCE")
    return ("defer", "ESCALATE_COMMAND")


def _http_rule(perm, a):
    """extension-http (class `http`, one HTTP request of the agent's sandbox). Like `command`: the allow list names requests that need no
    question, it is NOT the scope of the authority; an unlisted request is asked unless the principal wrote `unlisted: "deny"`."""
    if protected(a.get("data", [])):
        return ("deny", "DATA_FORBIDDEN")                # as publish / command: before everything else; step 12 does not apply
    if perm is True:
        return ("deny", "CLASS_DENIED")                  # `true` is not an http permission (CDDL): fail closed
    p = perm or {}
    if isinstance(p.get("allow"), list) and httpcanon.allowed(p["allow"], a.get("recipient", "")):
        return ("allow", "OK")
    if p.get("unlisted") == "deny":
        return ("deny", "RESOURCE")
    return ("defer", "ESCALATE_HTTP")


def _exec_changed(a):
    """extension: action.exec_changed = the files (paths, 1..64 tstr) that the command line will execute and that changed since the principal last
    confirmed them (conftest.py, package.json, Makefile, .git/hooks ...). Any other value than a non-empty list counts as changed too (fail closed),
    except absent / None / []."""
    v = a.get("exec_changed")
    if v is None or v == []:
        return False
    return True


def _allowance_covers(allowances, a, now):
    """extension: action.allowance names a recorded, not ended ALLOWANCE of THIS mandate (st carries only those) that lists the command
    identifier byte-exact (no prefix match) for the SAME project (action.project, byte-exact), and witness time is in [nbf, exp].
    A reference that does not cover the action changes nothing: the action is judged as without it (an unlisted command is asked)."""
    g = allowances.get(a.get("allowance")) if isinstance(a.get("allowance"), str) else None
    if g is None or not isinstance(now, int) or not g["nbf"] <= now <= g["exp"]:
        return False
    return isinstance(a.get("project"), str) and a["project"] == g["project"] and a.get("recipient", "") in g["commands"]


def _count_rule(M, a, st):
    """-05 Section 6.9 / 6.4 step 12a (result K). n = counted actions of this mandate and class in the window (Section 7.3)."""
    tier = ((M.get("ask_over") or {}).get("count") or {}).get(a["class"])
    if not tier:
        return None
    n = (st.get("counts") or {}).get(a["class"], 0)
    if tier.get("max") is not None and n + 1 > tier["max"]:
        return ("deny", "COUNT_LIMIT")
    if tier.get("ask_over") is not None and n + 1 > tier["ask_over"]:
        return ("defer", "ESCALATE_COUNT")
    return None


def decide(M, a, st, now=None):
    """Section 6.4 -> (verdict, reason). M carries '_sig_valid' (bool) and '_revoked' (bool) set by the caller.
    now = witness time (integer seconds); None = harness shorthand a["t"] (abstract decision vectors)."""
    if M is None:
        return ("deny", "NO_MANDATE")
    if not M.get("_sig_valid", True):
        return ("deny", "MANDATE_SIG")
    if a.get("agent") != M["agent"]:
        return ("deny", "AGENT_MISMATCH")
    t = a.get("t", 0) if now is None else now
    st = dict(st or {}, now=t)
    if M.get("_revoked") or not (M["nbf"] <= t <= M["exp"]):
        return ("deny", "EXPIRED")
    # -05 step 4a (Section 8.6): the tool map that produced the action is the one the principal signed (absent = null on both sides)
    if a.get("toolmap_sha256") != M.get("toolmap_sha256") or (a["class"] == "pass" and M.get("toolmap_sha256") is None):
        return ("deny", "TOOLMAP_CHANGED")
    if a["class"] not in CLASSES:
        return ("deny", "CLASS_UNKNOWN")
    amt = a.get("amount", 0)
    if isinstance(amt, bool) or not isinstance(amt, int) or amt < 0 or amt > MAX_AMOUNT:
        return ("deny", "BAD_AMOUNT")
    if a["class"] in MONETARY and "amount" not in a:      # -02 (C-11): amount is REQUIRED in a monetary action ...
        return ("deny", "BAD_AMOUNT")
    if a["class"] not in MONETARY and amt != 0:            # ... and a non-monetary action carries 0 or no amount
        return ("deny", "BAD_AMOUNT")
    if a["class"] in MONETARY and (a.get("currency") is None or a.get("currency") != M.get("currency")):
        return ("deny", "BAD_AMOUNT")
    if set(a.get("data", [])) & set(M.get("forbidden_data", [])):
        return ("deny", "DATA_FORBIDDEN")
    P = M["permissions"]
    perm = P.get(a["class"])
    if perm is False:
        return ("deny", "CLASS_DENIED")
    if a["class"] == "meeting" and risk(a) == "irreversible":
        return ("deny", "UNATTENDED_MEETING")
    res = _per_class(M, P, perm, a, st)
    if res[0] == "deny":
        return res
    d = None if a["class"] in ("publish", "pass", "command", "http") else _protected_rule(P, a)     # step 12 (not for publish, -05: not for pass, -06: not for command / http)
    k = _count_rule(M, a, st)                                                      # -05 step 12a
    for x in (d, k):                                                               # -05 step 13: deny in the order D, K ...
        if x is not None and x[0] == "deny":
            return x
    if res[0] == "allow":                                                          # ... then a defer of D or K turns an allow into a defer
        for x in (d, k):
            if x is not None:
                return x
    return res
