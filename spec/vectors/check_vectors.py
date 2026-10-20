#!/usr/bin/env python3
"""Abstract-level model of draft-deus-aar-00 (Sections 5-8) and runner for the test vectors.

This is NOT the reference implementation (that is svidetel/, Step 2). It is an executable
reading of the draft's normative algorithms, used to check that every vector's expected
verdict follows from the text. Cryptographic validity is an input flag at this level
(see vectors/index.json "level").

Usage:  python3 check_vectors.py [vectors_dir]      exit 0 = all vectors agree with the model
"""
import json
import os
import sys
import unicodedata
import re

CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish")
NON_PROTECTED = ("city",)


# ---------------- Section 5: canonicalisation ----------------
def canon_addr(s):
    s = str(s)
    m = re.search(r"<([^<>]+)>", s)
    if m:
        s = m.group(1)
    s = unicodedata.normalize("NFKC", s).casefold()
    return "".join(s.split())


def canon_domain(s):
    return "".join(unicodedata.normalize("NFKC", str(s)).casefold().split()).lstrip("@")


def protected(data):
    return sorted({x for x in data if x not in NON_PROTECTED})


def risk(a):
    c = a["class"]
    if c in ("purchase", "sale", "refund"):
        return "monetary"
    if c in ("file", "publish"):
        return "disclosure"
    if c == "delete":
        return "low" if a.get("reversible") is True else "irreversible"
    if c in ("message", "disclosure"):
        return "disclosure" if protected(a.get("data", [])) else "low"
    if c == "meeting":
        return "low" if a.get("principal_present") else "irreversible"
    return "irreversible"


def circle(P):
    out = set()
    for n in ("message", "file", "disclosure"):
        p = P.get(n)
        if isinstance(p, dict) and isinstance(p.get("to"), list):
            out |= {canon_addr(x) for x in p["to"]}
    return out


def recipient(p, rcpt, circ=frozenset()):
    """True | 'circle' | False | None(unspecified)"""
    if p.get("to") == "*":
        return True
    if p.get("to") is None and not p.get("domains"):
        return None
    a = canon_addr(rcpt)
    if a in {canon_addr(x) for x in (p.get("to") or [])}:
        return True
    dom = a.rsplit("@", 1)[-1] if "@" in a else None
    if dom is not None and dom in {canon_domain(d) for d in (p.get("domains") or [])}:
        return True
    return "circle" if a in circ else False


def protected_rule(P, a):
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
    r = recipient(rp, a.get("recipient", ""))          # no circle for protected data
    if r is None:
        return ("defer", "ESCALATE_DATA")
    return None if r is True else ("deny", "RECIPIENT")


def res_match(entries, target):
    return any(e == target or (isinstance(e, str) and e.endswith("*") and target.startswith(e[:-1])) for e in entries or [])


def per_class(M, P, perm, a, st):
    c, amt = a["class"], a.get("amount", 0)
    circ = circle(P) if M.get("named_circle") else frozenset()
    if c == "meeting":
        return ("allow", "OK" if perm is True else "OK_UNSPECIFIED")
    if c == "delete":
        rev = a.get("reversible") is True
        if perm is None:
            return ("defer", "ESCALATE_DELETE") if rev else ("deny", "IRREVERSIBLE_DELETE")
        if not res_match(perm.get("targets"), a.get("recipient", "")):
            return ("deny", "RESOURCE")
        if not rev and not perm.get("allow_irreversible"):
            return ("deny", "IRREVERSIBLE_DELETE")
        return ("allow", "OK")
    if c == "publish":
        if protected(a.get("data", [])):
            return ("deny", "DATA_FORBIDDEN")
        if perm is None or perm.get("channels") is None:
            return ("defer", "ESCALATE_PUBLISH")
        return ("allow", "OK") if res_match(perm["channels"], a.get("recipient", "")) else ("deny", "RESOURCE")
    if c in ("message", "disclosure"):
        p = perm
        if c == "disclosure" and not protected(a.get("data", [])):
            p = P.get("message")
            if p is False:
                return ("deny", "CLASS_DENIED")
        if p is None:
            return ("allow", "OK_UNSPECIFIED")
        r = recipient(p, a.get("recipient", ""), circ)
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", {True: "OK", "circle": "OK_CIRCLE", None: "OK_UNSPECIFIED"}[r])
    if c == "file":
        if perm is None:
            return ("defer", "ESCALATE_FILE")
        r = recipient(perm, a.get("recipient", ""), circ)
        if r is None:
            return ("defer", "ESCALATE_FILE")
        if r is False:
            return ("deny", "RECIPIENT")
        return ("allow", "OK" if r is True else "OK_CIRCLE")
    if c == "refund":
        return ("allow", "OK") if perm is True else ("defer", "ESCALATE_MONEY")
    if c == "sale":
        if perm is None or perm.get("min_price") is None:
            return ("defer", "ESCALATE_MONEY")
        return ("deny", "PRICE") if amt < perm["min_price"] else ("allow", "OK")
    p = perm or {}
    mx, bd = p.get("max_per_action"), p.get("budget")
    if mx is not None and amt > mx:
        return ("deny", "PER_ACTION_LIMIT")
    if bd is not None and st.get("mandate_committed", 0) + amt > bd:
        return ("deny", "BUDGET")
    ce = st.get("ceiling")
    if ce is not None and st.get("principal_committed", 0) + amt > ce:
        return ("deny", "CEILING")
    if perm is None or mx is None or bd is None:
        return ("defer", "ESCALATE_MONEY")
    return ("allow", "OK")


def decide(M, a, st):
    """Section 6.4. -> (verdict, reason)"""
    if M is None:
        return ("deny", "NO_MANDATE")
    if not M.get("_sig_valid", True):
        return ("deny", "MANDATE_SIG")
    if a.get("agent") != M["agent"]:
        return ("deny", "AGENT_MISMATCH")
    t = a.get("t", 0)
    if not (M["nbf"] <= t <= M["exp"]):
        return ("deny", "EXPIRED")
    if a["class"] not in CLASSES:
        return ("deny", "CLASS_UNKNOWN")
    amt = a.get("amount", 0)
    if isinstance(amt, bool) or not isinstance(amt, int) or amt < 0:
        return ("deny", "BAD_AMOUNT")
    if set(a.get("data", [])) & set(M.get("forbidden_data", [])):
        return ("deny", "DATA_FORBIDDEN")
    P = M["permissions"]
    perm = P.get(a["class"])
    if perm is False:
        return ("deny", "CLASS_DENIED")
    if a["class"] == "meeting" and risk(a) == "irreversible":
        return ("deny", "UNATTENDED_MEETING")
    res = per_class(M, P, perm, a, st)
    if res[0] == "deny" or a["class"] == "publish":
        return res
    d = protected_rule(P, a)
    if d is not None and (d[0] == "deny" or res[0] == "allow"):
        return d
    return res


# ---------------- Section 7: ledger ----------------
class Ledger:
    """One logical ledger per principal, shared by every witness instance (Section 7.2)."""

    def __init__(self, pinned_key):
        self.pinned = pinned_key
        self.mandates = {}
        self.ceiling = None
        self.res = {}          # receipt id -> dict(amount, mandate, expires, state, action)
        self.now = 0
        self.receipts = {}

    def committed(self, mid=None):
        return sum(r["amount"] for r in self.res.values()
                   if r["state"] in ("active", "consumed") and (mid is None or r["mandate"] == mid))

    def expire(self):
        for r in self.res.values():
            if r["state"] == "active" and self.now > r["expires"]:
                r["state"] = "released"

    def step(self, op):
        k = op["op"]
        if k == "register_mandate":
            if op.get("signed_by") != self.pinned:
                return {"result": "reject", "reason": "KEY_MISMATCH"}
            M = dict(op["mandate"])
            self.mandates[M["id"]] = M
            return {"result": "accept"}
        if k == "register_ceiling":
            if op.get("signed_by") != self.pinned:
                return {"result": "reject", "reason": "KEY_MISMATCH"}
            self.ceiling = op["amount"]
            return {"result": "accept"}
        if k == "restart":
            return {"result": "ok"}
        if k == "clock":
            if op["t"] < self.now:
                return {"result": "clamped"}
            self.now = op["t"]
            self.expire()
            return {"result": "ok"}
        if k == "authorize":
            self.expire()
            M = self.mandates.get(op["mandate"])
            a = dict(op["action"])
            a.setdefault("t", self.now)
            st = {"mandate_committed": self.committed(op["mandate"]), "principal_committed": self.committed(),
                  "ceiling": self.ceiling}
            v, why = decide(M, a, st)
            if v in ("allow", "defer") and a["class"] == "purchase":
                self.res[op["id"]] = {"amount": a["amount"], "mandate": op["mandate"],
                                      "expires": self.now + op.get("ttl", 300), "state": "active", "action": a}
            self.receipts[op["id"]] = {"verdict": v, "action": a, "used": False,
                                       "expires": self.now + op.get("ttl", 300)}
            return {"verdict": v, "reason": why}
        if k == "approve":
            rc = self.receipts[op["receipt"]]
            if op.get("signed_by") != self.pinned:
                return {"result": "reject", "reason": "APPROVAL_SIG"}
            if rc["verdict"] != "defer":
                return {"result": "reject", "reason": "NOT_DEFERRED"}
            rc["verdict"] = "allow"
            return {"result": "accept", "verdict": "allow"}
        if k == "tool_present":
            self.expire()
            rid = op.get("receipt")
            if rid is None:
                return {"result": "reject", "reason": "NO_RECEIPT"}
            rc = self.receipts[rid]
            if rc["verdict"] != "allow":
                return {"result": "reject", "reason": "NOT_ALLOWED"}
            if op.get("audience_mismatch"):
                return {"result": "reject", "reason": "AUDIENCE"}
            if op.get("request") is not None and op["request"] != rc["action"]:
                return {"result": "reject", "reason": "REQUEST_MISMATCH"}
            if rc["used"]:
                return {"result": "reject", "reason": "REPLAY"}
            if self.now > rc["expires"]:
                return {"result": "reject", "reason": "RECEIPT_EXPIRED"}
            r = self.res.get(rid)
            if r is not None and r["state"] != "active":
                return {"result": "reject", "reason": "RESERVATION_INACTIVE"}
            rc["used"] = True
            if r is not None:
                r["state"] = "consumed"
            return {"result": "accept"}
        if k == "agent_report":
            return {"result": "ignored"}
        if k == "tool_report":
            r = self.res.get(op["receipt"])
            if not op.get("executed") and r is not None and r["state"] == "active":
                r["state"] = "released"
                self.receipts[op["receipt"]]["used"] = True
                return {"result": "released"}
            return {"result": "ok"}
        raise ValueError(k)


# ---------------- Section 8: third-party verification ----------------
def verify_log(v):
    """Abstract verifier: v = {"operator_keys", "witness_key", "pinned_principal_key", "entries", "checkpoint"}."""
    if v["witness_key"] in v.get("operator_keys", []):
        return {"result": "invalid", "reason": "WITNESS_NOT_INDEPENDENT"}
    prev = None
    L = Ledger(v["pinned_principal_key"])
    heads = {}
    for e in v["entries"]:
        if not e.get("witness_sig_valid", True):
            return {"result": "invalid", "reason": "WITNESS_SIG", "at": e["seq"]}
        if e["prev"] != prev:
            return {"result": "invalid", "reason": "CHAIN_BREAK", "at": e["seq"]}
        prev = e["hash"]
        heads[e["seq"]] = e["hash"]
        body = e["body"]
        t = e.get("t", 0)
        if e["type"] != "RELEASE":          # Section 7.4/10: expired reservation needs an explicit RELEASE before any later entry
            for r in L.res.values():
                if r["state"] == "active" and t > r["expires"]:
                    return {"result": "invalid", "reason": "RELEASE_MISSING", "at": e["seq"]}
        else:
            r = L.res.get(body.get("receipt"))
            if body.get("cause") == "expired" and (r is None or r["state"] != "active" or not t > r["expires"]):
                return {"result": "invalid", "reason": "RELEASE_INVALID", "at": e["seq"]}
            if r is not None:
                r["state"] = "released"
        L.now = max(L.now, t)
        if e["type"] == "MANDATE":
            r = L.step({"op": "register_mandate", "mandate": body["mandate"], "signed_by": body["signed_by"]})
            if r["result"] != "accept":
                return {"result": "invalid", "reason": "MANDATE_KEY", "at": e["seq"]}
        elif e["type"] == "CEILING":
            r = L.step({"op": "register_ceiling", "amount": body["amount"], "signed_by": body["signed_by"]})
            if r["result"] != "accept":
                return {"result": "invalid", "reason": "MANDATE_KEY", "at": e["seq"]}
        elif e["type"] == "RECEIPT":
            if body["mandate"] not in L.mandates and not (body["verdict"] == "deny" and body.get("reason") == "NO_MANDATE"):
                return {"result": "invalid", "reason": "MANDATE_UNKNOWN", "at": e["seq"]}
            r = L.step({"op": "authorize", "id": body["id"], "mandate": body["mandate"], "action": body["action"]})
            if r["verdict"] != body["verdict"]:
                return {"result": "invalid", "reason": "VERDICT_NOT_REPRODUCIBLE", "at": e["seq"]}
        elif e["type"] == "CONSUME":
            r = L.step({"op": "tool_present", "receipt": body["receipt"]})
            if r["result"] != "accept":
                return {"result": "invalid", "reason": "CONSUME_INVALID", "at": e["seq"]}
    cp = v.get("checkpoint")
    cpseq = cp["seq"] if cp is not None and "seq" in cp else len(v["entries"]) - 1
    for p in v.get("presented", []):          # Section 8.4(9): tool-reported receipts need an inclusion in the ledger
        inc = p.get("inclusion")
        if inc is None:
            return {"result": "invalid", "reason": "NO_INCLUSION", "receipt": p["id"]}
        s = inc.get("seq")
        if not (cp is not None and isinstance(s, int) and 0 <= s <= cpseq and s < len(v["entries"])
                and v["entries"][s]["type"] == "RECEIPT" and v["entries"][s]["body"].get("id") == p["id"]):
            return {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": p["id"]}
    if cp is not None:
        if cp["head"] != (heads.get(cp["seq"]) if "seq" in cp else prev):
            return {"result": "invalid", "reason": "CHECKPOINT_HEAD"}
        if cp.get("ots_digest") is not None and cp["ots_digest"] != cp["head"]:
            return {"result": "invalid", "reason": "ANCHOR_MISMATCH"}
        if cp.get("ots_status") == "pending":
            return {"result": "valid", "anchor": "pending"}
        if cp.get("ots_status") == "bitcoin":
            return {"result": "valid", "anchor": "bitcoin"}
    return {"result": "valid", "anchor": "none"}


def run_vector(x):
    kind = x["kind"]
    if kind == "decision":
        M = x["input"]["mandate"]
        if M is not None:
            M = dict(M, _sig_valid=x["input"].get("mandate_signature_valid", True))
        v, why = decide(M, x["input"]["action"], x["input"].get("ledger_state", {}))
        return {"verdict": v, "reason": why}
    if kind == "sequence":
        L = Ledger(x["input"]["pinned_principal_key"])
        return {"steps": [L.step(op) for op in x["input"]["ops"]]}
    if kind == "verification":
        return verify_log(x["input"])
    raise ValueError(kind)


# This model reads draft-deus-aar-00 / rev 4.1 and is FROZEN (ancestor). Vectors that exist only because of -01 are skipped:
# they are covered by aar_ref (implementation A) and verifier_js (implementation B).
NEW_IN_01 = {"D55", "D56", "D57", "D58", "D59", "D60", "D61", "D62", "D63", "D64", "D65", "S19", "S20", "S21", "S22",
             "V19", "V20", "V21", "V22"}
# Vectors that exist only because of -02 (revision 4.3) are skipped too (the model stays frozen at -00/4.1):
NEW_IN_02 = {"D%d" % i for i in range(66, 82)} | {"S%d" % i for i in range(23, 31)} | {"V%d" % i for i in range(23, 31)}
# ... and because of -03 (revision 4.4):
NEW_IN_03 = {"D82"} | {"S%d" % i for i in range(31, 37)} | {"V%d" % i for i in range(31, 42)}
# ... and because of -04 (revision 4.5):
NEW_IN_04 = {"S37", "S38"} | {"V%d" % i for i in range(42, 50)}
# ... and because of ERRATA-04 E1 (R-01):
NEW_IN_04 = NEW_IN_04 | {"D%d" % i for i in range(83, 92)}
# ... and because of -05 (revision 4.6):
NEW_IN_05 = {"D%d" % i for i in range(92, 118)} | {"S%d" % i for i in range(39, 43)} | {"V%d" % i for i in range(50, 63)}
NEW_IN_01 = NEW_IN_01 | NEW_IN_02 | NEW_IN_03 | NEW_IN_04 | NEW_IN_05


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    files = sorted(f for f in os.listdir(d) if f.endswith(".json") and f != "index.json" and f[:-5] not in NEW_IN_01)
    bad = 0
    for f in files:
        with open(os.path.join(d, f), encoding="utf-8") as fh:
            x = json.load(fh)
        got = run_vector(x)
        if got != x["expected"]:
            bad += 1
            print("MISMATCH", f, "\n  expected", x["expected"], "\n  got     ", got)
    print("vectors: %d, mismatches: %d" % (len(files), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
