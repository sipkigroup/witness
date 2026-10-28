"""Section 6.1 CDDL of the mandate, as an executable check (draft-deus-aar-02: optional members, absent = null; unknown members rejected).
Also Section 6.3 (ceiling) and Section 7.1 (entry bodies). Returns None or the first offending member."""
from . import httpcanon


MANDATE_KEYS = {"v", "id", "principal", "agent", "nbf", "exp", "currency", "budget_window_s", "permissions", "forbidden_data",
                "named_circle", "key_attestation", "pin_source", "payment_mandate_ref", "permit_ref",
                "ask_over", "toolmap_sha256"}          # -05 (6.1, 6.9, 8.6)
COUNT_CLASSES = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass", "command", "http")   # extension: command; extension-http: http
PERM_KEYS = ("message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "command", "http")


def _is_uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _is_strs(x):
    return isinstance(x, list) and all(isinstance(i, str) for i in x)


def _rcpt_ok(p, with_data=False):
    if not isinstance(p, dict) or not (p.get("to") is None or p["to"] == "*" or _is_strs(p["to"])):
        return False
    if p.get("domains") is not None and not _is_strs(p["domains"]):
        return False
    return not with_data or p.get("data") is None or _is_strs(p["data"])


def _ask_over_bad(ao):
    """-05 Section 6.9 CDDL: ask-over = { ? "amount": uint / null, ? "committed": uint / null, ? "count": { + class => tier } / null }
    tier = { ? "ask_over": uint / null, ? "max": uint / null }; members not named are not allowed."""
    if ao is None:
        return None
    if not isinstance(ao, dict) or set(ao) - {"amount", "committed", "count"}:
        return "ask_over"
    for k in ("amount", "committed"):
        if not (ao.get(k) is None or _is_uint(ao[k])):
            return "ask_over." + k
    c = ao.get("count")
    if c is None:
        return None
    if not isinstance(c, dict) or not c or set(c) - set(COUNT_CLASSES):
        return "ask_over.count"
    for tier in c.values():
        if not isinstance(tier, dict) or set(tier) - {"ask_over", "max"} or not all(tier.get(x) is None or _is_uint(tier[x]) for x in ("ask_over", "max")):
            return "ask_over.count tier"
    return None


def validate_mandate(m):
    """Section 6.1 CDDL (-01). -> None if well formed, else a short reason (the witness answers MANDATE_MALFORMED)."""
    if not isinstance(m, dict):
        return "not a map"
    for k, ty in (("id", str), ("principal", str), ("agent", str), ("currency", str)):
        if not isinstance(m.get(k), ty):
            return k
    if m.get("v") != "deus-aar-0.1":
        return "v"
    for k in ("nbf", "exp", "budget_window_s"):
        if not _is_uint(m.get(k)):
            return k
    if set(m) - MANDATE_KEYS:
        return "unknown member"
    if not _is_strs(m.get("forbidden_data")) or not (m.get("named_circle") is None or isinstance(m["named_circle"], bool)):
        return "forbidden_data/named_circle"             # -03 (C2-1): `named_circle: null` is allowed (`? "named_circle": bool / null`)
    if not (m.get("pin_source") is None or isinstance(m["pin_source"], str)):
        return "pin_source"
    for k in ("payment_mandate_ref", "permit_ref"):
        h = m.get(k)
        if not (h is None or (isinstance(h, dict) and h.get("alg") == "sha-256" and isinstance(h.get("digest"), bytes)
                              and set(h) <= {"alg", "digest", "uri"} and isinstance(h.get("uri", ""), str))):
            return k
    bad = _ask_over_bad(m.get("ask_over"))
    if bad:
        return bad
    th = m.get("toolmap_sha256")
    if not (th is None or (isinstance(th, bytes) and len(th) == 32) or isinstance(th, str)):   # str: abstract vectors only (Appendix A conv. 9)
        return "toolmap_sha256"
    if m.get("key_attestation") not in ("secure-element", "passkey", "software"):
        return "key_attestation"
    P = m.get("permissions")
    if not isinstance(P, dict) or set(P) - set(PERM_KEYS):
        return "permissions"
    for k, p in P.items():
        if p is None or p is False:
            continue
        ok = {"message": lambda: _rcpt_ok(p), "file": lambda: _rcpt_ok(p), "disclosure": lambda: _rcpt_ok(p, True),
              "meeting": lambda: p is True, "refund": lambda: p is True,
              "purchase": lambda: isinstance(p, dict) and all(p.get(x) is None or _is_uint(p[x]) for x in ("max_per_action", "budget")),
              "sale": lambda: isinstance(p, dict) and (p.get("min_price") is None or _is_uint(p["min_price"])),
              "delete": lambda: isinstance(p, dict) and _is_strs(p.get("targets", [])) and (p.get("allow_irreversible") is None or isinstance(p["allow_irreversible"], bool)),
              "publish": lambda: isinstance(p, dict) and _is_strs(p.get("channels", [])),
              "command": lambda: isinstance(p, dict) and (p.get("allow") is None or _is_strs(p["allow"]))
                                 and p.get("unlisted") in (None, "ask", "allow", "deny")
                                 and p.get("sandboxed") in (None, "ask", "allow"),
              "http": lambda: isinstance(p, dict) and _http_rules_ok(p.get("allow")) and p.get("unlisted") in (None, "ask", "deny")}[k]()
        if not ok:
            return "permissions." + k
        if isinstance(p, dict) and set(p) - SUB_KEYS[k]:
            return "permissions." + k + " unknown member"
    return None


SUB_KEYS = {"message": {"to", "domains"}, "file": {"to", "domains"}, "disclosure": {"to", "domains", "data"},
            "purchase": {"max_per_action", "budget"}, "sale": {"min_price"}, "meeting": set(), "refund": set(),
            "delete": {"targets", "allow_irreversible"}, "publish": {"channels"}, "command": {"allow", "unlisted", "sandboxed"},
            "http": {"allow", "unlisted"}}


def _http_rules_ok(x):
    """extension-http: allow = null or a list of at most 200 CANONICAL rules (httpcanon.canon_rule(r) == r), no duplicates."""
    if x is None:
        return True
    return (_is_strs(x) and len(x) <= httpcanon.MAX_RULES and len(set(x)) == len(x)
            and all(httpcanon.is_canonical_rule(r) for r in x))


def validate_ceiling(c):
    """-02 Section 6.3: the CEILING entry body carries the members of the principal-signed map (beside cose / signed_by).
    -> None or the first offending member (the witness answers CEILING_MALFORMED)."""
    if not isinstance(c, dict):
        return "not a map"
    for k in ("id", "currency"):
        if not isinstance(c.get(k), str):
            return k
    if not _is_uint(c.get("amount")):
        return "amount"
    if not _is_uint(c.get("window_s")) or c["window_s"] < 1:
        return "window_s"
    return None


def validate_body(typ, b, own_seq=None):
    """-02 Section 7.1: CDDL of the entry bodies (members not named are ignored). -> None or a reason (verifier: MALFORMED)."""
    if not isinstance(b, dict):
        return "body"
    need = {"MANDATE": ("mandate",), "CEILING": (), "REVOCATION": ("mandate",), "APPROVAL": ("receipt", "approved"),
            "CONSUME": ("receipt",), "RELEASE": ("receipt", "cause"), "REFUND": (), "RECEIPT": ("id", "mandate", "action", "verdict", "reason", "ttl"),
            "CHECKPOINT": ("seq", "head", "root"), "ALLOWANCE": ("allowance", "mandate"), "ALLOWANCE_END": ("allowance", "cause")}
    if typ not in need:
        return "type"
    for k in need[typ]:
        if k not in b:
            return k
    if typ == "RECEIPT":
        if not (isinstance(b["id"], str) and isinstance(b["mandate"], str) and isinstance(b["action"], dict) and isinstance(b["reason"], str)
                and b["verdict"] in ("allow", "defer", "deny") and _is_uint(b["ttl"])):
            return "RECEIPT member type"
        if "audience" in b:
            if not isinstance(b["audience"], str):
                return "audience"
        elif not (b["verdict"] == "deny" and b["reason"] == "NO_MANDATE"):
            return "audience"
    if typ == "CHECKPOINT" and not (_is_uint(b["seq"]) and isinstance(b["head"], (bytes, str)) and isinstance(b["root"], (bytes, str))):
        return "CHECKPOINT member type"
    if typ == "CHECKPOINT" and own_seq is not None and not b["seq"] < own_seq:
        return "CHECKPOINT seq"                          # Section 7.1: seq < own seq
    if typ == "APPROVAL" and not isinstance(b["approved"], bool):
        return "approved"
    if typ == "APPROVAL" and "view" in b and not (isinstance(b["view"], bytes) and len(b["view"]) == 32):
        return "view"                                    # pv2810: the presentation hash, when present, is bstr .size 32
    if typ == "ALLOWANCE" and (not isinstance(b["mandate"], str) or validate_allowance(b["allowance"])):
        return "ALLOWANCE member"
    if typ == "ALLOWANCE_END" and not (isinstance(b["allowance"], str) and b["cause"] in ALLOWANCE_END_CAUSES):
        return "ALLOWANCE_END member"
    return None


# extension (0.2.10): a principal-signed ALLOWANCE adds named commands to ONE mandate for ONE project and a bounded time
# ("allow this command in this project"). It never covers a dangerous command (the class rule checks danger first).
ALLOWANCE_KEYS = {"v", "t", "id", "mandate", "class", "commands", "project", "nbf", "exp"}
ALLOWANCE_MAX_S = 90 * 86400
ALLOWANCE_MAX_COMMANDS = 8
ALLOWANCE_END_CAUSES = ("revoked",)


def validate_allowance(a):
    """CDDL of the allowance map (= the signed payload, typ application/aar-allowance+cbor):
      { v: "deus-aar-0.1", t: "allowance", id: tstr (1..64), mandate: bstr .size 32 (hash of the mandate it extends), class: "command",
        commands: [1*8 tstr (1..200, no "*")], project: tstr (absolute path, 1..1024), nbf: uint, exp: uint (nbf < exp <= nbf + 90 days) }
    Exactly these members. -> None or the first offending member."""
    if not isinstance(a, dict) or set(a) != ALLOWANCE_KEYS:
        return "members"
    if a["v"] != "deus-aar-0.1" or a["t"] != "allowance" or a["class"] != "command":
        return "v/t/class"
    if not (isinstance(a["id"], str) and 0 < len(a["id"]) <= 64):
        return "id"
    if not (isinstance(a["mandate"], bytes) and len(a["mandate"]) == 32):
        return "mandate"
    c = a["commands"]
    if not (isinstance(c, list) and 0 < len(c) <= ALLOWANCE_MAX_COMMANDS and len(set(c)) == len(c)
            and all(isinstance(x, str) and 0 < len(x) <= 200 and "*" not in x for x in c)):
        return "commands"
    p = a["project"]
    if not (isinstance(p, str) and 0 < len(p) <= 1024 and p.startswith("/")):
        return "project"
    if not (_is_uint(a["nbf"]) and _is_uint(a["exp"]) and a["nbf"] < a["exp"] <= a["nbf"] + ALLOWANCE_MAX_S):
        return "nbf/exp"
    return None
