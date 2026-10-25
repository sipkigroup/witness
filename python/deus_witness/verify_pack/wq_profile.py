"""Reference implementation of the team profile 0.2 (the design notes sections 2-4): quorum envelope `wq`, batch envelope `wb`,
organisation policy, requirements, second pass (policy-at-time), release payload. Only stdlib + cbor2 + cryptography.
Imports (does not copy) ../wa_profile.py.

Public API: make_wq, make_wsig, wsig_of_wa, make_wb, wb_challenge, envelope_kind, policy_hash, validate_policy, requirements,
verify_wq, verify_wb, wb_requirements_met, verify_policy_chain, policy_at, release_payload;
0.2.2 (recovery): key_swap, policy_step, key_event_payload, parse_key_event, key_intervals, key_active_at.
0.2.15 (delegation in the signed policy): DELEGATION_KEYS, delegation_of, delegation_code, verify_wq(..., agent=), phone_lift_payload.

chain = list of entries; an entry is a tuple (policy_bytes, envelope_bytes[, t]) or a dict {"policy": bytes, "envelope": bytes, "t": int}.
`t` (unix seconds of the registry_log record that made the version effective) is needed only for the second pass.
rp = {"rp_id": str, "origins": [str]} -- where the members' passkeys live (the policy itself carries only kid/pub/cred)."""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))
import cbor2

import wa_profile as wa
from wa_profile import cde

V_WQ = "deus-aar-wq-0.1"
V_WB = "deus-aar-wb-0.1"
V_POLICY = "dw-org-policy-0.1"
TYP_POLICY = "application/dw-org-policy+cbor"
TYP_RELEASE = "application/dw-release+cbor"
ROLES = ("owner", "budget", "access")
REQ_ROLES = ROLES + ("any",)
MONEY = ("purchase", "sale", "refund")
NONMONEY = ("message", "file", "disclosure", "delete", "publish", "meeting", "command", "http")   # command: extension (a granted command list is access); http: extension-http
MAX_MEMBERS, MAX_ITEMS, MAX_LABEL = 16, 20, 32
WQ_KEYS = ("v", "typ", "payload", "policy", "sigs")
WSIG_KEYS = ("kid", "authData", "clientDataJSON", "sig")
WB_KEYS = ("v", "typ", "items", "kid", "authData", "clientDataJSON", "sig")
POLICY_KEYS = ("v", "principal", "ver", "prev", "members", "rules")
MEMBER_KEYS = ("kid", "pub", "cred", "roles", "label")
RULE_KEYS = ("policy", "mandate", "approval", "revocation", "ceiling")
OPT_RULE_KEYS = ("recovery", "delegation")       # 0.2.2: recovery (k >= 2 OTHER members replace one member's lost key); 0.2.15: delegation
# 0.2.15: rules.delegation = [{agent, operator, approvers, until}] sorted by agent, agents distinct. agent: the mandate's `agent` (text);
# operator: the kid (64 lowercase hex) of the person who runs the agent -- a signature by it never counts for an approval of that agent
# (WQ_SELF); approvers: null (anyone the approval rule allows, minus the operator) or the sorted kids (hex) of the policy members who
# alone may confirm (WQ_NOT_DELEGATE for anyone else); until: null or unix seconds after which the named approvers may not confirm.
# Kids are TEXT (hex), not bytes: the rules stay plain JSON for the browser, which rebuilds the policy bytes from the server's JSON.
DELEGATION_KEYS = ("agent", "operator", "approvers", "until")
MAX_DELEGATIONS, MAX_AGENT_ID = 64, 64
V_PHONE_LIFT = "dw-phone-lift-0.1"
TYP_PHONE_LIFT = "application/dw-phone-lift+cbor"
WB_TYPS = (wa.TYP_APPROVAL, wa.TYP_REVOCATION)      # 0.2.2: a batch may also revoke (one ceremony stops many mandates)
V_KEY_EVENT = "dw-key-event-0.1"
TYP_KEY_EVENT = "application/dw-key-event+cbor"
KEY_EVENT_KEYS = ("v", "principal", "op", "kid", "pub", "cred", "nonce")
INF = float("inf")
SIG_CODE = dict(wa.SIG_CODE)
SIG_CODE[TYP_POLICY] = "POLICY_SIG"
SIG_CODE[TYP_RELEASE] = "RELEASE_SIG"
SIG_CODE[TYP_KEY_EVENT] = "KEY_EVENT_SIG"
SIG_CODE[TYP_PHONE_LIFT] = "PHONE_LIFT_SIG"
RULE_OF_TYP = {wa.TYP_MANDATE: "mandate", wa.TYP_APPROVAL: "approval", wa.TYP_REVOCATION: "revocation",
               wa.TYP_CEILING: "ceiling", TYP_POLICY: "policy"}


def _uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _b32(x):
    return isinstance(x, bytes) and len(x) == 32


# ---------------------------------------------------------------- envelopes
def envelope_kind(b):
    """'wa' | 'wq' | 'wb' | None, by member `v` (not by the first byte). COSE_Sign1 (tag 18) and garbage -> None."""
    try:
        m = cbor2.loads(b)
    except Exception:
        return None
    if not isinstance(m, dict):
        return None
    return {wa.V: "wa", V_WQ: "wq", V_WB: "wb"}.get(m.get("v"))


def make_wsig(kid, authData, clientDataJSON, der_sig, normalize=True):
    sig = wa.der_to_raw_lows(der_sig) if normalize else wa._raw(der_sig)
    return {"kid": kid, "authData": authData, "clientDataJSON": clientDataJSON, "sig": sig}


def wsig_of_wa(env: bytes):
    """Extract the wsig of an ordinary wa-sig envelope (the browser of every signer signs a plain wa-sig, 2.3)."""
    m = cbor2.loads(env)
    return {k: m[k] for k in WSIG_KEYS}


def make_wq(typ, payload, policy_hash_, wsigs, sort=True):
    """wq in CDE. wsigs: dicts {kid, authData, clientDataJSON, sig(64)}. sort=False keeps the given order (negative tests only)."""
    sigs = sorted(wsigs, key=lambda s: s["kid"]) if sort else list(wsigs)
    return cde({"v": V_WQ, "typ": typ, "payload": payload, "policy": policy_hash_, "sigs": [dict(s) for s in sigs]})


def wb_challenge(items, typ=wa.TYP_APPROVAL):
    """SHA-256("deus-aar-wb-0.1" || 0x00 || typ || 0x00 || CDE(items)); typ = approval (0.2) or revocation (0.2.2: batch revocation).
    The typ is inside the challenge, so a batch approval can never be replayed as a batch revocation (or back)."""
    return hashlib.sha256(V_WB.encode() + b"\x00" + typ.encode() + b"\x00" + cde(list(items))).digest()


def make_wb(items, kid, authData, clientDataJSON, der_sig, normalize=True, typ=wa.TYP_APPROVAL):
    sig = wa.der_to_raw_lows(der_sig) if normalize else wa._raw(der_sig)
    return cde({"v": V_WB, "typ": typ, "items": list(items), "kid": kid, "authData": authData,
                "clientDataJSON": clientDataJSON, "sig": sig})


def release_payload(rid, args_sha256, release) -> bytes:
    """CDE {rid, args_sha256 (bstr 32; a 64-char hex string is accepted and converted), release: bool}, typ application/dw-release+cbor."""
    if isinstance(args_sha256, str):
        args_sha256 = bytes.fromhex(args_sha256)
    if not _b32(args_sha256) or not isinstance(rid, str) or not isinstance(release, bool):
        raise ValueError("MALFORMED")
    return cde({"rid": rid, "args_sha256": args_sha256, "release": release})


# ---------------------------------------------------------------- policy
def policy_hash(policy_map) -> bytes:
    return hashlib.sha256(cde(policy_map)).digest()


def _req_ok(r, roles_allowed):
    return (isinstance(r, dict) and set(r) == {"role", "k"} and r["role"] in roles_allowed
            and _uint(r["k"]) and 1 <= r["k"] <= MAX_MEMBERS)


def _tier_ok(t):
    if not isinstance(t, dict) or t.get("if") not in ("money", "money_over", "access"):
        return False
    keys = {"if", "role", "k"} | ({"amount"} if t["if"] == "money_over" else set())
    return (set(t) == keys and t["role"] in ROLES and _uint(t["k"]) and 1 <= t["k"] <= MAX_MEMBERS
            and (t["if"] != "money_over" or _uint(t["amount"])))


def validate_policy(p):
    """None if the org-policy map is well formed (2.2), else 'POLICY_MALFORMED'. Also rejects a requirement that the member
    list can never meet (k larger than the number of holders of the role): it would lock the organisation."""
    try:
        if not isinstance(p, dict) or set(p) != set(POLICY_KEYS) or p["v"] != V_POLICY:
            return "POLICY_MALFORMED"
        if not isinstance(p["principal"], str) or not p["principal"].startswith("dw:") or len(p["principal"]) < 4:
            return "POLICY_MALFORMED"
        if not _uint(p["ver"]) or p["ver"] < 1:
            return "POLICY_MALFORMED"
        if (p["prev"] is None) != (p["ver"] == 1) or (p["prev"] is not None and not _b32(p["prev"])):
            return "POLICY_MALFORMED"
        ms = p["members"]
        if not isinstance(ms, list) or not 1 <= len(ms) <= MAX_MEMBERS:
            return "POLICY_MALFORMED"
        last = None
        for m in ms:
            if not isinstance(m, dict) or set(m) != set(MEMBER_KEYS):
                return "POLICY_MALFORMED"
            if not _b32(m["kid"]) or not isinstance(m["pub"], bytes) or len(m["pub"]) != 65 or m["pub"][0] != 4:
                return "POLICY_MALFORMED"
            if not isinstance(m["cred"], bytes) or wa.thumbprint(m["pub"]) != m["kid"]:
                return "POLICY_MALFORMED"
            if last is not None and m["kid"] <= last:
                return "POLICY_MALFORMED"      # not sorted by kid, or a repeated kid
            last = m["kid"]
            r = m["roles"]
            if not isinstance(r, list) or not r or len(set(r)) != len(r) or any(x not in ROLES for x in r):
                return "POLICY_MALFORMED"
            lab = m["label"]
            if not isinstance(lab, str) or len(lab) > MAX_LABEL or "@" in lab or any(ord(c) < 32 for c in lab):
                return "POLICY_MALFORMED"
        rl = p["rules"]
        if not isinstance(rl, dict) or not set(RULE_KEYS) <= set(rl) or not set(rl) <= set(RULE_KEYS + OPT_RULE_KEYS):
            return "POLICY_MALFORMED"
        for key in ("policy", "revocation", "ceiling"):
            if not _req_ok(rl[key], REQ_ROLES):
                return "POLICY_MALFORMED"
        for key in ("mandate", "approval"):
            if not isinstance(rl[key], list) or not all(_tier_ok(t) for t in rl[key]):
                return "POLICY_MALFORMED"
        holders = {r: sum(1 for m in ms if r in m["roles"]) for r in ROLES}
        holders["any"] = len(ms)
        reqs = [rl["policy"], rl["revocation"], rl["ceiling"]] + rl["mandate"] + rl["approval"]
        if any(q["k"] > holders[q["role"]] for q in reqs):
            return "POLICY_MALFORMED"
        if "recovery" in rl:
            # 0.2.2: replacing someone's key takes at least two OTHER people, and must stay reachable when ANY one member is lost
            rc = rl["recovery"]
            if not _req_ok(rc, REQ_ROLES) or rc["k"] < 2:
                return "POLICY_MALFORMED"
            for m in ms:
                others = sum(1 for o in ms if o is not m and (rc["role"] == "any" or rc["role"] in o["roles"]))
                if others < rc["k"]:
                    return "POLICY_MALFORMED"
        if "delegation" in rl and not _delegation_ok(rl["delegation"], ms):
            return "POLICY_MALFORMED"
        return None
    except Exception:
        return "POLICY_MALFORMED"


def _hexkid(x):
    return isinstance(x, str) and len(x) == 64 and all(c in "0123456789abcdef" for c in x)


def _delegation_ok(dl, members):
    """0.2.15: the list is non-empty (no delegation = no key), sorted by agent, one entry per agent; approvers are members of THIS
    version, sorted, distinct, never the operator. The operator need not be a member (an observer runs agents too)."""
    if not isinstance(dl, list) or not 1 <= len(dl) <= MAX_DELEGATIONS:
        return False
    kids = {m["kid"].hex() for m in members}
    last = None
    for d in dl:
        if not isinstance(d, dict) or set(d) != set(DELEGATION_KEYS):
            return False
        a = d["agent"]
        if not isinstance(a, str) or not 1 <= len(a) <= MAX_AGENT_ID or any(not 33 <= ord(c) < 127 for c in a):
            return False
        if last is not None and a <= last:
            return False
        last = a
        if not _hexkid(d["operator"]):
            return False
        ap = d["approvers"]
        if ap is not None:
            if not isinstance(ap, list) or not 1 <= len(ap) <= MAX_MEMBERS or not all(_hexkid(k) for k in ap):
                return False
            if ap != sorted(set(ap)) or d["operator"] in ap or any(k not in kids for k in ap):
                return False
        if d["until"] is not None and not _uint(d["until"]):
            return False
    return True


def delegation_of(policy, agent):
    """0.2.15: the delegation entry of `agent` in a policy map, or None."""
    try:
        for d in policy["rules"].get("delegation") or ():
            if d["agent"] == agent:
                return d
    except Exception:
        return None
    return None


def delegation_code(policy, agent, kids, at=None):
    """0.2.15: None when the signers `kids` (bytes) may confirm an action of `agent` under `policy`, else WQ_SELF (the agent's operator
    signed) or WQ_NOT_DELEGATE (a signer is not a named approver, or `at` is past their term). A refusal is never judged here."""
    d = delegation_of(policy, agent) if agent is not None else None
    if d is None:
        return None
    hx = [k.hex() if isinstance(k, bytes) else k for k in kids]
    if d["operator"] in hx:
        return "WQ_SELF"
    ap = d["approvers"]
    if ap is not None:
        if at is not None and d["until"] is not None and at > d["until"]:
            return "WQ_NOT_DELEGATE"
        if any(k not in ap for k in hx):
            return "WQ_NOT_DELEGATE"
    return None


def phone_lift_payload(principal, kid, not_before, nonce) -> bytes:
    """0.2.15: CDE {v, principal, kid, not_before, nonce(16)} that k >= 2 OTHER members (rule `recovery` of the team policy) sign to let
    a key declared "my new phone" with a recovery code count as a phone before its delay ends."""
    if not isinstance(principal, str) or not _b32(kid) or not _uint(not_before) or not isinstance(nonce, bytes) or len(nonce) != 16:
        raise ValueError("MALFORMED")
    return cde({"v": V_PHONE_LIFT, "principal": principal, "kid": kid, "not_before": not_before, "nonce": nonce})


def _grant(v):
    return v is not None and v is not False


def _money_level(perm):
    """max(budget, max_per_action, min_price) of a money class; True (no limits) is unbounded."""
    if perm is True:
        return INF
    if not isinstance(perm, dict):
        return 0
    return max([perm.get(k) for k in ("budget", "max_per_action", "min_price") if _uint(perm.get(k))] or [0])


def requirements(policy, typ, payload_map, action=None):
    """2.2: [(role, k)] to meet, one entry per role (max k of the rules that fire). One pure function for server and verifier.
    mandate: payload_map = mandate map; approval: payload carries only a hash, so the ACTION (class/amount) is needed -- without it
    the list is empty (stateless part of the check); revocation/ceiling/policy: the single request of rules."""
    rule = RULE_OF_TYP.get(typ)
    rules = policy["rules"]
    out = {}

    def add(role, k):
        out[role] = max(out.get(role, 0), k)

    if rule in ("revocation", "ceiling", "policy"):
        add(rules[rule]["role"], rules[rule]["k"])
    elif rule == "mandate":
        perms = (payload_map or {}).get("permissions") or {}
        money = [c for c in MONEY if _grant(perms.get(c))]
        level = max([_money_level(perms[c]) for c in money] or [0])
        access = any(_grant(perms.get(c)) for c in NONMONEY)
        for t in rules["mandate"]:
            if (t["if"] == "money" and money) or (t["if"] == "access" and access) or \
                    (t["if"] == "money_over" and money and level > t["amount"]):
                add(t["role"], t["k"])
    elif rule == "approval" and action is not None:
        is_money = action.get("class") in MONEY
        amount = action.get("amount") if _uint(action.get("amount")) else 0
        for t in rules["approval"]:
            if (t["if"] == "money" and is_money) or (t["if"] == "access" and not is_money) or \
                    (t["if"] == "money_over" and is_money and amount > t["amount"]):
                add(t["role"], t["k"])
    return sorted(out.items())


def _norm(chain):
    out = []
    for e in chain:
        if isinstance(e, dict):
            out.append((e["policy"], e.get("envelope"), e.get("t")))
        else:
            out.append((e[0], e[1] if len(e) > 1 else None, e[2] if len(e) > 2 else None))
    return out


def policy_at(chain_with_t, t):
    """Version in force at time t (policy[v].t <= t < policy[v+1].t); None if t precedes version 1."""
    ver = None
    for i, (pb, _, pt) in enumerate(_norm(chain_with_t)):
        if pt is not None and pt <= t:
            ver = i + 1
    return ver


def _reg_of(member, rp):
    return {"alg": "ES256", "pub": member["pub"].hex(),
            "webauthn": {"rp_id": rp["rp_id"], "origins": list(rp["origins"]), "credential_id": wa.b64u(member.get("cred", b""))}}


def _parse_wq(env):
    m = cbor2.loads(env)
    if not isinstance(m, dict) or set(m) != set(WQ_KEYS) or m["v"] != V_WQ:
        return None
    if not isinstance(m["typ"], str) or not isinstance(m["payload"], bytes) or not _b32(m["policy"]):
        return None
    s = m["sigs"]
    if not isinstance(s, list) or not 1 <= len(s) <= MAX_MEMBERS:
        return None
    for w in s:
        if not isinstance(w, dict) or set(w) != set(WSIG_KEYS) or not _b32(w["kid"]) or len(w["sig"] if isinstance(w["sig"], bytes) else b"") != 64:
            return None
        if not isinstance(w["authData"], bytes) or not isinstance(w["clientDataJSON"], bytes):
            return None
    if cde(m) != env:
        return None
    return m


def verify_wq(env, expect_typ, expect_payload, chain, action=None, rp=None, at=None, rule=None, agent=None):
    """Verify a quorum envelope. Returns None when valid, else a code. Order (normative for this profile):
    1 structure (WQ_MALFORMED; unsorted kid; WQ_DUP_SIGNER for a repeated kid)  2 typ/payload (*_SIG)  3 policy known in chain (WQ_POLICY_UNKNOWN)
    4 only with `at`: the policy was in force at `at` (WQ_POLICY_STALE)  5 every signer is a member (WQ_NOT_MEMBER)
    6 each signature, in kid order, by the steps of wa 3.5 (first broken -> its WA_*/KEY_MISMATCH)  7 requirements (WQ_QUORUM).
    chain is NOT re-verified here (use verify_policy_chain once). For expect_typ = org-policy the quorum is judged by the rule `policy`
    of the policy named in the envelope (the PREVIOUS version). rp: {rp_id, origins}. at: the witnessed time of the ledger entry.
    rule: {role, k} judged INSTEAD of requirements() (0.2.2: the `recovery` rule of a key replacement, see policy_step).
    agent (0.2.15, approvals only): the mandate's agent; with a rules.delegation entry for it in the policy named by the envelope,
    step 6b refuses a wq that contains the operator's signature (WQ_SELF) or a signer outside the named approvers (WQ_NOT_DELEGATE;
    with `at`, also after `until`). Pass it for an approval, never for a refusal (the operator may always stop)."""
    try:
        m = _parse_wq(env)
    except Exception:
        m = None
    if m is None:
        return "WQ_MALFORMED"
    kids = [w["kid"] for w in m["sigs"]]
    if kids != sorted(kids):
        return "WQ_MALFORMED"
    if len(set(kids)) != len(kids):
        return "WQ_DUP_SIGNER"
    if m["typ"] != expect_typ or m["payload"] != expect_payload:
        return SIG_CODE.get(expect_typ, "MANDATE_SIG")
    ch = _norm(chain)
    idx = None
    for i, (pb, _, _) in enumerate(ch):
        if hashlib.sha256(pb).digest() == m["policy"]:
            idx = i
    if idx is None:
        return "WQ_POLICY_UNKNOWN"
    try:
        policy = cbor2.loads(ch[idx][0])
    except Exception:
        return "WQ_POLICY_UNKNOWN"
    if at is not None:
        t0 = ch[idx][2]
        t1 = ch[idx + 1][2] if idx + 1 < len(ch) else None
        if t0 is None or at < t0 or (t1 is not None and at >= t1):
            return "WQ_POLICY_STALE"
    members = {mm["kid"]: mm for mm in policy["members"]}
    if any(k not in members for k in kids):
        return "WQ_NOT_MEMBER"
    if rp is None:
        raise ValueError("rp (rp_id, origins) is required to verify signatures")
    for w in m["sigs"]:
        one = cde({"v": wa.V, "typ": m["typ"], "kid": w["kid"], "payload": m["payload"], "authData": w["authData"],
                   "clientDataJSON": w["clientDataJSON"], "sig": w["sig"]})
        code = wa.verify_envelope(one, expect_typ, expect_payload, _reg_of(members[w["kid"]], rp))
        if code:
            return code
    if agent is not None and expect_typ == wa.TYP_APPROVAL:
        code = delegation_code(policy, agent, kids, at)
        if code:
            return code
    try:
        pm = cbor2.loads(m["payload"]) if expect_typ in (wa.TYP_MANDATE,) else None
        if expect_typ == wa.TYP_MANDATE and not isinstance(pm, dict):
            return "WQ_MALFORMED"
    except Exception:
        return "WQ_MALFORMED"
    for role, k in ([(rule["role"], rule["k"])] if rule is not None else requirements(policy, expect_typ, pm, action)):
        n = sum(1 for kid in kids if role == "any" or role in members[kid]["roles"])
        if n < k:
            return "WQ_QUORUM"
    return None


def wb_requirements_met(policy, kid, action, typ=wa.TYP_APPROVAL):
    """A wb carries ONE signature, so it is valid for an item only when the requirement of the item is k = 1 for a role the signer holds.
    typ = revocation (0.2.2): the rule `revocation` of the policy (always {any, 1} on the server)."""
    mem = {m["kid"]: m for m in policy["members"]}.get(kid)
    if mem is None:
        return "WQ_NOT_MEMBER"
    for role, k in requirements(policy, typ, None, action):
        if k > 1 or (role != "any" and role not in mem["roles"]):
            return "WQ_QUORUM"
    return None


def verify_wb(env, expect_typ, expect_payload, reg_entry_or_member, rp=None):
    """Batch approval (or 0.2.2 batch revocation): wa 3.5 over challenge = wb_challenge(items, typ) + SHA-256(expect_payload) in items.
    Returns None or a code.
    reg_entry_or_member: a registry entry (as wa_profile) or a policy member map (then rp is required)."""
    try:
        m = cbor2.loads(env)
        if not isinstance(m, dict) or set(m) != set(WB_KEYS) or m["v"] != V_WB or m["typ"] not in WB_TYPS:
            return "WB_MALFORMED"
        it = m["items"]
        if not isinstance(it, list) or not 1 <= len(it) <= MAX_ITEMS or not all(_b32(x) for x in it):
            return "WB_MALFORMED"
        if not _b32(m["kid"]) or not all(isinstance(m[k], bytes) for k in ("authData", "clientDataJSON", "sig")) or len(m["sig"]) != 64:
            return "WB_MALFORMED"
        if cde(m) != env:
            return "WB_MALFORMED"
    except Exception:
        return "WB_MALFORMED"
    if expect_typ != m["typ"]:      # 0.2 vector b11: anything else than the two batch types answers APPROVAL_SIG
        return SIG_CODE[expect_typ] if expect_typ in WB_TYPS else "APPROVAL_SIG"
    if hashlib.sha256(expect_payload).digest() not in m["items"]:
        return "WB_ITEM"
    reg = reg_entry_or_member
    if "webauthn" not in reg:
        reg = _reg_of(reg, rp)
    try:
        pub = bytes.fromhex(reg["pub"])
        if reg.get("alg") != "ES256" or m["kid"] != wa.thumbprint(pub):
            return "KEY_MISMATCH"
        w = reg["webauthn"]
    except Exception:
        return "KEY_MISMATCH"
    import json
    try:
        cd = json.loads(m["clientDataJSON"].decode("utf-8"))
        if not isinstance(cd, dict) or cd.get("type") != "webauthn.get" or cd.get("challenge") != wa.b64u(wb_challenge(m["items"], m["typ"])) \
                or cd.get("origin") not in w["origins"] or cd.get("crossOrigin", False) is not False:
            return "WA_CLIENTDATA"
    except Exception:
        return "WA_CLIENTDATA"
    ad = m["authData"]
    if len(ad) < 37 or ad[:32] != hashlib.sha256(w["rp_id"].encode()).digest() or not (ad[32] & wa.FLAG_UP) or not (ad[32] & wa.FLAG_UV):
        return "WA_AUTHDATA"
    r, s = int.from_bytes(m["sig"][:32], "big"), int.from_bytes(m["sig"][32:], "big")
    if not (0 < r < wa.P256_N and 0 < s <= wa.P256_N // 2):
        return "WA_SIG"
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
        key.verify(encode_dss_signature(r, s), ad + hashlib.sha256(m["clientDataJSON"]).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return "WA_SIG"
    return None


def verify_policy_chain(chain, rp=None):
    """Verify the whole chain of org policies. None when ok, else (code, ver). Codes: POLICY_MALFORMED, POLICY_CHAIN (gap/prev/principal),
    WQ_* and WA_* (signature of that version). Genesis (ver 1) = ordinary wa-sig of the single member (all roles, all k = 1);
    ver >= 2 = wq signed by the rule `policy` of the PREVIOUS version. rp: {rp_id, origins}."""
    ch = _norm(chain)
    if not ch:
        return ("POLICY_CHAIN", 0)
    prev_hash, principal = None, None
    for i, (pb, env, _) in enumerate(ch):
        ver = i + 1
        try:
            p = cbor2.loads(pb)
        except Exception:
            return ("POLICY_MALFORMED", ver)
        if not isinstance(p, dict) or cde(p) != pb:
            return ("POLICY_MALFORMED", ver)
        if validate_policy(p):
            return ("POLICY_MALFORMED", ver)
        if p["ver"] != ver:
            return ("POLICY_CHAIN", ver)
        if p["prev"] != prev_hash:
            return ("POLICY_CHAIN", ver)
        if principal is not None and p["principal"] != principal:
            return ("POLICY_CHAIN", ver)
        principal = p["principal"]
        if rp is None:
            raise ValueError("rp is required")
        if ver == 1:
            ms = p["members"]
            full = len(ms) == 1 and set(ms[0]["roles"]) == set(ROLES) and all(
                q["k"] == 1 for q in [p["rules"]["policy"], p["rules"]["revocation"], p["rules"]["ceiling"]] + p["rules"]["mandate"] + p["rules"]["approval"])
            if not full:
                return ("POLICY_MALFORMED", ver)
            if envelope_kind(env or b"") != "wa":
                return ("WA_MALFORMED", ver)
            code = wa.verify_envelope(env, TYP_POLICY, pb, _reg_of(ms[0], rp))
            if code:
                return (code, ver)
        else:
            code = policy_step(ch[:i], pb, env, rp)
            if code:
                return (code, ver)
        prev_hash = hashlib.sha256(pb).digest()
    return None


# ---------------------------------------------------------------- 0.2.2: recovery (lost passkey)
def key_swap(prev, new):
    """-> (old_kid, new_kid) when policy `new` is `prev` with exactly ONE member's key (kid, pub, cred) replaced and nothing else
    changed (same principal, rules, roles and label of every member), else None. Both are policy maps."""
    try:
        if new["principal"] != prev["principal"] or len(new["members"]) != len(prev["members"]):
            return None
        pk = {m["kid"]: m for m in prev["members"]}
        nk = {m["kid"]: m for m in new["members"]}
        gone, came = [k for k in pk if k not in nk], [k for k in nk if k not in pk]
        if len(gone) != 1 or len(came) != 1:
            return None
        if new["rules"] != swap_rules(prev["rules"], gone[0], came[0]):
            return None
        for k in pk:
            if k in nk and (pk[k]["roles"] != nk[k]["roles"] or pk[k]["label"] != nk[k]["label"] or pk[k]["cred"] != nk[k]["cred"]):
                return None
        o, n = pk[gone[0]], nk[came[0]]
        if o["roles"] != n["roles"] or o["label"] != n["label"]:
            return None
        return gone[0], came[0]
    except Exception:
        return None


def swap_rules(rules, old, new):
    """0.2.15: the rules after replacing key `old` by `new` (bytes): only the kids named in rules.delegation change (sorted again)."""
    if "delegation" not in rules:
        return rules
    o, n = old.hex(), new.hex()
    dl = []
    for d in rules["delegation"]:
        d = dict(d)
        if d["operator"] == o:
            d["operator"] = n
        if d["approvers"] is not None:
            d["approvers"] = sorted(n if k == o else k for k in d["approvers"])
        dl.append(d)
    return dict(rules, delegation=dl)


def policy_step(chain, pb, env, rp):
    """None when `env` validly adopts policy bytes `pb` as the version after `chain` (verified already), else a code. The normal path:
    a wq of the rule `policy` of the last version. The recovery path (0.2.2): `pb` only replaces ONE member's key (key_swap) and the
    last version has a rule `recovery`; then that rule is met by signers OTHER than the replaced key (the lost key never counts).
    In both cases the wq names the last version exactly."""
    ch = _norm(chain)
    if envelope_kind(env or b"") != "wq":
        return "WQ_MALFORMED"
    code = verify_wq(env, TYP_POLICY, pb, ch, rp=rp)
    if code == "WQ_QUORUM":
        prev = cbor2.loads(ch[-1][0])
        sw = key_swap(prev, cbor2.loads(pb))
        rc = prev["rules"].get("recovery")
        if sw is not None and rc is not None and sw[0] not in [w["kid"] for w in cbor2.loads(env)["sigs"]]:
            code = verify_wq(env, TYP_POLICY, pb, ch, rp=rp, rule=rc)
    if code:
        return code
    if cbor2.loads(env)["policy"] != hashlib.sha256(ch[-1][0]).digest():
        return "POLICY_CHAIN"
    return None


def key_event_payload(principal, op, kid, pub, cred, nonce) -> bytes:
    """CDE {v, principal, op: "add"|"remove", kid, pub, cred, nonce(16)} signed (wa-sig, typ application/dw-key-event+cbor) by a passkey
    that is ACTIVE on the account when the event is recorded: adding a second passkey or removing one is a signature over the exact key."""
    if op not in ("add", "remove") or not _b32(kid) or not isinstance(pub, bytes) or len(pub) != 65 or wa.thumbprint(pub) != kid \
            or not isinstance(cred, bytes) or not isinstance(nonce, bytes) or len(nonce) != 16 or not isinstance(principal, str):
        raise ValueError("MALFORMED")
    return cde({"v": V_KEY_EVENT, "principal": principal, "op": op, "kid": kid, "pub": pub, "cred": cred, "nonce": nonce})


def parse_key_event(b):
    """-> the key-event map or None (structure, CDE, kid = thumbprint(pub))."""
    try:
        m = cbor2.loads(b)
        if not isinstance(m, dict) or set(m) != set(KEY_EVENT_KEYS) or m["v"] != V_KEY_EVENT or cde(m) != b:
            return None
        key_event_payload(m["principal"], m["op"], m["kid"], m["pub"], m["cred"], m["nonce"])
        return m
    except Exception:
        return None


def key_intervals(base_kid, base_t, events):
    """events: [(t, op, kid)] in registry order -> {kid: [(from_t, until_t|None), ...]}. The pinned key is active from base_t."""
    out = {base_kid: [[base_t, None]]}
    for t, op, kid in events:
        iv = out.setdefault(kid, [])
        if op == "add" and (not iv or iv[-1][1] is not None):
            iv.append([t, None])
        elif op == "remove" and iv and iv[-1][1] is None:
            iv[-1][1] = t
    return {k: [tuple(x) for x in v] for k, v in out.items()}


def key_active_at(intervals, kid, t):
    """A signature by kid is acceptable in an entry witnessed at t: from_t <= t < until_t (the second pass of 0.2.2)."""
    return any(a <= t and (b is None or t < b) for a, b in intervals.get(kid, ()))
