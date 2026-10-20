#!/usr/bin/env python3 -I
"""Generate verifier_swift extra conformance vectors (X*). Byte vectors are mutations of spec/vectors/cose (read-only)."""
import json, copy, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'extra-vectors')
COSE = os.path.join(HERE, '..', '..', 'spec', 'vectors', 'cose')
M = {"id": "m1", "principal": "pk-principal", "agent": "agent-1", "nbf": 0, "exp": 86400, "key_attestation": "software",
     "permissions": {"message": {"to": ["buh@firma3.example", "partner@firma3.example"]},
                     "file": {"to": ["buh@firma3.example", "partner@firma3.example"]},
                     "disclosure": {"to": ["buh@firma3.example", "partner@firma3.example"], "data": []},
                     "purchase": {"max_per_action": 25000, "budget": 62500}, "sale": {"min_price": 0},
                     "meeting": True, "refund": True,
                     "delete": {"targets": ["repo:tmp/*", "doc:draft-1"], "allow_irreversible": False}},
     "forbidden_data": [], "budget_window_s": 86400, "named_circle": False, "v": "deus-aar-0.1", "currency": "USD"}
def act(cls, rcpt="", data=(), amount=0, **kw):
    a = {"class": cls, "agent": "agent-1", "t": 100, "amount": amount, "recipient": rcpt, "data": list(data)}
    if cls in ("purchase", "sale", "refund"): a["currency"] = "USD"
    a.update(kw); return a
vecs = []
def D(id, title, basis, expected, action, perms=None, mand=None, cls="invalid", raw=None, **inp):
    m = copy.deepcopy(M)
    if perms: m["permissions"].update(perms)
    if mand: m.update(mand)
    v = {"id": id, "class": cls, "kind": "decision", "title": title, "basis": basis,
         "input": dict({"mandate": m, "action": action}, **inp), "expected": expected}
    vecs.append((v, raw))
def dn(r): return {"verdict": "deny", "reason": r}

D("X01", "Amount written 100.0 is a float even though its value is integral", "5.2 ('a number written with a fraction ... denotes a floating-point value and is rejected'), App. A conv. 4",
  dn("BAD_AMOUNT"), act("purchase", amount=100.0))
D("X02", "Amount written 1e2 (exponent) is a float", "5.2", dn("BAD_AMOUNT"), act("purchase", amount="__1e2__"), raw=('"__1e2__"', '1e2'))
D("X03", "Lower-case currency 'usd' is another currency (no conversion, no case folding)", "5.2 ('any currency other than the mandate's currency ... BAD_AMOUNT'; 'MUST NOT round or convert')",
  dn("BAD_AMOUNT"), act("purchase", amount=100, currency="usd"))
D("X04", "Refund without currency", "5.2 ('currency is REQUIRED ... in every monetary action (purchase, sale, refund)')", dn("BAD_AMOUNT"),
  {k: v for k, v in act("refund", amount=100).items() if k != "currency"})
D("X05", "Data label 'City' is unregistered, hence protected; disclosure absent", "5.5 (byte-exact; 'City' is not 'city'), 6.4 step 12",
  dn("DATA_NOT_PERMITTED"), act("message", "buh@firma3.example", ["City"]), perms={"disclosure": None})
D("X06", "Publish with 'City' (protected because unregistered) is denied before channel checks", "5.5, 6.4 step 10 publish",
  dn("DATA_FORBIDDEN"), act("publish", "blog:main", ["City"]), perms={"publish": {"channels": ["blog:main"]}})
D("X07", "Delete pattern never matches an r with a '.' segment", "5.6.1 ('a pattern never matches an r that contains a . or .. path segment')",
  dn("RESOURCE"), act("delete", "repo:tmp/./x", reversible=True))
D("X08", "Delete with matched target, reversible given as string 'true' is irreversible", "5.6 / 6.4 step 10 delete ('reversible is true only for the boolean true')",
  dn("IRREVERSIBLE_DELETE"), act("delete", "repo:tmp/x", reversible="true"))
D("X09", "'<>' with nothing between the brackets is an invalid recipient", "5.4 step 1 ('at least one character between them')",
  dn("RECIPIENT"), act("message", "<>"))
D("X10", "'>' before '<' is an invalid recipient", "5.4 step 1 ('exactly one < followed by exactly one >')",
  dn("RECIPIENT"), act("message", "buh@firma3.example> x <"))
D("X11", "to: [\"*\"] is a list containing the literal string '*', not the wildcard", "6.1 CDDL ('to': \"*\" / [* tstr]); 5.4 exact comparison",
  dn("RECIPIENT"), act("message", "x@y.example"), perms={"message": {"to": ["*"]}})
D("X12", "Named circle opens a file recipient but never protected data (step 12 uses disclosure recipients only)", "6.5 ('never opens protected data'), 6.4 step 12 ('the named circle never applies')",
  dn("RECIPIENT"), act("file", "partner@firma3.example", ["phone"]), mand={"named_circle": True},
  perms={"file": {"to": ["buh@firma3.example"]}, "message": {"to": ["partner@firma3.example"]}, "disclosure": {"to": ["buh@firma3.example"], "data": ["phone"]}})
D("X13", "forbidden_data is checked before the meeting rule", "6.4 step 7 before step 9", dn("DATA_FORBIDDEN"),
  act("meeting", "", ["address"], principal_present=True), mand={"forbidden_data": ["address"]})
D("X14", "AGENT_MISMATCH precedes EXPIRED", "6.4 order (step 3 before step 4)", dn("AGENT_MISMATCH"),
  dict(act("message", "buh@firma3.example"), agent="agent-2", t=999999))
D("X15", "Witness time exp+1 is outside [nbf, exp]", "6.4 step 4", dn("EXPIRED"), dict(act("message", "buh@firma3.example"), t=86401))
D("X16", "Witness time == exp is inside [nbf, exp]", "6.4 step 4 (closed interval)", {"verdict": "allow", "reason": "OK"},
  dict(act("message", "buh@firma3.example"), t=86400), cls="valid")
D("X17", "Default-ignorable code point (ZWSP) is removed by toNFKC_Casefold, so the recipient matches", "5.4 step 2 (NFKC_CF removes default-ignorable code points)",
  {"verdict": "allow", "reason": "OK"}, act("file", "buh@firma3.ex​ample"), cls="valid")
D("X18", "Fullwidth letters fold to ASCII under NFKC; capital sharp S folds to 'ss'", "5.4 step 2",
  {"verdict": "allow", "reason": "OK"}, act("file", "ＳＴＲＡẞE@firma3.example"), perms={"file": {"to": ["strasse@firma3.example"]}}, cls="valid")
D("X19", "Purchase: committed + amount = budget + 1 is BUDGET", "6.4 step 10 purchase ('committed(M) + amount > budget')", dn("BUDGET"),
  act("purchase", amount=2501), ledger_state={"mandate_committed": 60000, "principal_committed": 60000})
D("X20", "Purchase exactly reaching the budget is allowed", "6.4 step 10 purchase (strict >)", {"verdict": "allow", "reason": "OK"},
  act("purchase", amount=2500), ledger_state={"mandate_committed": 60000, "principal_committed": 60000}, cls="valid")
D("X21", "Sale with protected data and no disclosure grant: step 12 applies to sale", "6.4 step 12 ('for every action class except publish')",
  dn("DATA_FORBIDDEN"), act("sale", "buyer", ["address"], amount=1000))

# --- sequence vectors
def mop(m=None): return {"op": "register_mandate", "mandate": m or copy.deepcopy(M), "signed_by": "pk-principal"}
def auth(id, a, ttl=300): return {"op": "authorize", "id": id, "mandate": "m1", "action": a, "ttl": ttl}
def S(id, title, basis, ops, steps, cls="invalid"):
    vecs.append(({"id": id, "class": cls, "kind": "sequence", "title": title, "basis": basis,
                  "input": {"pinned_principal_key": "pk-principal", "ops": ops}, "expected": {"steps": steps}}, None))
mu = copy.deepcopy(M); mu["permissions"]["purchase"] = {"max_per_action": 25000, "budget": None}
S("XS01", "An approval is bound to one receipt: an identical second request stays deferred and is NOT_ALLOWED at the tool",
  "6.6 ('cannot be reused for a second, identical request'), 8.4 check 3",
  [mop(mu), auth("a0", act("purchase", amount=500)), {"op": "approve", "receipt": "a0", "signed_by": "pk-principal"},
   auth("a1", act("purchase", amount=500)), {"op": "tool_present", "receipt": "a1"}],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "accept", "verdict": "allow"},
   {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "reject", "reason": "NOT_ALLOWED"}])
S("XS02", "Second RECEIPT with the same id is refused", "7.1 ('MUST refuse a second RECEIPT with the same id (DUPLICATE_RECEIPT_ID)')",
  [mop(), auth("r0", act("message", "buh@firma3.example")), auth("r0", act("message", "partner@firma3.example"))],
  [{"result": "accept"}, {"verdict": "allow", "reason": "OK"}, {"result": "reject", "reason": "DUPLICATE_RECEIPT_ID"}])
S("XS03", "Tool non-execution report after the tool consumed does not release budget", "7.4 (release only of an active reservation)",
  [mop(), auth("r0", act("purchase", amount=25000)), {"op": "tool_present", "receipt": "r0"},
   {"op": "tool_report", "receipt": "r0", "executed": False}, auth("r1", act("purchase", amount=25000)), auth("r2", act("purchase", amount=25000))],
  [{"result": "accept"}, {"verdict": "allow", "reason": "OK"}, {"result": "accept"}, {"result": "ignored"},
   {"verdict": "allow", "reason": "OK"}, {"verdict": "deny", "reason": "BUDGET"}])
S("XS04", "Revocation by the pinned key releases the deferred reservation; ceiling headroom returns, but the mandate is EXPIRED",
  "6.7 ('Outstanding active reservations ... are released'; 'Actions evaluated after it are denied (EXPIRED)')",
  [mop(mu), {"op": "register_ceiling", "id": "c1", "amount": 600, "currency": "USD", "window_s": 86400, "signed_by": "pk-principal"},
   auth("a0", act("purchase", amount=500)), {"op": "revoke", "mandate": "m1", "signed_by": "pk-principal"},
   auth("a1", act("purchase", amount=500))],
  [{"result": "accept"}, {"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "accept"},
   {"verdict": "deny", "reason": "EXPIRED"}])
S("XS05", "Approval after the deferral expired is refused (reservation already released as expired)",
  "6.6 ('On timeout the reservation expires like any other'), 7.4 (b)",
  [mop(mu), auth("a0", act("purchase", amount=500)), {"op": "clock", "t": 1000},
   {"op": "approve", "receipt": "a0", "signed_by": "pk-principal"}],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "ok"}, {"result": "reject", "reason": "NOT_DEFERRED"}])

# --- verification vectors
def ent(seq, typ, body, t=100):
    return {"seq": seq, "type": typ, "t": t, "body": body, "prev": None if seq == 0 else "h%d" % (seq - 1), "hash": "h%d" % seq}
DEFAULT_REASON = {"allow": "OK", "defer": "ESCALATE_MONEY", "deny": "RECIPIENT"}
def rcpt(id, a, verdict="allow", reason=None, **kw):
    # -02 7.1: `reason` REQUIRED; `audience` REQUIRED except for a logged deny NO_MANDATE
    b = {"id": id, "mandate": "m1", "action": a, "verdict": verdict, "reason": reason or DEFAULT_REASON[verdict], "ttl": 300}
    if not (verdict == "deny" and b["reason"] == "NO_MANDATE"): b["audience"] = "tool-A"
    b.update(kw)
    return {k: v for k, v in b.items() if v is not None}
MAND = {"mandate": copy.deepcopy(M), "signed_by": "pk-principal"}
P1 = act("purchase", amount=1000)
def Vv(id, title, basis, entries, expected, cls="invalid", **extra):
    inp = {"witness_key": "pk-witness", "operator_keys": ["pk-operator"], "pinned_principal_key": "pk-principal", "entries": entries}
    inp.update(extra)
    vecs.append(({"id": id, "class": cls, "kind": "verification", "title": title, "basis": basis, "input": inp, "expected": expected}, None))
def inv(r, at=None):
    d = {"result": "invalid", "reason": r}
    if at is not None: d["at"] = at
    return d
Vv("XV01", "CONSUME of a deny receipt", "10 step 6 ('the corresponding receipt was allow')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("message", "evil@zlo.example"), "deny", "RECIPIENT")), ent(2, "CONSUME", {"receipt": "r0"})],
   inv("CONSUME_INVALID", 2))
Vv("XV02", "Second CONSUME of the same receipt", "10 step 6 ('unconsumed')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "CONSUME", {"receipt": "r0"}), ent(3, "CONSUME", {"receipt": "r0"})],
   inv("CONSUME_INVALID", 3))
Vv("XV03", "RELEASE cause refused without a refusing APPROVAL", "7.4 ('with refused without a refusing APPROVAL ... RELEASE_INVALID')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RELEASE", {"receipt": "r0", "cause": "refused"})],
   inv("RELEASE_INVALID", 2))
Vv("XV04", "RELEASE cause revoked without a REVOCATION", "7.4 ('revoked without a preceding REVOCATION of its mandate')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RELEASE", {"receipt": "r0", "cause": "revoked"})],
   inv("RELEASE_INVALID", 2))
Vv("XV05", "RELEASE cause expired at t == expires (not yet expired)", "7.4 ('expired before expires'; release only after now > expires)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RELEASE", {"receipt": "r0", "cause": "expired"}, 400)],
   inv("RELEASE_INVALID", 2))
Vv("XV06", "RECEIPT without ttl", "-02 7.1 receipt-body ('ttl' REQUIRED; a body that does not match its shape is MALFORMED), 10 step 4",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", {k: v for k, v in rcpt("r0", P1).items() if k != "ttl"})], inv("MALFORMED", 1))
Vv("XV07", "Logged NO_MANDATE refusal for a mandate that IS in the ledger", "10 step 5 (exception only for an unknown mandate; re-evaluation gives allow)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("message", "buh@firma3.example"), "deny", "NO_MANDATE"))], inv("VERDICT_NOT_REPRODUCIBLE", 1))
Vv("XV08", "CONSUME of a purchase after expiry: under -02 step 7(a) runs before steps 4-6, so RELEASE_MISSING (not CONSUME_INVALID)", "-02 10 ('7(a) ... evaluated for each entry directly after step 3'), 7.4 (b)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "CONSUME", {"receipt": "r0"}, 401)], inv("RELEASE_MISSING", 2))
Vv("XV09", "APPROVAL signed by the operator key", "6.6, 10 step 4 (MANDATE_KEY in a verifier)",
   [ent(0, "MANDATE", {"mandate": mu, "signed_by": "pk-principal"}, 0), ent(1, "RECEIPT", rcpt("r0", act("purchase", amount=500), "defer", "ESCALATE_MONEY")),
    ent(2, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-operator"})], inv("MANDATE_KEY", 2))
Vv("XV10", "Witness signed 'allow' with a wrong reason (OK_UNSPECIFIED instead of OK)", "10 step 5 ('gives the signed verdict and reason')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("message", "buh@firma3.example"), "allow", "OK_UNSPECIFIED"))], inv("VERDICT_NOT_REPRODUCIBLE", 1))
Vv("XV11", "RECEIPT after a missing RELEASE: -02 evaluates 7(a) first, so RELEASE_MISSING is reported before the re-evaluation of step 5 (was VERDICT_NOT_REPRODUCIBLE under the literal -01 order)",
   "-02 10 (7(a) directly after step 3), 7.3 ('a verifier reports a missing RELEASE before it re-evaluates anything'), App. E C-5",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("purchase", amount=25000))), ent(2, "RECEIPT", rcpt("r1", act("purchase", amount=25000))),
    ent(3, "RECEIPT", rcpt("r2", dict(act("purchase", amount=25000), t=1000)), 1000)], inv("RELEASE_MISSING", 3))

# =====================  -02 additions  =====================
# --- decision
D("X22", "Non-monetary action with amount 5", "-02 5.2 ('any other value (for example amount: 5 on a message) is BAD_AMOUNT'), 6.4 step 6",
  dn("BAD_AMOUNT"), act("message", "buh@firma3.example", amount=5))
D("X23", "Non-monetary action without amount is allowed", "-02 5.2 ('A non-monetary action carries amount 0 or no amount')",
  {"verdict": "allow", "reason": "OK"}, {k: v for k, v in act("message", "buh@firma3.example").items() if k != "amount"}, cls="valid")
D("X24", "Non-monetary action with amount 0.0 (float) is BAD_AMOUNT", "-02 5.2 (floating-point values rejected; 'Amount invalid' in 6.4 step 6 applies to every class)",
  dn("BAD_AMOUNT"), act("message", "buh@firma3.example", amount=0.0))
D("X25", "Disclosure without protected data, message=false, disclosure granted: CLASS_DENIED (explicit denial wins)", "-02 6.4 step 8 ('message = false is CLASS_DENIED for it too'), App. E C-9",
  dn("CLASS_DENIED"), act("disclosure", "buh@firma3.example", ["city"]), perms={"message": False})
D("X26", "File with an invalid recipient and the file permission unspecified: RECIPIENT, not ESCALATE_FILE", "-02 5.4 step 1 ('is not OK_UNSPECIFIED or ESCALATE_FILE'), 6.4 step 10",
  dn("RECIPIENT"), act("file", "<a@b.example> <c@d.example>"), perms={"file": None})
D("X27", "Message to '*' with an invalid recipient: RECIPIENT", "-02 5.4 step 1 ('an invalid recipient is not matched by to: \"*\"')",
  dn("RECIPIENT"), act("message", "x<y"), perms={"message": {"to": "*"}})
D("X28", "Mandate with to: null and a domains list: only the listed domain matches", "-02 6.1 (? to / null), 6.2 ('to: null with a domains list is a specification')",
  dn("RECIPIENT"), act("message", "x@other.example"), perms={"message": {"to": None, "domains": ["firma3.example"]}})
D("X29", "domains: null with a to list is a valid specification (domains null allowed in -02)", "-02 6.1 (? domains: [* tstr] / null), App. E C-1",
  {"verdict": "allow", "reason": "OK"}, act("message", "buh@firma3.example"), perms={"message": {"to": ["buh@firma3.example"], "domains": None}}, cls="valid")
D("X30", "Named circle: a recipient granted only through message.domains does not open the circle for file", "-02 6.5 ('a domains list and to: \"*\" do NOT belong to the circle')",
  dn("RECIPIENT"), act("file", "anyone@firma9.example"), mand={"named_circle": True},
  perms={"message": {"domains": ["firma9.example"]}, "file": {"to": ["buh@firma3.example"]}})
D("X31", "Named circle applies to a disclosure without protected data (evaluated under message)", "-02 6.5 ('applies to message, to file and to a disclosure without protected data')",
  {"verdict": "allow", "reason": "OK_CIRCLE"}, act("disclosure", "partner@firma3.example", ["city"]), mand={"named_circle": True},
  perms={"message": {"to": ["buh@firma3.example"]}, "file": {"to": ["partner@firma3.example"]}}, cls="valid")
D("X32", "Meeting with principal_present = 1 (not the boolean true)", "-02 5.6 ('any other value, e.g. \"yes\" or 1, = not present'), 6.4 step 9",
  dn("UNATTENDED_MEETING"), act("meeting", "", principal_present=1))
D("X33", "Disclosure permission with data but no to/domains: recipients unspecified -> OK_UNSPECIFIED in step 10, then ESCALATE_DATA in step 12 (C reading; see AMBIGUITY-C2-6)",
  "-02 6.2 ('unspecified is exactly: to null or absent AND domains null or absent'), 6.4 step 10 disclosure, step 12",
  {"verdict": "defer", "reason": "ESCALATE_DATA"}, act("disclosure", "anyone@x.example", ["address"]), perms={"disclosure": {"data": ["address"]}})
D("X34", "Purchase permission {} (both members absent = null): defer ESCALATE_MONEY", "-02 6.1 (optional members, absent = null), 6.4 step 10 purchase",
  {"verdict": "defer", "reason": "ESCALATE_MONEY"}, act("purchase", amount=100), perms={"purchase": {}})

# --- sequence: mandate/ceiling CDDL, C-6 approved AAR, C-7 only purchase reserves
mn = copy.deepcopy(M); mn["named_circle"] = None
S("XS06", "named_circle: null is well formed (-03: every `?` member also accepts null; under -02 C read it literally as MANDATE_MALFORMED)",
  "-03 6.1 CDDL ('? \"named_circle\": bool / null'; 'every `?` member also accepts null'), App. F C2-1",
  [mop(mn)], [{"result": "accept"}], cls="valid")
mx = copy.deepcopy(M); mx["permissions"]["purchase"] = {"max_per_action": 25000, "budget": 62500, "note": "x"}
S("XS07", "Unknown member inside a permission map", "-02 6.1 ('Members not named in the CDDL are not allowed, in the mandate and in the permission maps')",
  [mop(mx)], [{"result": "reject", "reason": "MANDATE_MALFORMED"}])
S("XS08", "Ceiling with window_s 0", "-02 6.3 ('window_s is an integer of at least 1'; 'window_s 0 ... CEILING_MALFORMED')",
  [mop(), {"op": "register_ceiling", "id": "c1", "amount": 600, "currency": "USD", "window_s": 0, "signed_by": "pk-principal"}],
  [{"result": "accept"}, {"result": "reject", "reason": "CEILING_MALFORMED"}])
S("XS09", "Ceiling with a member not named in the CDDL", "-02 6.3 ('a member ... not named here ... CEILING_MALFORMED')",
  [mop(), {"op": "register_ceiling", "id": "c1", "amount": 600, "currency": "USD", "window_s": 86400, "note": "x", "signed_by": "pk-principal"}],
  [{"result": "accept"}, {"result": "reject", "reason": "CEILING_MALFORMED"}])
S("XS10", "Approved AAR: executed once, then REPLAY (same identity as the deferral AAR)", "-02 6.6 (approved AAR, same sub), 8.4 check 6 ('accepted once'), App. E C-6",
  [mop(mu), auth("a0", act("purchase", amount=500)), {"op": "tool_present", "receipt": "a0"}, {"op": "approve", "receipt": "a0", "signed_by": "pk-principal"},
   {"op": "tool_present", "receipt": "a0"}, {"op": "tool_present", "receipt": "a0"}],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "reject", "reason": "NOT_ALLOWED"},
   {"result": "accept", "verdict": "allow"}, {"result": "accept"}, {"result": "reject", "reason": "REPLAY"}], cls="valid")
S("XS11", "Approved AAR does not extend the receipt: presented after the deferral's expires -> RECEIPT_EXPIRED (reservation released as expired first)",
  "-02 6.6 ('expires = the expires of the deferred RECEIPT ... there is no new ttl'), 8.4 check 7",
  [mop(mu), auth("a0", act("purchase", amount=500)), {"op": "approve", "receipt": "a0", "signed_by": "pk-principal"}, {"op": "clock", "t": 401},
   {"op": "tool_present", "receipt": "a0"}],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "accept", "verdict": "allow"}, {"result": "ok"},
   {"result": "reject", "reason": "RECEIPT_EXPIRED"}])
mc = copy.deepcopy(M); mc["permissions"]["purchase"] = {"max_per_action": 25000, "budget": 62500}
S("XS12", "A sale does not use the ceiling: sale 900 then purchase 500 under a ceiling of 1000 is allowed", "-02 7.3 ('Only a purchase creates a reservation'), 7.4 ('does not use the budget or the ceiling'), App. E C-7",
  [mop(mc), {"op": "register_ceiling", "id": "c1", "amount": 1000, "currency": "USD", "window_s": 86400, "signed_by": "pk-principal"},
   auth("s0", act("sale", "buyer", amount=900)), auth("p0", act("purchase", amount=500)), auth("p1", act("purchase", amount=501))],
  [{"result": "accept"}, {"result": "accept"}, {"verdict": "allow", "reason": "OK"}, {"verdict": "allow", "reason": "OK"},
   {"verdict": "deny", "reason": "CEILING"}], cls="valid")
mr = copy.deepcopy(M); mr["permissions"]["refund"] = None
S("XS13", "A deferred refund holds no reservation: the budget is untouched and a tool non-execution report has nothing to release",
  "-02 6.2 table ('a sale or refund does not' hold a reservation), 7.4", 
  [mop(mr), auth("f0", act("refund", "shop", amount=62500)), {"op": "tool_report", "receipt": "f0", "executed": False},
   auth("p0", act("purchase", amount=25000))],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "ignored"}, {"verdict": "allow", "reason": "OK"}], cls="valid")

# --- verification
Vv("XV12", "Deferred purchase approved and consumed: the deferred RECEIPT plus an approving APPROVAL counts as allow for step 6",
   "-02 6.6, 10 step 6, App. E C-6",
   [ent(0, "MANDATE", {"mandate": mu, "signed_by": "pk-principal"}, 0), ent(1, "RECEIPT", rcpt("r0", act("purchase", amount=500), "defer", "ESCALATE_MONEY")),
    ent(2, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"}), ent(3, "CONSUME", {"receipt": "r0"}, 200)],
   {"result": "valid", "anchor": "none"}, cls="valid")
Vv("XV13", "Refused deferral (APPROVAL false + RELEASE refused) then CONSUME", "-02 6.6, 7.4 (c), 10 step 6",
   [ent(0, "MANDATE", {"mandate": mu, "signed_by": "pk-principal"}, 0), ent(1, "RECEIPT", rcpt("r0", act("purchase", amount=500), "defer", "ESCALATE_MONEY")),
    ent(2, "APPROVAL", {"receipt": "r0", "approved": False, "signed_by": "pk-principal"}), ent(3, "RELEASE", {"receipt": "r0", "cause": "refused"}),
    ent(4, "CONSUME", {"receipt": "r0"}, 200)], inv("CONSUME_INVALID", 4))
Vv("XV14", "A sale receipt has no reservation: an entry after its expires needs no RELEASE", "-02 7.3, 7.4 (only purchase reserves), 10 step 7(a)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("s0", act("sale", "buyer", amount=1000))),
    ent(2, "RECEIPT", rcpt("m0", dict(act("message", "buh@firma3.example"), t=1000)), 1000)], {"result": "valid", "anchor": "none"}, cls="valid")
Vv("XV15", "RELEASE (tool_not_executed) of a sale receipt: there is no active reservation", "-02 7.4 ('for a reservation that is not active ... RELEASE_INVALID')",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("s0", act("sale", "buyer", amount=1000))), ent(2, "RELEASE", {"receipt": "s0", "cause": "tool_not_executed"})],
   inv("RELEASE_INVALID", 2))
P2 = dict(act("purchase", amount=1000), t=110)
Vv("XV16", "Two reservations expire together: two consecutive RELEASE(expired), then the next RECEIPT", "-02 7.4 (one RELEASE per expired reservation, consecutive), 10 step 7(a)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RECEIPT", rcpt("r1", P2), 110),
    ent(3, "RELEASE", {"receipt": "r0", "cause": "expired"}, 1000), ent(4, "RELEASE", {"receipt": "r1", "cause": "expired"}, 1000),
    ent(5, "RECEIPT", rcpt("r2", dict(act("purchase", amount=1000), t=1000)), 1000)], {"result": "valid", "anchor": "none"}, cls="valid")
Vv("XV17", "After two expiries, the second reservation is released with cause tool_not_executed: another cause does not excuse the missing one",
   "-02 7.4 ('a RELEASE with any other cause does not excuse the missing ones'), 10 step 7(a)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RECEIPT", rcpt("r1", P2), 110),
    ent(3, "RELEASE", {"receipt": "r0", "cause": "expired"}, 1000), ent(4, "RELEASE", {"receipt": "r1", "cause": "tool_not_executed"}, 1000)],
   inv("RELEASE_MISSING", 4))
Vv("XV18", "RECEIPT allow without audience", "-02 7.1 ('audience ... REQUIRED in a RECEIPT body' except deny NO_MANDATE), 10 step 4",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("message", "buh@firma3.example"), audience=None))], inv("MALFORMED", 1))
Vv("XV19", "Logged deny NO_MANDATE without audience for an unknown mandate is valid", "-02 7.1 (audience REQUIRED except for a logged deny NO_MANDATE), 10 step 5",
   [ent(0, "MANDATE", MAND, 0), ent(1, "RECEIPT", rcpt("r0", act("message", "buh@firma3.example"), "deny", "NO_MANDATE", mandate="m9"))],
   {"result": "valid", "anchor": "none"}, cls="valid")
Vv("XV20", "CHECKPOINT entry whose seq equals its own seq", "-02 7.1 checkpoint-body ('seq < own seq'), 9.1 ('seq less than the entry's own seq'), 10 step 4",
   [ent(0, "MANDATE", MAND, 0), ent(1, "CHECKPOINT", {"seq": 1, "head": "h1", "root": "x"})], inv("MALFORMED", 1))
Vv("XV21", "Entry of a type outside the entry CDDL (CONSUME_ACK)", "-02 7.1 entry CDDL ('type': MANDATE / ... / CHECKPOINT), 10 step 4 -- code chosen by C, see AMBIGUITY-C2-5",
   [ent(0, "MANDATE", MAND, 0), ent(1, "CONSUME_ACK", {"receipt": "r0"})], inv("MALFORMED", 1))
Vv("XV22", "CEILING entry with window_s 0", "-02 6.3 ('window_s is an integer of at least 1'), 10 step 4 (CEILING_MALFORMED)",
   [ent(0, "MANDATE", MAND, 0), ent(1, "CEILING", {"id": "c1", "amount": 600, "currency": "USD", "window_s": 0, "signed_by": "pk-principal"})],
   inv("CEILING_MALFORMED", 1))

# --- byte-level mutations of spec vectors (no signing needed)
def load(c): return json.load(open(os.path.join(COSE, c + '.json')))
def B(id, src, title, basis, expected, mut, cls="invalid"):
    v = load(src); mut(v)
    v.update({"id": id, "class": cls, "title": title, "basis": basis + " (mutation of %s)" % src, "expected": expected})
    vecs.append((v, None))
rej = lambda r: {"result": "reject", "reason": r}
B("XC01", "C01", "Trailing byte after a valid COSE_Sign1", "5.1 (a) not well-formed: one item plus trailing data", rej("MALFORMED"),
  lambda v: v.__setitem__("cose_hex", v["cose_hex"] + "00"))
B("XC02", "C08", "Audience compared exactly: 'tool-a' is not 'tool-A'", "8.4 check 4", rej("AUDIENCE"), lambda v: v.__setitem__("tool_id", "tool-a"))
B("XC03", "C08", "Request members in another order hash the same (CDE sorts keys)", "5.7 (CDE of the map)", {"result": "accept"},
  lambda v: v.__setitem__("request", dict(reversed(list(v["request"].items())))), cls="valid")
B("XC04", "C08", "Request with t written 100.0 (float) does not hash to binding_request_hash", "5.2, 5.7", rej("REQUEST_MISMATCH"),
  lambda v: v["request"].__setitem__("t", 100.0))
B("XC05", "C08", "Inclusion path with an extra element", "9.1 (labels must equal the derived ones)", rej("INCLUSION_INVALID"),
  lambda v: v["proof"]["path"].append(["R", "00" * 32]))
B("XC06", "C08", "Inclusion proof with a checkpoint of another ledger (C25's)", "8.4 check 8 (path to the root of a witness-signed checkpoint covering it)",
  rej("INCLUSION_INVALID"), lambda v: v["proof"].__setitem__("checkpoint", load("C25")["proof"]["checkpoint"]))
B("XC07", "C08", "Inclusion path whose sibling is the raw entry hash instead of the RFC 9162 leaf hash", "9.1 (leaf = SHA-256(0x00 || entry hash))",
  rej("INCLUSION_INVALID"), lambda v: v["proof"]["path"].__setitem__(0, ["L", "f9f101028a87d249101155ec3860b7cd87b8a4eef74528eb3725b8ffb24079c6"]))
B("XC08", "C08", "Presented to the tool without any request", "8.4 check 5", rej("REQUEST_MISMATCH"), lambda v: v.__setitem__("request", None))
B("XC09", "C02", "ES256 AAR verified against a pinned set holding only an Ed25519 key: the kid is selected first", "-02 8.4 check 2 ('An AAR with an unknown kid is therefore KID_UNKNOWN whatever its alg'), App. E C-3",
  rej("KID_UNKNOWN"), lambda v: v.__setitem__("keys", load("C01")["keys"]))
B("XC10", "C15", "Honest ledger with its checkpoint, but entries 2 and 3 swapped", "10 step 3", {"result": "invalid", "reason": "CHAIN_BREAK", "at": 3},
  lambda v: v.__setitem__("ledger_hex", [v["ledger_hex"][0], v["ledger_hex"][1], v["ledger_hex"][3], v["ledger_hex"][2], v["ledger_hex"][4]]))
B("XC11", "C15", "Honest ledger, published checkpoint replaced by one of another ledger/witness (C39, other witness key)", "10 step 8 (signature checked first)",
  {"result": "invalid", "reason": "CHECKPOINT_SIG"}, lambda v: v.__setitem__("checkpoint_hex", load("C39")["checkpoint_hex"]))

# -02 byte-level additions
def C46_approval_is_receipt(v):
    v["proof"]["approval"] = {"entry": v["proof"]["entry"], "path": v["proof"]["path"]}
B("XC12", "C46", "Approved AAR whose 'approval' proof proves the RECEIPT entry instead of the APPROVAL entry", "-02 8.4 check 8 (the APPROVAL entry: its entry hash equals approved_by.digest ... INCLUSION_INVALID otherwise)",
  rej("INCLUSION_INVALID"), C46_approval_is_receipt)
def C46_flip_side(v):
    p = v["proof"]["approval"]["path"]; p[0] = ["R" if p[0][0] == "L" else "L", p[0][1]]
B("XC13", "C46", "Approved AAR whose APPROVAL path has a wrong side label", "-02 9.1 ('MUST reject (INCLUSION_INVALID) a path whose labels differ from the derived ones')",
  rej("INCLUSION_INVALID"), C46_flip_side)
c45 = load("C45")
def C46_deferral_then_approved(v):
    assert v["keys"] == c45["keys"] and v["tool_id"] == c45["tool_id"] and v["request"] == c45["request"]
    v["presentations"] = [{"cose_hex": c45["cose_hex"], "proof": c45["proof"]}, {}, {}]
B("XC14", "C46", "Deferral AAR (NOT_ALLOWED, not recorded), then the approved AAR (accepted once), then the approved AAR again (REPLAY)",
  "-02 8.4 check 6 ('The approved AAR ... has the same identity as the deferral AAR, which is NOT_ALLOWED and never accepted, so it is accepted once')",
  {"steps": [rej("NOT_ALLOWED"), {"result": "accept"}, rej("REPLAY")]}, C46_deferral_then_approved, cls="valid")
def C44_swap_proofs(v):
    v["presentations"] = [{"proof": v["presentations"][1]["proof"]}, {"cose_hex": v["presentations"][1]["cose_hex"], "proof": v["proof"]}]
B("XC15", "C44", "Two principals' r0: each AAR presented with the OTHER ledger's (valid) proof", "-02 8.4 check 8 ('a proof that names another entry than this AAR' is INCLUSION_INVALID), check 6 key (iss, chain.ledger, sub)",
  {"steps": [rej("INCLUSION_INVALID"), rej("INCLUSION_INVALID")]}, C44_swap_proofs)
c49 = load("C49")
def C60_with_C49_proof(v):
    assert v["keys"] == c49["keys"]
    v["proof"] = c49["proof"]
B("XC16", "C60", "Batch checkpoint: the second receipt presented with the first receipt's proof (same signed checkpoint)",
  "-02 9.1.1 (a batch shares one checkpoint, each entry has its own path), 8.4 check 8", rej("INCLUSION_INVALID"), C60_with_C49_proof)
def C48_no_approval_proof(v):
    del v["presented"][0]["proof"]["approval"]
B("XC17", "C48", "Ledger verifier: approved AAR reported accepted, proof without the APPROVAL entry", "-02 10 step 9 ('No proof: NO_INCLUSION'; for an approved AAR also the APPROVAL entry), 8.4 check 8 -- see AMBIGUITY-C2-8",
  {"result": "invalid", "reason": "NO_INCLUSION"}, C48_no_approval_proof)
def C48_approval_is_receipt(v):
    pr = v["presented"][0]["proof"]; pr["approval"] = {"entry": pr["entry"], "path": pr["path"]}
B("XC18", "C48", "Ledger verifier: approved AAR whose 'approval' proof proves the RECEIPT entry (valid proof of another entry)",
  "-02 10 step 9 ('a proof that verifies but whose entry is not this receipt (...; for an approved AAR also the APPROVAL entry): OFFLOG_RECEIPT')",
  {"result": "invalid", "reason": "OFFLOG_RECEIPT"}, C48_approval_is_receipt)

# =====================  -03 additions  =====================
import subprocess
FORGE = os.path.join(HERE, 'forge', 'forge')
SEED_C = "c3" * 32          # deterministic Ed25519 test key of implementation C (NOT a key of the spec vectors)
def forge(hexs, muts):
    out = subprocess.run([FORGE, "resign", hexs, SEED_C, muts], capture_output=True, text=True, check=True).stdout
    return json.loads(out)
def add_key(v, f):
    v["keys"] = dict(v["keys"]); v["keys"][f["kid"]] = {"alg": "EdDSA", "pub": f["pub"]}   # appended AFTER the witness key
KC = " Re-signed by C's test key, pinned as a second witness key after the original (the ledger id still derives from the first)."

# --- abstract verification: C2-11 (RECEIPT must record allow / defer+APPROVAL), C2-3, C2-4, C2-5, C2-10
MP = copy.deepcopy(M)
MANDP = {"mandate": MP, "signed_by": "pk-principal"}
DEN = rcpt("r0", act("message", "evil@zlo.example"), "deny", "RECIPIENT")
DEF = rcpt("r0", P1, "defer", "ESCALATE_MONEY")
mpe = copy.deepcopy(M); mpe["permissions"]["purchase"] = {"max_per_action": 25000}   # purchase without budget -> defer ESCALATE_MONEY
MANDE = {"mandate": mpe, "signed_by": "pk-principal"}
Vv("XV23", "Deny receipt reported accepted together with an (irrelevant) approval proof", "-03 10 step 9 ('whose RECEIPT entry does not record allow (it records deny ...): OFFLOG_RECEIPT'), 12.12",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", DEN)], {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": "r0"},
   checkpoint={"seq": 1, "head": "h1"}, presented=[{"id": "r0", "inclusion": {"seq": 1}, "approval": {"seq": 1}}])
Vv("XV24", "Defer receipt; the approval proof names the APPROVAL of ANOTHER deferral", "-03 10 step 9 ('OFFLOG_RECEIPT when one was given and does not fit'), App. A conv. 10",
   [ent(0, "MANDATE", MANDE, 0), ent(1, "RECEIPT", DEF), ent(2, "RECEIPT", rcpt("r1", P1, "defer", "ESCALATE_MONEY")),
    ent(3, "APPROVAL", {"receipt": "r1", "approved": True, "signed_by": "pk-principal"})],
   {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": "r0"},
   checkpoint={"seq": 3, "head": "h3"}, presented=[{"id": "r0", "inclusion": {"seq": 1}, "approval": {"seq": 3}}])
Vv("XV25", "Defer receipt; its APPROVAL exists but after the checkpoint of the proof",
   "-04 10 step 9 (b) ('validity: a proof that does not verify as a proof (... checkpoint seq below the entry) ... INCLUSION_INVALID'); was OFFLOG_RECEIPT under -03 -- the -04 order changes it, App. G does not list it, see AMBIGUITY-C4-2",
   [ent(0, "MANDATE", MANDE, 0), ent(1, "RECEIPT", DEF), ent(2, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"})],
   {"result": "invalid", "reason": "INCLUSION_INVALID", "receipt": "r0"},
   checkpoint={"seq": 1, "head": "h1"}, presented=[{"id": "r0", "inclusion": {"seq": 1}, "approval": {"seq": 2}}])
Vv("XV26", "Allow receipt presented with an approval member: the approval is not read", "-04 10 step 9 (d) ('for a RECEIPT entry that records allow an approval proof that is given is ignored'), C3-5",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1))], {"result": "valid", "anchor": "none"}, cls="valid",
   checkpoint={"seq": 1, "head": "h1"}, presented=[{"id": "r0", "inclusion": {"seq": 1}, "approval": {"seq": 0}}])
Vv("XV27", "Repeated RECEIPT id whose second entry would also fail recomputation: the duplicate is reported first", "-03 10 step 5 (first part: 'its id is not the id of an earlier RECEIPT ... DUPLICATE_RECEIPT_ID; its mandate is ...')",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RECEIPT", rcpt("r0", act("message", "evil@zlo.example")))],
   inv("DUPLICATE_RECEIPT_ID", 2))
Vv("XV28", "APPROVAL exactly at expires (t = receipt t + ttl) is unexpired", "-03 6.6, 10 step 4 ('has not expired at the entry's t'), 7.4 (expired = now > expires)",
   [ent(0, "MANDATE", MANDE, 0), ent(1, "RECEIPT", DEF), ent(2, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"}, t=400),
    ent(3, "CONSUME", {"receipt": "r0"}, t=400)], {"result": "valid", "anchor": "none"}, cls="valid")
Vv("XV29", "Second APPROVAL of an already decided deferral", "-03 6.6 ('that has not been decided before (no earlier APPROVAL for it)'), 10 step 4 (MANDATE_KEY)",
   [ent(0, "MANDATE", MANDE, 0), ent(1, "RECEIPT", DEF), ent(2, "APPROVAL", {"receipt": "r0", "approved": False, "signed_by": "pk-principal"}),
    ent(3, "RELEASE", {"receipt": "r0", "cause": "refused"}), ent(4, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"})],
   inv("MANDATE_KEY", 4))
Vv("XV30", "APPROVAL of an allow receipt", "-03 6.6, 10 step 4 ('not ... a defer RECEIPT': MANDATE_KEY)",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"})],
   inv("MANDATE_KEY", 2))
mpo = copy.deepcopy(M); mpo["principal"] = "pk-other"
Vv("XV31", "MANDATE whose principal is not the ledger's (signed by the pinned key)", "-03 6.1 consistency ('principal of every MANDATE MUST be the principal identifier ... in an abstract vector, the pinned principal key'), 10 step 4",
   [ent(0, "MANDATE", {"mandate": mpo, "signed_by": "pk-principal"}, 0)], inv("MANDATE_MALFORMED", 0))
Vv("XV32", "CEILING in EUR BEFORE the first MANDATE (USD)", "-04 5.2 ('A CEILING that comes before the first MANDATE ... CEILING_MALFORMED'), 6.3, 10 step 4 (C3-2; was valid under C's -03 reading)",
   [ent(0, "CEILING", {"id": "c1", "amount": 600, "currency": "EUR", "window_s": 86400, "signed_by": "pk-principal"}, 0), ent(1, "MANDATE", MANDP, 0)],
   inv("CEILING_MALFORMED", 0))
e33 = ent(1, "RECEIPT", rcpt("r0", P1)); del e33["t"]
Vv("XV33", "Entry without `t` (abstract)", "-03 7.1 'Shape of the entry' ('t is missing ... MALFORMED at that entry'), 10 step 4",
   [ent(0, "MANDATE", MANDP, 0), e33], inv("MALFORMED", 1))
mc = copy.deepcopy(M); mc["id"] = "m2"; mc["currency"] = "EUR"
Vv("XV34", "Second MANDATE in another currency with a valid mandate CDDL, before any receipt", "-03 5.2, 6.1 consistency, 10 step 4 (MANDATE_MALFORMED, before the signature check)",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "MANDATE", {"mandate": mc, "signed_by": "pk-attacker"}, 0)], inv("MANDATE_MALFORMED", 1))

Vv("XV35", "C3-1: a RECEIPT back-dated below earlier entries (would escape the budget window): CHAIN_BREAK at it",
   "-04 7.1 'Order of t' ('The t of an entry MUST NOT be less than the t of the entry before it ... CHAIN_BREAK at that entry'), 10 step 3, 12.13 (was valid under -03: the defect)",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", act("purchase", amount=25000, t=50000)), 50000),
    ent(2, "RECEIPT", rcpt("r1", act("purchase", amount=25000, t=50000)), 50000),
    ent(3, "RECEIPT", rcpt("r2", act("purchase", amount=25000, t=10)), 10)],
   inv("CHAIN_BREAK", 3))

mf = copy.deepcopy(M); mf["permissions"] = {"message": {"to": ["buh@firma3.example"]}}
Vv("XV36", "Deferred file action, mandate REVOKED, then the principal approves (and the tool consumes): MANDATE_KEY at the APPROVAL",
   "-04 6.6 ('and whose mandate has not been revoked'), 6.7, 10 step 4 (C3-9; was valid under -03)",
   [ent(0, "MANDATE", {"mandate": mf, "signed_by": "pk-principal"}, 0),
    ent(1, "RECEIPT", rcpt("r0", act("file", "buh@firma3.example"), "defer", "ESCALATE_FILE")),
    ent(2, "REVOCATION", {"mandate": "m1", "signed_by": "pk-principal"}, 150),
    ent(3, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"}, 200),
    ent(4, "CONSUME", {"receipt": "r0"}, 200)], inv("MANDATE_KEY", 3))

# --- sequence (-03)
S("XS14", "register_ceiling with the harness member `instance`", "-03 App. A conv. 6 ('and the harness members signed_by, instance')",
  [mop(), {"op": "register_ceiling", "id": "c1", "amount": 600, "currency": "USD", "window_s": 86400, "signed_by": "pk-principal", "instance": "w2"}],
  [{"result": "accept"}, {"result": "accept"}], cls="valid")
S("XS15", "register_mandate whose principal is not the pinned key", "-03 6.1 consistency (witness rejects with MANDATE_MALFORMED)",
  [mop(mpo)], [{"result": "reject", "reason": "MANDATE_MALFORMED"}])
S("XS16", "register_ceiling in EUR before any mandate, then a USD mandate", "-04 5.2, 6.3 ('one that comes before the first MANDATE, is CEILING_MALFORMED'), C3-2 (was accept under C's -03 reading)",
  [{"op": "register_ceiling", "id": "c1", "amount": 600, "currency": "EUR", "window_s": 86400, "signed_by": "pk-principal"}, mop()],
  [{"result": "reject", "reason": "CEILING_MALFORMED"}, {"result": "accept"}])

# --- byte-level (-03): forged decisions on every path (tool, verifier)
def C46_noapproved_with_approval(v):
    f = forge(v["cose_hex"], "noapproved"); add_key(v, f); v["cose_hex"] = f["hex"]
B("XC19", "C46", "Tool: approved AAR re-signed WITHOUT approved_by over the defer entry; the proof still carries a fitting approval",
  "-03 8.4 check 8 ('defer for an AAR without approved_by ... is INCLUSION_INVALID whatever the AAR says')." + KC, rej("INCLUSION_INVALID"), C46_noapproved_with_approval)
def C61_with_approval(v):
    v["proof"]["approval"] = {"entry": v["proof"]["entry"], "path": v["proof"]["path"]}
B("XC20", "C61", "Tool: forged allow over a deny entry, with an extra 'approval' member in the proof", "-03 8.4 check 8 ('A RECEIPT entry that records deny ... is INCLUSION_INVALID whatever the AAR says')",
  rej("INCLUSION_INVALID"), C61_with_approval)
def C48_noapproved_noproof(v):
    pr = v["presented"][0]; f = forge(pr["aar_hex"], "noapproved"); add_key(v, f); pr["aar_hex"] = f["hex"]; del pr["proof"]["approval"]
B("XC21", "C48", "Verifier: allow AAR without approved_by over a defer entry, reported accepted, no approval proof",
  "-03 10 step 9 ('records defer and no APPROVAL ... which is NO_INCLUSION when no approval proof was given'), 12.12." + KC,
  {"result": "invalid", "reason": "NO_INCLUSION"}, C48_noapproved_noproof)
def C48_noapproved_withproof(v):
    pr = v["presented"][0]; f = forge(pr["aar_hex"], "noapproved"); add_key(v, f); pr["aar_hex"] = f["hex"]
B("XC22", "C48", "Verifier: allow AAR without approved_by over a defer entry WITH a fitting approval proof",
  "-04 10 step 9 (d) ('or the AAR has no approved_by that names it: OFFLOG_RECEIPT ... the verifier mirrors Section 8.4 check 8'), 12.12, C3-4 (was valid under C's -03 reading)." + KC,
  {"result": "invalid", "reason": "OFFLOG_RECEIPT"}, C48_noapproved_withproof)
def C48_verdict(d):
    def m(v):
        pr = v["presented"][0]; f = forge(pr["aar_hex"], "verdict=" + d); add_key(v, f); pr["aar_hex"] = f["hex"]
    return m
B("XC23", "C48", "Verifier: honest ledger and proofs, but the AAR reported accepted says verdict deny",
  "-03 10 step 9 ('an AAR whose verdict is not allow is never an accepted receipt')." + KC,
  {"result": "invalid", "reason": "OFFLOG_RECEIPT"}, C48_verdict("deny"))
def C62_with_approval(v):
    pr = v["presented"][0]["proof"]; pr["approval"] = {"entry": pr["entry"], "path": pr["path"]}
B("XC24", "C62", "Verifier: forged allow over a deny entry, with an 'approval' proof that is the RECEIPT itself", "-03 10 step 9 (deny is never recorded as allow: OFFLOG_RECEIPT)",
  {"result": "invalid", "reason": "OFFLOG_RECEIPT"}, C62_with_approval)
c15 = load("C15")
def last_entry(muts):
    def m(v):
        f = forge(v["ledger_hex"][-1], muts); add_key(v, f); v["ledger_hex"][-1] = f["hex"]; v.pop("checkpoint_hex", None); v.pop("presented", None)
    return m
n15 = len(c15["ledger_hex"]) - 1
B("XC25", "C15", "Last entry without `prev`", "-03 7.1 'Shape of the entry' ('ledger, seq or prev is missing ... CHAIN_BREAK'), 10 step 3." + KC,
  {"result": "invalid", "reason": "CHAIN_BREAK", "at": n15}, last_entry("del=prev"))
B("XC26", "C15", "Last entry with `t` as a text string", "-03 7.1 'Shape of the entry' ('t is missing or not a non-negative integer ... MALFORMED'), 10 step 4." + KC,
  {"result": "invalid", "reason": "MALFORMED", "at": n15}, last_entry("text=t:100"))
B("XC27", "C15", "Last entry with `seq` as a text string", "-03 7.1 'Shape of the entry' ('seq ... of the wrong type is CHAIN_BREAK'), 10 step 3." + KC,
  {"result": "invalid", "reason": "CHAIN_BREAK"}, last_entry("text=seq:%d" % n15))


# =====================  -04 additions: order of the entry `t` (C3-1) on every path  =====================
B4 = "-04 7.1 'Order of t', 10 step 3, 12.13"
mb = copy.deepcopy(M)
Vv("XV37", "Back-dated APPROVAL (t below the entry before it, still before the deferral's expires): CHAIN_BREAK even when harmless",
   B4 + " ('whatever its type')",
   [ent(0, "MANDATE", MANDE, 0), ent(1, "RECEIPT", DEF), ent(2, "RECEIPT", rcpt("r1", act("message", "evil@zlo.example"), "deny", "RECIPIENT"), 350),
    ent(3, "APPROVAL", {"receipt": "r0", "approved": True, "signed_by": "pk-principal"}, 300)], inv("CHAIN_BREAK", 3))
Vv("XV38", "Back-dated CHECKPOINT entry", B4 + " ('whatever its type')",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1), 200), ent(2, "CHECKPOINT", {"seq": 1, "head": "h1", "root": "r1"}, 199)],
   inv("CHAIN_BREAK", 2))
Vv("XV39", "Entry with a negative `t` after t=100: not compared (MALFORMED at step 4), not CHAIN_BREAK",
   "-04 7.1 ('The comparison is made only between entries whose t is a non-negative integer'), 10 step 3, step 4",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1)), ent(2, "RECEIPT", rcpt("r1", act("message", "evil@zlo.example"), "deny", "RECIPIENT"), -1)],
   inv("MALFORMED", 2))
Vv("XV40", "Back-dated EUR CEILING: step 3 (CHAIN_BREAK) before step 4 (CEILING_MALFORMED)", B4 + ", 10 (steps 2-7 in numerical order)",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1), 500),
    ent(2, "CEILING", {"id": "c1", "amount": 600, "currency": "EUR", "window_s": 86400, "signed_by": "pk-principal"}, 400)],
   inv("CHAIN_BREAK", 2))
xv41 = [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1), 500), ent(2, "RECEIPT", rcpt("r1", act("message", "evil@zlo.example"), "deny", "RECIPIENT"), 400)]
xv41[2]["witness_sig_valid"] = False
Vv("XV41", "Back-dated entry whose witness signature is also bad: step 2 (WITNESS_SIG) before step 3", "-04 10 (steps 2-7 in numerical order), step 2, step 3",
   xv41, inv("WITNESS_SIG", 2))
Vv("XV42", "t goes down then up again: the first decrease is the failure", B4 + ", 10 ('The result is the FIRST failure found')",
   [ent(0, "MANDATE", MANDP, 0), ent(1, "RECEIPT", rcpt("r0", P1), 500), ent(2, "RECEIPT", rcpt("r1", act("message", "evil@zlo.example"), "deny", "RECIPIENT"), 499),
    ent(3, "CONSUME", {"receipt": "r0"}, 600)], inv("CHAIN_BREAK", 2))
Vv("XV43", "First entry with t greater than later equal entries is fine: t 7 7 7 (equal allowed)", B4 + " ('equal is allowed')",
   [ent(0, "MANDATE", MANDP, 7), ent(1, "RECEIPT", rcpt("r0", P1), 7), ent(2, "CONSUME", {"receipt": "r0"}, 7)],
   {"result": "valid", "anchor": "none"}, cls="valid")

S("XS17", "Witness: a request asserting t far in the past cannot back-date the entry (XV35 at the witness): third purchase is BUDGET",
  "-04 5.3 ('a member t inside an action map is requester-asserted ... NEVER used'), 7.1 ('A witness MUST NOT append such an entry'), App. A conv. 1 (clock reads AT LEAST action.t)",
  [mop(), auth("a0", act("purchase", amount=25000, t=50000)), auth("a1", act("purchase", amount=25000, t=50000)),
   auth("a2", act("purchase", amount=25000, t=10))],
  [{"result": "accept"}, {"verdict": "allow", "reason": "OK"}, {"verdict": "allow", "reason": "OK"}, {"verdict": "deny", "reason": "BUDGET"}])
S("XS18", "Witness: host clock steps back (clamped), the next decision is at the clamped time: deferral is NOT revived",
  "-04 5.3 (clamp), 7.1, 12.7",
  [mop(mu), auth("a0", act("purchase", amount=500)), {"op": "clock", "t": 1000}, {"op": "clock", "t": 200},
   {"op": "approve", "receipt": "a0", "signed_by": "pk-principal"}],
  [{"result": "accept"}, {"verdict": "defer", "reason": "ESCALATE_MONEY"}, {"result": "ok"}, {"result": "clamped"}, {"result": "reject", "reason": "NOT_DEFERRED"}])

def nth_entry(i, muts):
    def m(v):
        f = forge(v["ledger_hex"][i], muts); add_key(v, f); v["ledger_hex"][i] = f["hex"]; v.pop("checkpoint_hex", None); v.pop("presented", None)
    return m
B("XC28", "C15", "Last entry re-signed with t one second below the entry before it", B4 + "." + KC,
  {"result": "invalid", "reason": "CHAIN_BREAK", "at": n15}, last_entry("int=t:999"))
B("XC29", "C15", "Control: last entry re-signed with the SAME t (equal is allowed)", B4 + " ('equal is allowed')." + KC,
  {"result": "valid", "anchor": "none"}, last_entry("int=t:1000"), cls="valid")
B("XC30", "C15", "Last entry with a negative t (CBOR nint): not compared, MALFORMED", "-04 7.1 ('only between entries whose t is a non-negative integer'), 10 step 4." + KC,
  {"result": "invalid", "reason": "MALFORMED", "at": n15}, last_entry("int=t:-1"))
B("XC31", "C15", "Back-dated last entry whose `type` is also unknown: step 3 before step 4", B4 + ", 10 (steps in numerical order)." + KC,
  {"result": "invalid", "reason": "CHAIN_BREAK", "at": n15}, last_entry("int=t:999,text=type:BOGUS"))
B("XC32", "C15", "Back-dated RECEIPT in the middle (seq 2): CHAIN_BREAK at 2, before the prev-hash break it causes at 3", B4 + ", 10 ('the FIRST failure')." + KC,
  {"result": "invalid", "reason": "CHAIN_BREAK", "at": 2}, nth_entry(2, "int=t:999"))


# --- -04 interop findings (C's reading; the other honest reading is in the basis)
def flip0(path): path[0] = ["R" if path[0][0] == "L" else "L", path[0][1]]
def C78_bad_approval(v): flip0(v["presented"][0]["proof"]["approval"]["path"])
B("XC33", "C78", "Verifier: honest allow AAR, the extra approval proof (ignored by C3-5) has a wrong side label",
  "-04 10 step 9 (b) ('validity of every proof given ... INCLUSION_INVALID') vs (d) ('an approval proof that is given is ignored') -- C reads (b) first; the other reading gives valid. See AMBIGUITY-C4-1",
  {"result": "invalid", "reason": "INCLUSION_INVALID"}, C78_bad_approval)
def C08_bad_approval(v):
    v["proof"]["approval"] = {"entry": v["proof"]["entry"], "path": copy.deepcopy(v["proof"]["path"])}; flip0(v["proof"]["approval"]["path"])
B("XC34", "C08", "Tool: honest allow AAR, proof carries an extra approval proof that does not verify (wrong side label)",
  "-04 8.4 check 8 ('(b) validity of every proof given ... INCLUSION_INVALID' vs 'An approval proof given for a RECEIPT entry that records allow is ignored') -- C reads (b) first; the other reading accepts. See AMBIGUITY-C4-1",
  rej("INCLUSION_INVALID"), C08_bad_approval)
def C48_badsig_noapproval(v):
    pr = v["presented"][0]; h = pr["aar_hex"]; pr["aar_hex"] = h[:-2] + ("00" if h[-2:] != "00" else "01"); del pr["proof"]["approval"]
B("XC35", "C48", "Verifier: approved AAR whose signature does not verify, presented without the APPROVAL proof",
  "-04 10 step 9 (a) ('for an approved AAR (approved_by present), no proof of the APPROVAL entry: NO_INCLUSION') vs (b) ('a presented AAR that is not a well-formed COSE_Sign1 under a witness key ... INCLUSION_INVALID') -- C does not read approved_by from an AAR that does not verify; a reader that reads the unverified payload answers NO_INCLUSION. See AMBIGUITY-C4-3",
  {"result": "invalid", "reason": "INCLUSION_INVALID"}, C48_badsig_noapproval)

os.makedirs(OUT, exist_ok=True)
for v, raw in vecs:
    s = json.dumps(v, ensure_ascii=False, indent=1)
    if raw: s = s.replace(raw[0], raw[1])
    open(os.path.join(OUT, v["id"] + ".json"), "w").write(s + "\n")
print(len(vecs), "vectors written")
