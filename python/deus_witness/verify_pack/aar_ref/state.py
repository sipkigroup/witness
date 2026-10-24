"""Ledger state derived ONLY from entries (Section 7.2): no hidden process memory. (draft-deus-aar-02)
Time is integer seconds on the witness clock (the vectors use seconds)."""
from .decide import decide
from . import cose
from .checkpoint import merkle_root
from .schema import validate_allowance, validate_body, validate_ceiling, validate_mandate

DEFAULT_WINDOW = 86400


def request_map(action: dict) -> dict:
    """Section 5.7 / AMBIGUITY-28: the canonical request = the action map exactly as submitted (every member, including a
    requester-asserted `t`, which is opaque to validity checks: the witness uses its own clock)."""
    return dict(action)


def request_hash(action: dict) -> bytes:
    """binding_request_hash = SHA-256 over the Core Deterministic Encoding of the request map (-01 Section 5.7)."""
    import cbor2
    return cose.sha256(cbor2.dumps(request_map(action), canonical=True))


def params_hash(a: dict) -> bytes:
    """-02 Section 8.2 (minor): params_hash = SHA-256 over the CDE of {"data": action.data (absent = []), "amount": action.amount (absent = 0)}."""
    import cbor2
    return cose.sha256(cbor2.dumps({"data": a.get("data", []), "amount": a.get("amount", 0)}, canonical=True))


def mandate_hash(mandate: dict) -> bytes:
    """Hash of the mandate = SHA-256 of its CDE payload (not of the COSE bytes: ES256 signatures are not unique)."""
    import cbor2
    return cose.sha256(cbor2.dumps({k: v for k, v in mandate.items() if not k.startswith("_")}, canonical=True))


V = "deus-aar-0.1"


def ceiling_payload(principal, cid, amount, currency, window_s):
    """Principal-signed CEILING (typ application/aar-ceiling+cbor), -01 Section 6.3: the same map is the signed payload."""
    import cbor2
    return cbor2.dumps({"v": V, "id": cid, "principal": principal, "amount": amount, "currency": currency, "window_s": window_s}, canonical=True)


def approval_payload(mandate: dict, action: dict, rid: str, approved: bool = True):
    """Principal-signed approval (typ application/aar-approval+cbor), -01 Section 6.6: bound to the mandate hash, the action hash
    and the id of the deferred receipt (so it cannot be reused for a second, identical request)."""
    import cbor2
    return cbor2.dumps({"v": V, "t": "approval", "receipt": rid, "mandate": mandate_hash(mandate), "action": request_hash(action),
                        "approved": approved}, canonical=True)


def revocation_payload(mandate: dict):
    """Principal-signed revocation (typ application/aar-revocation+cbor), -01 Section 6.7."""
    import cbor2
    return cbor2.dumps({"v": V, "t": "revocation", "mandate": mandate_hash(mandate)}, canonical=True)


def allowance_payload(allowance: dict):
    """extension: the principal signs the allowance map itself (typ application/aar-allowance+cbor), as a MANDATE signs its map."""
    import cbor2
    return cbor2.dumps(allowance, canonical=True)


RELEASE_CAUSES = ("expired", "tool_not_executed", "refused", "revoked")


class State:
    def __init__(self):
        self.mandates = {}
        self.revoked = set()
        self.refused = set()
        self.ceiling = None
        self.ceiling_window = DEFAULT_WINDOW
        self.receipts = {}   # id -> dict(verdict, reason, action, mandate, used, expires, bhash)
        self.res = {}        # id -> dict(amount, mandate, created, expires, state)
        self.last_t = 0
        self.nseq = 0
        self.acts = []        # -05 (6.9, 7.3): (mandate, class, t) of every RECEIPT recorded with allow or defer
        self.currency = None  # -03 (C2-10): the currency of the ledger = the currency of its first MANDATE
        self.allowances = {}  # extension: id -> dict(mandate (id), commands, project, nbf, exp, ended, seq)

    # ---- derived views at time `now` ----
    def _eff(self, r, now):
        if r["state"] == "active" and now > r["expires"]:
            return "released"
        return r["state"]

    def committed(self, now, mid=None, window=DEFAULT_WINDOW, before_seq=None):
        return sum(r["amount"] for r in self.res.values()
                   if self._eff(r, now) in ("active", "consumed")
                   and (before_seq is None or r["seq"] < before_seq)
                   and (mid is None or r["mandate"] == mid)
                   and r["created"] > now - window)

    def count(self, now, mid, cls, window=DEFAULT_WINDOW):
        """-05 Section 7.3: count(M, c, t) = RECEIPT entries of mandate M and class c recorded with allow or defer, t in (t - window, t]."""
        return sum(1 for (m, c, t) in self.acts if m == mid and c == cls and now - window < t <= now)

    def decide_for(self, mid, action, now):
        M = self.mandates.get(mid)
        a = request_map(action)
        window = M.get("budget_window_s", DEFAULT_WINDOW) if M else DEFAULT_WINDOW
        st = {"mandate_committed": self.committed(now, mid, window),
              "principal_committed": self.committed(now, None, self.ceiling_window),
              "ceiling": self.ceiling,
              "counts": {action.get("class"): self.count(now, mid, action.get("class"), window)},
              "allowances": {k: g for k, g in self.allowances.items() if g["mandate"] == mid and not g["ended"]}}
        v, why = decide(dict(M, _sig_valid=True, _revoked=mid in self.revoked) if M else None, a, st, now)
        return a, v, why

    def check_present(self, rid, now, audience_ok=True, bhash=None):
        """Section 8.4 checks 1,3,4,5,6,7,8 in the order of the reference model. -> None or reason."""
        if rid is None:
            return "NO_RECEIPT"
        rc = self.receipts.get(rid)
        if rc is None:
            return "NO_RECEIPT"
        if rc["verdict"] != "allow":
            return "NOT_ALLOWED"
        if not audience_ok:
            return "AUDIENCE"
        if bhash is not None and bhash != rc["bhash"]:
            return "REQUEST_MISMATCH"
        if rc["used"]:
            return "REPLAY"
        if now > rc["expires"]:
            return "RECEIPT_EXPIRED"
        r = self.res.get(rid)
        if r is not None and self._eff(r, now) != "active":
            return "RESERVATION_INACTIVE"
        return None

    # ---- entry application (pure function of the entry) ----
    def apply(self, typ, body, t):
        self.nseq += 1
        self.last_t = max(self.last_t, t)
        if typ == "MANDATE":
            self.mandates[body["mandate"]["id"]] = dict(body["mandate"])
            if self.currency is None:
                self.currency = body["mandate"].get("currency")
        elif typ == "CEILING":
            self.ceiling = body["amount"]
            self.ceiling_window = body["window_s"]        # -02 (C-2): window_s is REQUIRED, there is no default
        elif typ == "RECEIPT":
            a = body["action"]
            ttl = body["ttl"]
            self.receipts[body["id"]] = {"verdict": body["verdict"], "reason": body.get("reason"), "action": a,
                                         "mandate": body["mandate"], "used": False, "expires": t + ttl,
                                         "audience": body.get("audience"),
                                         "bhash": request_hash(a)}
            if body["verdict"] in ("allow", "defer"):
                self.acts.append((body["mandate"], a.get("class"), t))
            if a["class"] == "purchase" and body["verdict"] in ("allow", "defer"):
                self.res[body["id"]] = {"amount": a["amount"], "mandate": body["mandate"], "created": t,
                                        "expires": t + ttl, "state": "active", "seq": self.nseq - 1}
        elif typ == "APPROVAL":
            if body.get("approved", True):
                self.receipts[body["receipt"]]["verdict"] = "allow"
            else:
                self.refused.add(body["receipt"])
        elif typ == "REVOCATION":
            self.revoked.add(body["mandate"])
        elif typ == "ALLOWANCE":
            g = body["allowance"]
            self.allowances[g["id"]] = {"mandate": body["mandate"], "commands": tuple(g["commands"]), "project": g["project"],
                                        "nbf": g["nbf"], "exp": g["exp"], "ended": False, "seq": self.nseq - 1}
        elif typ == "ALLOWANCE_END":
            self.allowances[body["allowance"]]["ended"] = True
        elif typ == "CONSUME":
            self.receipts[body["receipt"]]["used"] = True
            r = self.res.get(body["receipt"])
            if r is not None:
                r["state"] = "consumed"
        elif typ == "RELEASE":
            r = self.res.get(body["receipt"])
            if r is not None:
                r["state"] = "released"
            if body.get("cause") == "tool_not_executed":
                self.receipts[body["receipt"]]["used"] = True
        # CHECKPOINT: no budget effect here


def _root(hs):
    """Merkle root over entry hashes; abstract vectors (string hashes): lower-case hex of the root over their UTF-8 bytes (-05 Appendix A, convention 12)."""
    if hs and all(isinstance(h, str) for h in hs):
        return merkle_root([h.encode() for h in hs]).hex()
    return merkle_root(hs)


PROMISE_MAX_MMD = 3600


def check_promise(p, entries, witness_key, anchored, now, lid=None):
    """-05 Section 9.5 / 10 step 11 (abstract form). -> 'kept' | 'pending' | 'PROMISE_SIG' | 'PROMISE_MALFORMED' | 'PROMISE_LATE' | 'PROMISE_BROKEN'."""
    if not isinstance(p, dict) or p.get("signed_by") != witness_key:
        return "PROMISE_SIG"
    u = lambda x: isinstance(x, int) and not isinstance(x, bool) and x >= 0
    if (p.get("v") != "deus-aar-0.1" or p.get("t") != "promise" or not u(p.get("seq")) or not u(p.get("entry_t")) or not u(p.get("mmd"))
            or p["mmd"] > PROMISE_MAX_MMD or not isinstance(p.get("entry"), (bytes, str))
            or (lid is not None and p.get("ledger", lid) != lid)):
        return "PROMISE_MALFORMED"
    s, deadline = p["seq"], p["entry_t"] + p["mmd"]
    # anchored checkpoints of the audited ledger (CHECKPOINT entries named in `anchored`; step 8 has checked their head and root) that cover seq
    cover = [entries[i] for i in sorted(set(anchored or [])) if 0 <= i < len(entries) and entries[i]["type"] == "CHECKPOINT"
             and entries[i]["body"]["seq"] >= s]
    have = s < len(entries)
    same = have and entries[s]["hash"] == p["entry"] and entries[s].get("t") == p["entry_t"]
    if have and not same:
        return "PROMISE_BROKEN"          # two witness-signed statements about one position: the promise and the entry at seq
    if not have:
        return "PROMISE_BROKEN" if (cover or now > deadline) else "pending"
    if any(c["t"] <= deadline for c in cover):
        return "kept"
    if cover or now > deadline:
        return "PROMISE_LATE"
    return "pending"


def verify_entries(entries, witness_key, operator_keys, principal_ok, checkpoint=None, presented=None, lid=None, principal=None,
                   promises=None, anchored=None, now=None):
    """Section 10 core. entries: list of dict(seq,type,body,prev,hash,t?,witness_sig_valid?,ledger?).
    principal_ok(type, body, S) -> bool (principal signature under the PINNED key; S = state reconstructed so far).
    Order (-01 Section 10): step 1, then entry by entry in ledger order applying steps 2-7 in numerical order; the first failure
    is returned with at = the entry's seq. Whole-ledger checks (checkpoint, presented receipts) come last."""
    if witness_key in operator_keys:
        return {"result": "invalid", "reason": "WITNESS_NOT_INDEPENDENT"}
    prev, S = None, State()
    heads, tprev = {}, 0
    for i, e in enumerate(entries):
        at = e["seq"]
        if not e.get("witness_sig_valid", True):                                              # step 2
            return {"result": "invalid", "reason": "WITNESS_SIG", "at": at}
        if e.get("chain_bad") or e["prev"] != prev or e["seq"] != i or (lid is not None and e.get("ledger", lid) != lid):   # step 3
            return {"result": "invalid", "reason": "CHAIN_BREAK", "at": at}
        # -04 (C3-1): the `t` of an entry is not less than the `t` of the entry before it (the witness clock is monotonic, Section 5.3). An entry whose own `t`
        # is missing or not a non-negative integer is MALFORMED at step 4 (C3-7); the order is then not compared and 7(a) is not evaluated for it.
        t_raw = e.get("t")
        t_ok = isinstance(t_raw, int) and not isinstance(t_raw, bool) and t_raw >= 0 and not e.get("t_bad")
        if t_ok and t_raw < tprev:
            return {"result": "invalid", "reason": "CHAIN_BREAK", "at": at}
        prev = e["hash"]
        heads[e["seq"]] = e["hash"]
        typ, body, t = e["type"], e["body"], (t_raw if t_ok else 0)
        if t_ok:
            tprev = t_raw
        # step 7(a) (-02, C-4/C-5): RELEASE_MISSING depends only on the state before this entry and on its `t`; it is evaluated here, before steps 4-6.
        # The only entry that may follow an expired active reservation is a RELEASE with cause `expired` (the witness appends one per expired reservation).
        if t_ok and not (typ == "RELEASE" and isinstance(body, dict) and body.get("cause") == "expired"):
            for rid, r in S.res.items():
                if r["state"] == "active" and t > r["expires"]:
                    return {"result": "invalid", "reason": "RELEASE_MISSING", "at": at}
        if e.get("shape_bad") or not t_ok:                                                                 # step 4 (-03, C2-5): the entry payload does not match the `entry` CDDL
            return {"result": "invalid", "reason": "MALFORMED", "at": at}
        if typ == "CEILING" and validate_ceiling(body):                                       # step 4 (-02, C-2)
            return {"result": "invalid", "reason": "CEILING_MALFORMED", "at": at}
        if validate_body(typ, body, at):                                                       # step 4 (-02, C-14/C-18/C-19): CDDL of the entry body
            return {"result": "invalid", "reason": "MALFORMED", "at": at}
        if typ == "MANDATE" and validate_mandate(body.get("mandate")):                         # step 4: CDDL of Section 6.1
            return {"result": "invalid", "reason": "MANDATE_MALFORMED", "at": at}
        if typ == "MANDATE" and ((principal is not None and body["mandate"].get("principal") != principal)         # step 4 (-03, C2-10)
                                 or (S.currency is not None and body["mandate"].get("currency") != S.currency)):
            return {"result": "invalid", "reason": "MANDATE_MALFORMED", "at": at}
        if typ == "CEILING" and (S.currency is None or body.get("currency") != S.currency):      # -04 (C3-2): a CEILING before the first MANDATE has no currency to match
            return {"result": "invalid", "reason": "CEILING_MALFORMED", "at": at}
        if typ == "ALLOWANCE":                                                                 # extension: a new id, for a live mandate, bound to its hash
            M = S.mandates.get(body["mandate"])
            if body["allowance"]["id"] in S.allowances or M is None or body["mandate"] in S.revoked \
                    or body["allowance"]["mandate"] != mandate_hash(M):
                return {"result": "invalid", "reason": "MALFORMED", "at": at}
        if typ == "ALLOWANCE_END":                                                             # extension: ends a recorded allowance, once
            g = S.allowances.get(body["allowance"])
            if g is None or g["ended"]:
                return {"result": "invalid", "reason": "MALFORMED", "at": at}
        if typ in ("MANDATE", "CEILING", "APPROVAL", "REVOCATION", "ALLOWANCE"):               # step 4 (extension: and ALLOWANCE; an ALLOWANCE_END only narrows, the witness records it)
            if not principal_ok(typ, body, S):
                return {"result": "invalid", "reason": "MANDATE_KEY", "at": at}
        if typ == "APPROVAL":                                                                  # step 4 (-03, C2-4): an undecided, unexpired deferral at the entry's `t`
            rc = S.receipts.get(body["receipt"])
            if rc is None or rc["verdict"] != "defer" or body["receipt"] in S.refused or t > rc["expires"] or rc["mandate"] in S.revoked:     # -04 (C3-9): and its mandate is not revoked
                return {"result": "invalid", "reason": "MANDATE_KEY", "at": at}
        if typ == "RECEIPT":                                                                   # step 5
            if body["id"] in S.receipts:                                                       # (-03, C2-3) an id used by an earlier RECEIPT
                return {"result": "invalid", "reason": "DUPLICATE_RECEIPT_ID", "at": at}
            if body["mandate"] not in S.mandates and not (body["verdict"] == "deny" and body.get("reason") == "NO_MANDATE"):
                return {"result": "invalid", "reason": "MANDATE_UNKNOWN", "at": at}
            _, v, why = S.decide_for(body["mandate"], body["action"], t)
            if v is not None and (v != body["verdict"] or ("reason" in body and why != body["reason"])):
                return {"result": "invalid", "reason": "VERDICT_NOT_REPRODUCIBLE", "at": at}
        elif typ == "CONSUME":                                                                 # step 6
            if S.check_present(body["receipt"], t) is not None:
                return {"result": "invalid", "reason": "CONSUME_INVALID", "at": at}
        # step 7(b) (Section 7.4): the RELEASE itself must be legal
        if typ == "RELEASE":
            r = S.res.get(body.get("receipt"))
            c = body.get("cause")
            bad = c not in RELEASE_CAUSES or r is None or r["state"] != "active"
            bad = bad or (c == "expired" and not t > r["expires"])
            bad = bad or (c == "revoked" and r["mandate"] not in S.revoked)
            bad = bad or (c == "refused" and body.get("receipt") not in S.refused)
            if bad:
                return {"result": "invalid", "reason": "RELEASE_INVALID", "at": at}
        S.apply(typ, body, t)
    cp = checkpoint
    # step 8 (-02, C-18): every CHECKPOINT entry is checked like a published checkpoint: head = hash of the entry at body.seq, root = Merkle root over 0..seq
    hs = [e["hash"] for e in entries]
    for e in entries:
        if e["type"] == "CHECKPOINT":
            b = e["body"]
            if not (b["seq"] < e["seq"]) or b["head"] != hs[b["seq"]]:
                return {"result": "invalid", "reason": "CHECKPOINT_HEAD"}
            if b["root"] != _root(hs[:b["seq"] + 1]):
                return {"result": "invalid", "reason": "CHECKPOINT_ROOT"}
    if cp is not None:
        want = heads.get(cp["seq"]) if "seq" in cp else prev
        if cp["head"] != want:
            return {"result": "invalid", "reason": "CHECKPOINT_HEAD"}
        if cp.get("root") is not None:                       # signed checkpoints commit to the Merkle root of entry hashes 0..seq
            n = (cp["seq"] if "seq" in cp else len(entries) - 1) + 1
            if merkle_root([x["hash"] for x in entries[:n]]) != cp["root"]:
                return {"result": "invalid", "reason": "CHECKPOINT_ROOT"}
        if cp.get("ots_digest") is not None and cp["ots_digest"] != cp["head"]:
            return {"result": "invalid", "reason": "ANCHOR_MISMATCH"}
    # step 9 (Section 8.4(8)/12.6; -02, C-12): every receipt a tool reports as accepted must be included in the ledger under the checkpoint.
    # NO_INCLUSION: no proof. OFFLOG_RECEIPT: a proof exists but the entry/checkpoint it names is not (this receipt in) the audited ledger.
    # (INCLUSION_INVALID is for a proof that does not verify as such; abstract vectors have no cryptographic proof to break.)
    cpseq = (cp["seq"] if cp is not None and "seq" in cp else len(entries) - 1)
    for p in presented or []:
        inc = p.get("inclusion")
        if inc is None:
            return {"result": "invalid", "reason": "NO_INCLUSION", "receipt": p["id"]}
        s = inc.get("seq")
        ok = (cp is not None and isinstance(s, int) and 0 <= s <= cpseq and s < len(entries)
              and entries[s]["type"] == "RECEIPT" and entries[s]["body"].get("id") == p["id"])
        if not ok:
            return {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": p["id"]}
        # -03 (C2-11): the RECEIPT entry must RECORD allow, or defer followed by the approving APPROVAL entry (carried as `approval: {seq}`)
        vd = entries[s]["body"].get("verdict")
        if vd == "defer":
            ap = p.get("approval")
            if ap is None:
                return {"result": "invalid", "reason": "NO_INCLUSION", "receipt": p["id"]}
            sa = ap.get("seq")
            if not (isinstance(sa, int) and s < sa <= cpseq and sa < len(entries) and entries[sa]["type"] == "APPROVAL"
                    and entries[sa]["body"].get("receipt") == p["id"] and entries[sa]["body"].get("approved") is True):
                return {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": p["id"]}
        elif vd != "allow":
            return {"result": "invalid", "reason": "OFFLOG_RECEIPT", "receipt": p["id"]}
    # step 11 (-05 Section 9.5): inclusion promises. A promise that is not the witness's (PROMISE_SIG) or not conforming (PROMISE_MALFORMED)
    # is not evidence and does not change the result; a valid promise that is late or broken makes the ledger invalid.
    outs = []
    for i, p in enumerate(promises or []):
        o = check_promise(p, entries, witness_key, anchored, now if now is not None else 0, lid)
        if o in ("PROMISE_BROKEN", "PROMISE_LATE"):
            return {"result": "invalid", "reason": o, "promise": i}
        outs.append(o)
    res = {"result": "valid", "anchor": cp["ots_status"] if cp is not None and cp.get("ots_status") in ("pending", "bitcoin") else "none"}
    if promises is not None:
        res["promises"] = outs
    return res
