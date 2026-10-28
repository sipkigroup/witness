"""Third-party verifier (Section 10) for a ledger file. Needs only: the file, witness public key(s), operator key ids,
the pinned registry, and optionally a (signed) checkpoint. It re-evaluates every RECEIPT with the Section 6.4 algorithm,
re-verifies principal signatures on MANDATE, CEILING and APPROVAL, requires explicit RELEASE on expiry, and (optionally)
checks that receipts reported by tools are included in the ledger under the checkpoint."""
import cbor2

from . import cose
from .aar import check_inclusion
from .checkpoint import merkle_root
from .cose import sha256
from .state import allowance_payload, approval_payload, ceiling_payload, revocation_payload, verify_entries


ENTRY_TYPES = ("MANDATE", "CEILING", "REVOCATION", "RECEIPT", "APPROVAL", "CONSUME", "RELEASE", "REFUND", "CHECKPOINT",
               "ALLOWANCE", "ALLOWANCE_END")          # extension (0.2.10)
ENTRY_KEYS = {"ledger", "seq", "prev", "t", "type", "body"}


def load_entries(path, witness_keys):
    entries, raw_all = [], []
    with open(path, "rb") as f:
        data = f.read()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for line in lines:
        raw = bytes.fromhex(line.decode())
        ok = True
        try:
            payload, _ = cose.verify1(raw, witness_keys, cose.TYP_ENTRY)
            e = cose.loads(payload)
        except cose.CoseError:
            ok = False
            try:
                e = cose.loads(cose.parse1(raw)[2])
                assert isinstance(e, dict)
            except Exception:  # noqa
                e = {"seq": len(entries), "type": "?", "body": {}, "t": 0, "prev": entries[-1]["hash"] if entries else None}
        # -03 (C2-5): the payload must match the `entry` CDDL (Section 7.1). ledger/seq/prev wrong or missing: CHAIN_BREAK (step 3);
        # t, type, body or an extra member: MALFORMED (step 4).
        chain_bad = not (isinstance(e.get("ledger"), bytes) and isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool)
                         and (e.get("prev") is None or isinstance(e.get("prev"), bytes)) and "prev" in e)
        shape_bad = (not isinstance(e.get("t"), int) or isinstance(e.get("t"), bool) or e.get("t", -1) < 0 or e.get("type") not in ENTRY_TYPES
                     or "body" not in e or bool(set(e) - ENTRY_KEYS))
        t_ok = isinstance(e.get("t"), int) and not isinstance(e.get("t"), bool) and e.get("t") >= 0
        # -04 (C3-8): `at` of an entry whose `seq` is not a readable integer is its index in the presented ledger
        entries.append({"seq": e.get("seq", len(entries)) if isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool) else len(entries), "type": e.get("type"), "body": e.get("body"),
                        "t": e.get("t") if t_ok else 0, "t_bad": not t_ok, "prev": e.get("prev"), "ledger": e.get("ledger"),
                        "hash": sha256(raw), "witness_sig_valid": ok, "chain_bad": chain_bad, "shape_bad": shape_bad and not chain_bad})
    return entries


def verify_file(path, witness_keys, operator_kids, registry, principal, checkpoint=None, require_cose=False, presented=None):
    """checkpoint: None | dict(seq, head[, root]) (unauthenticated, legacy) | COSE_Sign1 bytes signed by the witness.
    presented: list of dict(aar=COSE bytes, proof=dict|None) reported by tools as accepted."""
    entries = load_entries(path, witness_keys)
    if entries is None:
        return {"result": "invalid", "reason": "MALFORMED"}
    wk = witness_keys[0].kid
    cp_sig_bad = False
    if isinstance(checkpoint, (bytes, bytearray)):
        try:
            checkpoint = cose.loads(cose.verify1(bytes(checkpoint), witness_keys, cose.TYP_CHECKPOINT)[0])
        except cose.CoseError:
            checkpoint, cp_sig_bad = None, True          # reported after the entries are checked (entry-major order, Section 10)

    def principal_ok(typ, body, S):
        c = body.get("cose")
        if c is None:                                       # symbolic signer (abstract mode only)
            return (not require_cose) and registry.check(principal, body.get("signed_by")) is None
        try:
            if typ == "MANDATE":
                m = body["mandate"]
                return registry.check(m["principal"], None, c, cbor2.dumps(m, canonical=True), cose.TYP_MANDATE) is None
            if typ == "CEILING":
                want = ceiling_payload(principal, body["id"], body["amount"], body["currency"], body["window_s"])
                return registry.check(principal, None, c, want, cose.TYP_CEILING) is None
            if typ == "APPROVAL":
                rc = S.receipts[body["receipt"]]
                want = approval_payload(S.mandates[rc["mandate"]], rc["action"], body["receipt"], body.get("approved", True), body.get("view"))
                return registry.check(principal, None, c, want, cose.TYP_APPROVAL) is None
            if typ == "REVOCATION":
                return registry.check(principal, None, c, revocation_payload(S.mandates[body["mandate"]]), cose.TYP_REVOCATION) is None
            if typ == "ALLOWANCE":
                return registry.check(principal, None, c, allowance_payload(body["allowance"]), cose.TYP_ALLOWANCE) is None
        except (KeyError, TypeError):
            return False
        return False

    lid = sha256(b"deus-aar/ledger/" + principal.encode() + wk)
    r = verify_entries(entries, wk, set(operator_kids), principal_ok, checkpoint, lid=lid, principal=principal)
    if cp_sig_bad and r["result"] == "valid":
        return {"result": "invalid", "reason": "CHECKPOINT_SIG"}
    if r["result"] != "valid" or not presented:
        return r
    # concrete inclusion of tool-reported receipts: proof must match THIS ledger, not a fork
    cpseq = checkpoint["seq"] if checkpoint is not None and "seq" in checkpoint else len(entries) - 1
    for p in presented:
        why, cp = check_inclusion(p["aar"], witness_keys, p.get("proof"))
        if why == "MISMATCH":                                      # -02 (C-12): a proof that verifies but names another receipt
            # -04 (C3-3): a RECEIPT entry that records defer with no approval proof given is NO_INCLUSION (presence before the recorded decision)
            try:
                rec = cose.loads(cose.verify1(p["proof"]["entry"], witness_keys, cose.TYP_ENTRY)[0])["body"].get("verdict")
            except Exception:  # noqa
                rec = None
            if rec == "defer" and not (p["proof"].get("approval") and p["proof"]["approval"].get("entry")):
                return {"result": "invalid", "reason": "NO_INCLUSION"}
            return {"result": "invalid", "reason": "OFFLOG_RECEIPT"}
        if why:
            return {"result": "invalid", "reason": why.split(":")[0]}
        s = cose.loads(cose.verify1(p["proof"]["entry"], witness_keys, cose.TYP_ENTRY)[0])["seq"]
        ap = p["proof"].get("approval")
        sa = cose.loads(cose.verify1(ap["entry"], witness_keys, cose.TYP_ENTRY)[0])["seq"] if ap else None
        if (s >= len(entries) or entries[s]["hash"] != sha256(p["proof"]["entry"]) or cp["seq"] >= len(entries)
                or cp["root"] != merkle_root([x["hash"] for x in entries[:cp["seq"] + 1]])
                or (ap and (sa >= len(entries) or entries[sa]["hash"] != sha256(ap["entry"])))):
            return {"result": "invalid", "reason": "OFFLOG_RECEIPT"}
    return r


def check_promise_cose(promise_bytes, entries, witness_keys, anchored, now, lid=None):
    """-05 Section 9.5 / 10 step 11 for a byte-level promise (COSE_Sign1, typ application/aar-inclusion-promise+cbor).
    entries: as returned by load_entries; anchored: seqs of CHECKPOINT entries whose anchor verified (Section 9.2)."""
    from .state import check_promise
    try:
        p = cose.loads(cose.verify1(bytes(promise_bytes), witness_keys, cose.TYP_PROMISE)[0])
    except cose.CoseError:
        return "PROMISE_SIG"
    if not isinstance(p, dict):
        return "PROMISE_MALFORMED"
    if set(p) - {"v", "t", "ledger", "seq", "entry", "entry_t", "mmd"} or not isinstance(p.get("ledger"), bytes):
        return "PROMISE_MALFORMED"
    return check_promise(dict(p, signed_by="<witness>"), entries, "<witness>", anchored, now, lid if lid is not None else (entries[0]["ledger"] if entries else p["ledger"]))   # ERRATA-05: the AUDITED ledger, not the one the promise names
