"""Tool-side acceptance of an AAR (draft-deus-aar-02 Section 8.4). Checks 1-8 are stateless except 6 (replay store, keyed by the
CWT claims (iss, chain.ledger, sub), NEVER by the COSE bytes); check 9 (reservation active) is made by the witness when it appends CONSUME."""
from . import cose
from .checkpoint import verify_inclusion
from .cose import sha256
from .state import request_hash


def check_inclusion(aar_bytes, witness_keys, proof):
    """Section 8.4(8) (-02): the AAR must be a RECEIPT entry included in a witness-signed checkpoint.
    proof = {"entry": COSE bytes of the RECEIPT entry, "path": [(side, hash)], "checkpoint": COSE bytes[, "approval": {"entry", "path"}]}.
    -> (None, checkpoint) if ok, else (code, None) with code in
       NO_INCLUSION          no proof (or, for an AAR with approved_by, no approval proof);
       INCLUSION_INVALID     the proof does not verify as a proof (bad signature/encoding, path or side labels, checkpoint not covering the entry);
       MISMATCH              the proof verifies but names another entry than this AAR (id, ledger, seq, hash, request, verdict): a tool answers
                             INCLUSION_INVALID, a third-party verifier OFFLOG_RECEIPT (-02, C-12)."""
    if not proof or not proof.get("entry") or not proof.get("checkpoint"):
        return "NO_INCLUSION", None
    try:
        aar = cose.loads(cose.verify1(aar_bytes, witness_keys, cose.TYP_AAR)[0])          # an AAR that does not verify: INCLUSION_INVALID (-04, C3-6)
        prot = cose.parse1(aar_bytes)[0]
        rid = prot[cose.H_CWT][cose.CWT_SUB]
        ch = aar["chain"]
        approved = aar["mandate"].get("approved_by")
        ap = proof.get("approval")
        # -04 (C3-3) order of faults: (a) presence, (b) validity of every proof given, (c) identity, (d) the decision the entry RECORDS, (e) the verdict of the AAR.
        if approved is not None and not (ap and ap.get("entry")):          # (a) an approved AAR needs the proof of the APPROVAL entry too
            return "NO_INCLUSION", None
        e = cose.loads(cose.verify1(proof["entry"], witness_keys, cose.TYP_ENTRY)[0])
        cp = cose.loads(cose.verify1(proof["checkpoint"], witness_keys, cose.TYP_CHECKPOINT)[0])
        if cp["ledger"] != ch["ledger"] or cp["seq"] < e["seq"]:           # (b)
            return "INCLUSION_INVALID", None
        if not verify_inclusion(sha256(proof["entry"]), [tuple(p) for p in proof["path"]], cp["root"], e["seq"], cp["seq"] + 1):
            return "INCLUSION_INVALID", None
        ea = None
        if ap and ap.get("entry"):
            ea = cose.loads(cose.verify1(ap["entry"], witness_keys, cose.TYP_ENTRY)[0])
            if ea["ledger"] != ch["ledger"] or cp["seq"] < ea["seq"]:
                return "INCLUSION_INVALID", None
            if not verify_inclusion(sha256(ap["entry"]), [tuple(p) for p in ap["path"]], cp["root"], ea["seq"], cp["seq"] + 1):
                return "INCLUSION_INVALID", None
        if not (e["type"] == "RECEIPT" and e["body"]["id"] == rid and e["seq"] == ch["seq"] and e["ledger"] == ch["ledger"]          # (c)
                and sha256(proof["entry"]) == ch["entry"]
                and request_hash(e["body"]["action"]) == aar["action"]["binding_request_hash"]):
            return "MISMATCH", None
        if approved is not None and not (ea["type"] == "APPROVAL" and ea["body"].get("receipt") == rid and sha256(ap["entry"]) == approved["digest"] and ea["seq"] > e["seq"]):
            return "MISMATCH", None
        # (d) the RECEIPT entry records allow (no approval needed: an approval proof for it is ignored, C3-5), or defer + the approving APPROVAL entry named by the AAR
        recorded = e["body"]["verdict"]
        if recorded == "allow":
            if approved is not None:
                return "MISMATCH", None
        elif recorded == "defer":
            if approved is None or ea is None or ea["body"].get("approved") is not True:
                return "MISMATCH", None
        else:
            return "MISMATCH", None
        if aar["verdict"]["decision"] != "allow":                          # (e)
            return "MISMATCH", None
    except (cose.CoseError, KeyError, TypeError, ValueError) as ex:
        return "INCLUSION_INVALID", None
    return None, cp


class Tool:
    """A tool with a replay store. accept() applies Section 8.4 checks 1-8 in order and records the AAR identity on success."""

    def __init__(self, tool_id, witness_keys):
        self.tool_id, self.keys, self.accepted = tool_id, witness_keys, set()

    def accept(self, aar_bytes, request, now, proof=None, require_inclusion=True):
        r = tool_accept(aar_bytes, self.keys, self.tool_id, request, now, proof, require_inclusion, replay=self.accepted)
        return r


def tool_accept(aar_bytes, witness_keys, tool_id, request, now, proof=None, require_inclusion=True, replay=None):
    """-> {"result": "accept"} | {"result": "reject", "reason": CODE}.  replay: a set kept by the caller (None = stateless).
    require_inclusion=False exists only for unit tests of the earlier checks; -01 requires check 8 for every AAR."""
    if aar_bytes is None:
        return {"result": "reject", "reason": "NO_RECEIPT"}                                  # 1
    try:
        payload, prot = cose.verify1(aar_bytes, witness_keys, cose.TYP_AAR)                  # 2
        aar = cose.loads(payload)
        cwt = prot[cose.H_CWT]
        ident = (cwt[cose.CWT_ISS], aar["chain"]["ledger"], cwt[cose.CWT_SUB])      # -02 (C-15): (iss, chain.ledger, sub)
    except cose.CoseError as e:
        return {"result": "reject", "reason": str(e)}
    except (KeyError, TypeError):
        return {"result": "reject", "reason": "MALFORMED"}
    if aar.get("independence") == "none":
        return {"result": "reject", "reason": "WITNESS_NOT_INDEPENDENT"}
    if aar["verdict"]["decision"] != "allow":                                                 # 3
        return {"result": "reject", "reason": "NOT_ALLOWED"}
    if aar["audience"] != tool_id:                                                            # 4
        return {"result": "reject", "reason": "AUDIENCE"}
    if request is None or aar["action"]["binding_request_hash"] != request_hash(request):     # 5 (no request = nothing to bind to)
        return {"result": "reject", "reason": "REQUEST_MISMATCH"}
    if replay is not None and ident in replay:                                                # 6
        return {"result": "reject", "reason": "REPLAY"}
    if now > aar["expires"]:                                                                  # 7
        return {"result": "reject", "reason": "RECEIPT_EXPIRED"}
    if require_inclusion:                                                                     # 8
        why, _ = check_inclusion(aar_bytes, witness_keys, proof)
        if why:
            return {"result": "reject", "reason": "INCLUSION_INVALID" if why == "MISMATCH" else why}
    if replay is not None:
        replay.add(ident)
    return {"result": "accept"}
