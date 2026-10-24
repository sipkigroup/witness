"""QuorumRegistry for the evidence-pack checker (the design notes 2.4): the STATELESS part of the team check behind the core's
registry.check(principal, signed_by, cose_bytes, expect_payload, typ) -> None|code, so aar_ref.verify_file runs unchanged.
 - wa-sig  -> WaRegistry (pinned key of the account: solo mode, genesis);
 - wq      -> wq_profile.verify_wq against the policy named in the envelope (signatures, membership, requirements from the payload);
 - wb      -> wq_profile.verify_wb with the signer taken from any version of the chain (who was a member WHEN is the second pass);
 - COSE_Sign1 -> aar_ref Registry, as before.
Policy-at-time and approval requirements (they need the RECEIPT action) are the SECOND pass in verify_pack.py, not here.
Written by task 06 because no QuorumRegistry of task 01 exists yet; the checker prefers registry_wa.QuorumRegistry once 01 ships it
with the same constructor (see ZAMECHANIYA.md)."""
import cbor2

import wa_profile as wa
import wq_profile as q
try:
    from registry_wa import WaRegistry, looks_like_envelope           # checker / pack layout: modules side by side
except ImportError:
    from app.registry_wa import WaRegistry, looks_like_envelope       # server source tree


def rp_of(entry):
    w = entry.get("webauthn") or {}
    return {"rp_id": w.get("rp_id"), "origins": list(w.get("origins") or [])}


class QuorumRegistry(WaRegistry):
    def __init__(self, principals, source, chain=(), rp=None):
        super().__init__(principals, source)
        self.chain = list(chain)
        self.rp = rp

    @staticmethod
    def for_account(principal, entry, chain=(), rp=None):
        return QuorumRegistry({principal: entry}, entry.get("pin_source") or "webauthn-registration", chain, rp or rp_of(entry))

    def _member(self, kid):
        for e in reversed(self.chain):
            pb = e[0] if not isinstance(e, dict) else e["policy"]
            try:
                for m in cbor2.loads(pb)["members"]:
                    if m["kid"] == kid:
                        return m
            except Exception:   # noqa: BLE001
                continue
        return None

    def check(self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None):
        if cose_bytes is None or not looks_like_envelope(cose_bytes):
            return super().check(principal, signed_by, cose_bytes, expect_payload, typ)
        if principal not in self.principals:
            return "KEY_NOT_PINNED"
        kind = q.envelope_kind(cose_bytes)
        if kind == "wq":
            if not self.chain:
                return "WQ_POLICY_UNKNOWN"
            return q.verify_wq(cose_bytes, typ, expect_payload, self.chain, rp=self.rp)
        if kind == "wb":
            try:
                kid = cbor2.loads(cose_bytes)["kid"]
            except Exception:   # noqa: BLE001
                return "WB_MALFORMED"
            m = self._member(kid) if isinstance(kid, bytes) else None
            if m is None:
                return "WQ_NOT_MEMBER"
            return q.verify_wb(cose_bytes, typ, expect_payload, m, rp=self.rp)
        return super().check(principal, signed_by, cose_bytes, expect_payload, typ)    # wa-sig or a malformed map -> WA_*


__all__ = ["QuorumRegistry", "rp_of", "wa"]
