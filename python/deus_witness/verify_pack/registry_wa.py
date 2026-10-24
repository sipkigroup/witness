"""WaRegistry: principal-key registry that understands BOTH signature forms (the design notes 3.6):
 - `wa-sig` envelope (first byte 0xA7) -> wa_profile.verify_envelope (profile of draft-deus-aar-04, section 3.5);
 - COSE_Sign1 (0xD2) -> exactly aar_ref.registry.Registry.
QuorumRegistry(WaRegistry) (the design notes 2.4): a CBOR-map envelope is told apart by its member `v`:
 - deus-aar-wa-0.1 -> as WaRegistry (solo account, genesis policy); with a chain and wa_with_policy=False (the live server) a plain
   wa-sig of the pinned key is refused (WQ_REQUIRED): one owner's signature must not bypass the rules of a team;
 - deus-aar-wq-0.1 -> wq_profile.verify_wq over the policy chain of the account (signatures, membership, requirements of mandate /
   revocation / ceiling / policy; an approval's requirements need the action and are checked by the caller);
 - deus-aar-wb-0.1 -> wq_profile.verify_wb, signer = member of the LAST policy of the chain, or the pinned key of a solo account
   (a checker of an old entry passes the chain up to the policy in force at that entry).
Entries are the registry records of 3.4: {"alg":"ES256","pub":hex,"webauthn":{...},"pin_source":...}.
0.2.2 (several passkeys per account): `keys` = {kid: record} -- when given, a wa-sig / wb of the account is checked against the record
of ITS kid in that set (the pinned record counts only when it is in the set). The live server passes the keys active NOW; the pack
checker passes every key the registry log ever added and checks WHEN each was active in its second pass (wq_profile.key_active_at).
Stand-alone on purpose (imports only aar_ref.registry, wa_profile and - if present - wq_profile): the same file is copied into the
evidence pack. Without wq_profile beside it a wq/wb envelope is WA_MALFORMED (as the 0.1 checkers say)."""
import cbor2

import wa_profile as wa
from aar_ref.registry import Registry

try:
    import wq_profile as wq
except ImportError:          # 0.1 pack / checker: only wa-sig and COSE_Sign1
    wq = None


def looks_like_envelope(b):
    """A CBOR map (major type 5) is a wa-sig attempt; anything it gets wrong is a WA_* code, not a COSE error."""
    return len(b) > 0 and (b[0] & 0xE0) == 0xA0


def envelope_v(b):
    """Member `v` of a CBOR-map envelope, or None."""
    try:
        m = cbor2.loads(b)
    except Exception:
        return None
    return m.get("v") if isinstance(m, dict) else None


def envelope_kid(b):
    try:
        k = cbor2.loads(b).get("kid")
    except Exception:
        return None
    return k if isinstance(k, bytes) else None


class WaRegistry(Registry):
    def __init__(self, principals, source, keys=None):
        super().__init__({"source": source, "principals": principals})
        self.keys = None if keys is None else dict(keys)

    @staticmethod
    def for_account(principal, entry, keys=None):
        return WaRegistry({principal: entry}, entry.get("pin_source") or "webauthn-registration", keys)

    def key_entry(self, principal, kid):
        """Record that checks a signature by `kid` for `principal`: the pinned record (0.1), or with a key set the record of that kid."""
        e = self.principals.get(principal)
        if e is None or self.keys is None:
            return e
        return self.keys.get(kid) or (e if kid is None else None)

    def check(self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None):
        """-> None if accepted, else a reason code. Envelope failures give the code of 3.5 (MANDATE_SIG/APPROVAL_SIG/KEY_MISMATCH/WA_*)."""
        if cose_bytes is not None and looks_like_envelope(cose_bytes):
            if self.principals.get(principal) is None:
                return "KEY_NOT_PINNED"
            e = self.key_entry(principal, envelope_kid(cose_bytes))
            if e is None:
                return "KEY_MISMATCH"            # a key of this account that is not active (removed, or never added)
            if "pub" not in e:
                return "KEY_NOT_PINNED"
            return wa.verify_envelope(cose_bytes, typ, expect_payload, e)
        return super().check(principal, signed_by, cose_bytes, expect_payload, typ)


class QuorumRegistry(WaRegistry):
    """chain: [(policy_bytes, envelope_bytes, t), ...] of the account, version 1 first (empty = solo account, behaves as WaRegistry).
    The chain itself is verified by whoever builds it (wq_profile.verify_policy_chain); here it is only looked up.
    wa_with_policy: True for a checker of a whole ledger (entries before the genesis are plain wa-sigs), False for the live server."""

    def __init__(self, principals, source, chain=(), wa_with_policy=True, keys=None):
        super().__init__(principals, source, keys)
        self.chain = list(chain)
        self.wa_with_policy = wa_with_policy

    @staticmethod
    def for_account(principal, entry, chain=(), wa_with_policy=True, keys=None):
        return QuorumRegistry({principal: entry}, entry.get("pin_source") or "webauthn-registration", chain, wa_with_policy, keys)

    @staticmethod
    def rp_of(entry):
        w = entry.get("webauthn") or {}
        return {"rp_id": w.get("rp_id"), "origins": list(w.get("origins") or [])}

    def wb_signer(self, kid, entry):
        """Member map of the newest policy of the chain that lists kid (stateless part: WHICH version was in force at the entry's time
        is the second pass -- server: current policy in approve_with_envelope; checker: policy-at-time), or (solo account) the pinned
        entry when kid is its key, else None. 0.2.0: was the last version only -> an honest wb of a member removed later failed the pack."""
        if self.chain:
            for pb, _, _ in reversed(self.chain):
                m = {m["kid"]: m for m in cbor2.loads(pb)["members"]}.get(kid)
                if m is not None:
                    return m
            return None
        if self.keys is not None:
            return self.keys.get(kid)
        try:
            if wa.thumbprint(bytes.fromhex(entry["pub"])) == kid:
                return entry
        except Exception:
            pass
        return None

    def check(self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None):
        if cose_bytes is None or not looks_like_envelope(cose_bytes):
            return super().check(principal, signed_by, cose_bytes, expect_payload, typ)
        v = envelope_v(cose_bytes)
        if v not in ("deus-aar-wq-0.1", "deus-aar-wb-0.1"):
            if v == wa.V and self.chain and not self.wa_with_policy:
                return "WQ_REQUIRED"
            return super().check(principal, signed_by, cose_bytes, expect_payload, typ)
        e = self.principals.get(principal)
        if e is None or "pub" not in e:
            return "KEY_NOT_PINNED"
        if wq is None:
            return "WA_MALFORMED"
        rp = self.rp_of(e)
        if v == wq.V_WQ:
            if not self.chain:
                return "WQ_POLICY_UNKNOWN"
            return wq.verify_wq(cose_bytes, typ, expect_payload, self.chain, rp=rp)
        try:
            kid = cbor2.loads(cose_bytes)["kid"]
            who = self.wb_signer(kid, e) if isinstance(kid, bytes) else None
        except Exception:
            return "WB_MALFORMED"
        if who is None:
            return "WQ_NOT_MEMBER"
        return wq.verify_wb(cose_bytes, typ, expect_payload, who, rp=rp)
