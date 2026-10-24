"""Principal key pinning from an EXTERNAL registry file (Section 4.2). No TOFU: a principal absent from the registry
cannot open a ledger. The registry file is read-only input to the witness; the operator must not control it.

Format (JSON):
 {"source": "out-of-band-registry:<who/when>",
  "principals": {"<principal-id>": {"alg": "EdDSA"|"ES256", "pub": "<hex>", "name": "<symbolic key name, abstract mode>"}}}
"""
import json
from . import cose

ALGS = {"EdDSA": cose.ALG_EDDSA, "ES256": cose.ALG_ES256}


class Registry:
    def __init__(self, data):
        self.source = data.get("source", "")
        self.principals = data.get("principals", {})
        if not self.source:
            raise ValueError("registry must name its source")

    @staticmethod
    def load(path):
        with open(path, encoding="utf-8") as f:
            return Registry(json.load(f))

    def key(self, principal):
        e = self.principals.get(principal)
        if e is None or "pub" not in e:
            return None
        return cose.Key.public(ALGS[e["alg"]], bytes.fromhex(e["pub"]))

    def check(self, principal, signed_by=None, cose_bytes=None, expect_payload=None, typ=None):
        """-> None if accepted, else reason: KEY_NOT_PINNED | KEY_MISMATCH | MANDATE_SIG."""
        e = self.principals.get(principal)
        if e is None:
            return "KEY_NOT_PINNED"
        if cose_bytes is not None:
            k = self.key(principal)
            if k is None:
                return "KEY_NOT_PINNED"
            try:
                payload, _ = cose.verify1(cose_bytes, [k], typ)
            except cose.CoseError:
                return "KEY_MISMATCH"
            if expect_payload is not None and payload != expect_payload:
                return "MANDATE_SIG"
            return None
        # abstract mode (symbolic keys): the claimed signer name must equal the pinned name
        return None if signed_by is not None and signed_by == e.get("name") else "KEY_MISMATCH"
