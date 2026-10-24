"""Reference implementation of the profile "mandate signed by a WebAuthn assertion" (the design notes section 3,
appendix to draft-deus-aar-04). Only stdlib + cbor2 + cryptography.

Public API: challenge, der_to_raw_lows, make_envelope, verify_envelope, is_envelope, thumbprint, SoftAuthenticator."""
import base64
import hashlib
import json
import os

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

V = "deus-aar-wa-0.1"
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
TYP_MANDATE = "application/aar-mandate+cbor"
TYP_APPROVAL = "application/aar-approval+cbor"
TYP_REVOCATION = "application/aar-revocation+cbor"
TYP_CEILING = "application/aar-ceiling+cbor"
TYP_ALLOWANCE = "application/aar-allowance+cbor"     # extension (0.2.10): "allow this command in this project"
SIG_CODE = {TYP_MANDATE: "MANDATE_SIG", TYP_APPROVAL: "APPROVAL_SIG",
            TYP_REVOCATION: "REVOCATION_SIG", TYP_CEILING: "CEILING_SIG", TYP_ALLOWANCE: "ALLOWANCE_SIG"}
KEYS = ("v", "typ", "kid", "payload", "authData", "clientDataJSON", "sig")
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cde(x) -> bytes:
    return cbor2.dumps(x, canonical=True)


def challenge(typ: str, payload: bytes) -> bytes:
    """3.3: SHA-256("deus-aar-wa-0.1" || 0x00 || typ || 0x00 || payload)."""
    return hashlib.sha256(V.encode() + b"\x00" + typ.encode() + b"\x00" + payload).digest()


def thumbprint(pub: bytes) -> bytes:
    """RFC 9679 SHA-256 thumbprint of an EC2 P-256 COSE_Key (as -04 6.1 / aar_ref.cose.thumbprint)."""
    if len(pub) != 65 or pub[0] != 4:
        raise ValueError("MALFORMED")
    return hashlib.sha256(cde({1: 2, -1: 1, -2: pub[1:33], -3: pub[33:]})).digest()


def der_to_raw_lows(der: bytes) -> bytes:
    """DER ECDSA signature -> r||s (32+32 big-endian) with low-S normalisation (s := n - s when s > n/2)."""
    r, s = decode_dss_signature(der)
    if s > P256_N // 2:
        s = P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def make_envelope(typ, kid, payload, authData, clientDataJSON, der_sig, normalize=True) -> bytes:
    """wa-sig envelope in CDE. normalize=False keeps a high-S signature (only for negative tests)."""
    sig = der_to_raw_lows(der_sig) if normalize else _raw(der_sig)
    return cde({"v": V, "typ": typ, "kid": kid, "payload": payload, "authData": authData,
                "clientDataJSON": clientDataJSON, "sig": sig})


def is_envelope(b: bytes) -> bool:
    """3.6: wa-sig starts with 0xA7 (map of 7), COSE_Sign1 with 0xD2 (tag 18)."""
    return len(b) > 0 and b[0] == 0xA7


def verify_envelope(env: bytes, expect_typ, expect_payload, reg_entry: dict):
    """Normative order of 3.5. Returns None when valid, else the reason code."""
    try:
        m = cbor2.loads(env)
        if not isinstance(m, dict) or tuple(sorted(m.keys(), key=str)) != tuple(sorted(KEYS)):
            return "WA_MALFORMED"
        if m["v"] != V or not isinstance(m["typ"], str):
            return "WA_MALFORMED"
        for k in ("kid", "payload", "authData", "clientDataJSON", "sig"):
            if not isinstance(m[k], bytes):
                return "WA_MALFORMED"
        if len(m["kid"]) != 32 or len(m["sig"]) != 64:
            return "WA_MALFORMED"
        if cde(dict(m)) != env:          # not Core Deterministic Encoding (key order, lengths, indefinite items)
            return "WA_MALFORMED"
    except Exception:
        return "WA_MALFORMED"
    # 2
    if m["typ"] != expect_typ or m["payload"] != expect_payload:
        return SIG_CODE.get(expect_typ, "MANDATE_SIG") if isinstance(expect_typ, str) else "MANDATE_SIG"
    # 3
    try:
        pub = bytes.fromhex(reg_entry["pub"])
        if reg_entry.get("alg") != "ES256" or m["kid"] != thumbprint(pub):
            return "KEY_MISMATCH"
        wa = reg_entry["webauthn"]
    except Exception:
        return "KEY_MISMATCH"
    # 4
    try:
        cd = json.loads(m["clientDataJSON"].decode("utf-8"))
        if not isinstance(cd, dict) or cd.get("type") != "webauthn.get":
            return "WA_CLIENTDATA"
        if cd.get("challenge") != b64u(challenge(m["typ"], m["payload"])):
            return "WA_CLIENTDATA"
        if cd.get("origin") not in wa["origins"]:
            return "WA_CLIENTDATA"
        if cd.get("crossOrigin", False) is not False:
            return "WA_CLIENTDATA"
    except Exception:
        return "WA_CLIENTDATA"
    # 5
    ad = m["authData"]
    try:
        rp_hash = hashlib.sha256(wa["rp_id"].encode()).digest()
    except Exception:                       # a damaged registry entry (rp_id missing / not a string)
        return "KEY_MISMATCH"
    if len(ad) < 37 or ad[:32] != rp_hash:
        return "WA_AUTHDATA"
    if not (ad[32] & FLAG_UP) or not (ad[32] & FLAG_UV):
        return "WA_AUTHDATA"
    # 6
    r, s = int.from_bytes(m["sig"][:32], "big"), int.from_bytes(m["sig"][32:], "big")
    if not (0 < r < P256_N and 0 < s <= P256_N // 2):
        return "WA_SIG"
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
        key.verify(encode_dss_signature(r, s), ad + hashlib.sha256(m["clientDataJSON"]).digest(), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return "WA_SIG"
    return None


class SoftAuthenticator:
    """Software passkey for tests: P-256, UP|UV flags, clientDataJSON, DER signature (can emit high-S)."""

    def __init__(self, private_int: int = None, credential_id: bytes = None):
        self.key = ec.derive_private_key(private_int, ec.SECP256R1()) if private_int else ec.generate_private_key(ec.SECP256R1())
        self.credential_id = credential_id or os.urandom(32)
        nums = self.key.public_key().public_numbers()
        self.x, self.y = nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")
        self.pub = b"\x04" + self.x + self.y
        self.kid = thumbprint(self.pub)

    def reg_entry(self, rp_id, origins, pin_source="webauthn-registration:%s:2026-10-19T08:00:00Z:registry-log#1"):
        return {"alg": "ES256", "pub": self.pub.hex(),
                "webauthn": {"rp_id": rp_id, "origins": list(origins), "credential_id": b64u(self.credential_id)},
                "pin_source": pin_source % rp_id if "%s" in pin_source else pin_source}

    @staticmethod
    def client_data(typ, chal: bytes, origin, cross_origin=None) -> bytes:
        d = {"type": typ, "challenge": b64u(chal), "origin": origin}
        if cross_origin is not None:
            d["crossOrigin"] = cross_origin
        return json.dumps(d, separators=(",", ":")).encode()

    def _auth_data(self, rp_id, flags, sign_count=0, attested=b"") -> bytes:
        return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big") + attested

    def get_assertion(self, chal: bytes, rp_id, origin, flags=FLAG_UP | FLAG_UV, high_s=False,
                      cd_type="webauthn.get", cross_origin=None, rp_id_hash_of=None):
        """-> (authData, clientDataJSON, der_sig). rp_id_hash_of: hash another rp id (negative test)."""
        ad = self._auth_data(rp_id_hash_of or rp_id, flags)
        cd = self.client_data(cd_type, chal, origin, cross_origin)
        der = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        if high_s != (s > P256_N // 2):
            der = encode_dss_signature(r, P256_N - s)
        return ad, cd, der

    def attestation_object(self, rp_id) -> bytes:
        """fmt none, ES256 credential public key (for the stub's registration)."""
        cose_key = cde({1: 2, 3: -7, -1: 1, -2: self.x, -3: self.y})
        acd = b"\x00" * 16 + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose_key
        ad = self._auth_data(rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0, acd)
        return cde({"fmt": "none", "attStmt": {}, "authData": ad})

    def create_credential(self, chal: bytes, rp_id, origin) -> dict:
        """RegistrationResponseJSON-like dict (as @simplewebauthn/browser)."""
        cd = self.client_data("webauthn.create", chal, origin)
        return {"id": b64u(self.credential_id), "rawId": b64u(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(self.attestation_object(rp_id))}}

    def login_credential(self, chal: bytes, rp_id, origin) -> dict:
        ad, cd, der = self.get_assertion(chal, rp_id, origin)
        return {"id": b64u(self.credential_id), "rawId": b64u(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(der)}}

    def sign_object(self, typ, payload, rp_id, origin, **kw) -> bytes:
        """Whole path: challenge -> assertion -> envelope (what a browser + server do)."""
        ad, cd, der = self.get_assertion(challenge(typ, payload), rp_id, origin, **kw)
        return make_envelope(typ, self.kid, payload, ad, cd, der)
