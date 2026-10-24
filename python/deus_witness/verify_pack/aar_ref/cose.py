"""Minimal COSE_Sign1 (RFC 9052) over cbor2 + cryptography. Algs: EdDSA (-8, Ed25519), ES256 (-7, P-256/SHA-256, raw r||s)."""
import hashlib

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ALG_EDDSA, ALG_ES256 = -8, -7
H_ALG, H_CWT, H_KID, H_TYP = 1, 15, 4, 16
CWT_ISS, CWT_SUB, CWT_IAT = 1, 2, 6
TYP_AAR = "application/aar-receipt+cbor"
TYP_ENTRY = "application/aar-ledger-entry+cbor"
TYP_MANDATE = "application/aar-mandate+cbor"
TYP_CEILING = "application/aar-ceiling+cbor"
TYP_APPROVAL = "application/aar-approval+cbor"
TYP_REVOCATION = "application/aar-revocation+cbor"
TYP_CHECKPOINT = "application/aar-checkpoint+cbor"
TYP_PROMISE = "application/aar-inclusion-promise+cbor"     # -05 Section 9.5
TYP_ALLOWANCE = "application/aar-allowance+cbor"           # extension (0.2.10)


class CoseError(Exception):
    """str(e) is always a reason code of the draft -01 registry (Section 8.5): MALFORMED, TYP_MISMATCH, KID_UNKNOWN,
    ALG_MISMATCH, SIGNATURE_INVALID."""


P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def thumbprint(alg, pub: bytes) -> bytes:
    """COSE Key Thumbprint (RFC 9679, SHA-256, 32 bytes) of the public key: hash of the deterministically encoded
    COSE_Key holding only the required members (OKP: kty crv x; EC2: kty crv x y)."""
    if alg == ALG_EDDSA:
        k = {1: 1, -1: 6, -2: pub}
    else:
        if len(pub) != 65 or pub[0] != 4:
            raise CoseError("MALFORMED")
        k = {1: 2, -1: 1, -2: pub[1:33], -3: pub[33:]}
    return hashlib.sha256(cbor2.dumps(k, canonical=True)).digest()


def plain(x):
    """cbor2 >= 6 returns tuple/frozendict; normalise to list/dict."""
    if isinstance(x, cbor2.CBORTag):
        return cbor2.CBORTag(x.tag, plain(x.value))
    if isinstance(x, (list, tuple)):
        return [plain(i) for i in x]
    if isinstance(x, dict) or (hasattr(x, "items") and not isinstance(x, (bytes, str))):
        return {k: plain(v) for k, v in x.items()}
    return x


def loads(b):
    return plain(cbor2.loads(b))


def sha256(b):
    return hashlib.sha256(b).digest()


class Key:
    """Signing key (private) or verification key (pub only)."""

    def __init__(self, alg, priv=None, pub=None):
        self.alg, self.priv = alg, priv
        if priv is not None:
            if alg == ALG_EDDSA:
                pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            else:
                pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.pub = pub
        self.kid = thumbprint(alg, pub)

    @staticmethod
    def generate(alg):
        if alg == ALG_EDDSA:
            return Key(alg, ed25519.Ed25519PrivateKey.generate())
        return Key(alg, ec.generate_private_key(ec.SECP256R1()))

    @staticmethod
    def from_seed(alg, seed32: bytes):
        """TEST VECTORS ONLY: deterministic keys from a 32-byte seed."""
        if alg == ALG_EDDSA:
            return Key(alg, ed25519.Ed25519PrivateKey.from_private_bytes(seed32))
        return Key(alg, ec.derive_private_key(int.from_bytes(seed32, "big"), ec.SECP256R1()))

    @staticmethod
    def public(alg, pub: bytes):
        return Key(alg, None, pub)

    def sign(self, data: bytes) -> bytes:
        if self.priv is None:
            raise CoseError("no private key")
        if self.alg == ALG_EDDSA:
            return self.priv.sign(data)
        r, s = decode_dss_signature(self.priv.sign(data, ec.ECDSA(hashes.SHA256())))
        if s > P256_N // 2:                     # -01 Section 8.1: ES256 signatures MUST be low-S (no malleability)
            s = P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, sig: bytes, data: bytes) -> bool:
        try:
            if self.alg == ALG_EDDSA:
                ed25519.Ed25519PublicKey.from_public_bytes(self.pub).verify(sig, data)
            else:
                if len(sig) != 64 or int.from_bytes(sig[32:], "big") > P256_N // 2:   # high-S is rejected (-01)
                    return False
                pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.pub)
                pk.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                          data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False


def _sig_structure(protected: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def sign1(key: Key, payload: bytes, typ: str, cwt: dict = None, unprotected: dict = None) -> bytes:
    prot = {H_ALG: key.alg, H_KID: key.kid, H_TYP: typ}
    if cwt:
        prot[H_CWT] = cwt
    pbytes = cbor2.dumps(prot, canonical=True)
    sig = key.sign(_sig_structure(pbytes, payload))
    return cbor2.dumps(cbor2.CBORTag(18, [pbytes, unprotected or {}, payload, sig]), canonical=True)


def parse1(data: bytes):
    """-> (protected_map, unprotected_map, payload, sig, protected_bytes). Raises CoseError on malformed input."""
    try:
        import io
        fp = io.BytesIO(data)
        t = plain(cbor2.CBORDecoder(fp).decode())
        if fp.read(1):                                          # -03 test XC01: exactly one item, no trailing data (Section 5.1)
            raise ValueError("trailing data")
    except Exception as e:  # noqa
        raise CoseError("MALFORMED")
    if not (isinstance(t, cbor2.CBORTag) and t.tag == 18 and isinstance(t.value, list) and len(t.value) == 4):
        raise CoseError("MALFORMED")   # includes: not tagged 18 (-01 Section 8.1)
    pb, un, payload, sig = t.value
    if not (isinstance(pb, bytes) and isinstance(un, dict) and isinstance(payload, bytes) and isinstance(sig, bytes)):
        raise CoseError("MALFORMED")
    try:
        prot = loads(pb)
    except Exception as e:  # noqa
        raise CoseError("MALFORMED")
    if not isinstance(prot, dict):
        raise CoseError("MALFORMED")
    return prot, un, payload, sig, pb


def verify1(data: bytes, keys, typ: str = None):
    """keys: iterable of Key (verification set pinned by the verifier). Returns (payload, protected_map).
    The key is chosen by kid; the alg in the header MUST equal the key's alg (no alg confusion)."""
    prot, _, payload, sig, pb = parse1(data)
    if cbor2.dumps(prot, canonical=True) != pb:                 # protected header must itself be CDE without duplicate keys
        raise CoseError("MALFORMED")
    alg, kid = prot.get(H_ALG), prot.get(H_KID)
    if alg is None or kid is None:                              # alg and kid MUST be protected (-01 Section 8.1)
        raise CoseError("MALFORMED")
    if typ is not None and prot.get(H_TYP) != typ:
        raise CoseError("TYP_MISMATCH")
    cands = [k for k in keys if k.kid == kid]          # -02 Section 8.4 check 2 (AMBIGUITY-C-3): select the key by kid FIRST ...
    if not cands:
        raise CoseError("KID_UNKNOWN")
    for k in cands:
        if k.alg != alg or alg not in (ALG_EDDSA, ALG_ES256):   # ... then alg MUST equal that key's algorithm
            raise CoseError("ALG_MISMATCH")
        if k.verify(sig, _sig_structure(pb, payload)):
            try:                                                # -01 Section 5.1: payload MUST be CDE, no duplicate keys
                ok = cbor2.dumps(loads(payload), canonical=True) == payload
            except Exception:  # noqa
                ok = False
            if not ok:
                raise CoseError("MALFORMED")
            return payload, prot
    raise CoseError("SIGNATURE_INVALID")
