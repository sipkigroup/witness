"""RFC 3161 time-stamp client and OFFLINE verifier (the design notes section 7: second anchor of the batch Merkle root).
Dependencies: asn1crypto (MIT) for DER, cryptography (Apache-2.0 / BSD) for signatures and the certificate chain. No network in verify().

request(digest32, url) -> tsr bytes        SHA-256 imprint, random 64-bit nonce, certReq=true; the reply is checked for status, nonce, imprint
verify(tsr, digest32, ca_bundle) -> {"ok": bool, "gen_time": int|None, "tsa": str|None, "reason": None|code}
  ca_bundle: list of certificates (DER or PEM bytes), or a path to a PEM/DER file or to a directory of them (trust anchors).
  codes: TSA_MALFORMED, TSA_STATUS, TSA_IMPRINT, TSA_SIG, TSA_CHAIN, TSA_EKU, TSA_TIME, TSA_NONCE.
Honest limits: no revocation check (offline: no CRL/OCSP); validity of the chain is judged at genTime, not now."""
import glob
import hashlib
import os
import secrets
import urllib.request

from asn1crypto import core, pem, tsp
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512, "sha1": hashes.SHA1}
MAX_DEPTH = 6
_DER = Encoding.DER


# ------------------------------------------------------------------ request
def make_query(digest32, nonce=None):
    """DER TimeStampReq (RFC 3161 2.4.1): v1, SHA-256 imprint, nonce, certReq=true. -> (der, nonce)"""
    if not isinstance(digest32, (bytes, bytearray)) or len(digest32) != 32:
        raise ValueError("digest32 must be 32 bytes")
    nonce = secrets.randbits(63) | 1 if nonce is None else nonce
    q = tsp.TimeStampReq({"version": "v1",
                          "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": bytes(digest32)},
                          "nonce": nonce, "cert_req": True})
    return q.dump(), nonce


def request(digest32, url, timeout=30):
    """POST a query to the TSA at `url`; -> the raw TimeStampResp bytes (what goes to /data/anchors/<batch>.tsr.<tsa>).
    Raises ValueError when the reply is not granted, or its nonce/imprint differ (the signature is checked by verify())."""
    der, nonce = make_query(digest32)
    req = urllib.request.Request(url, data=der, method="POST", headers={"Content-Type": "application/timestamp-query",
                                                                         "Accept": "application/timestamp-reply"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(1 << 20)
    tst, why = _tst_info(body)
    if why:
        raise ValueError(why)
    if tst["nonce"].native != nonce:
        raise ValueError("TSA_NONCE")
    mi = tst["message_imprint"]
    if mi["hash_algorithm"]["algorithm"].native != "sha256" or mi["hashed_message"].native != bytes(digest32):
        raise ValueError("TSA_IMPRINT")
    return body


# ------------------------------------------------------------------ verify
def _status(tsr):
    """PKIStatus of a TimeStampResp read on its own: asn1crypto's TimeStampResp wrongly requires the token, which a rejection omits."""
    seq = core.Sequence.load(bytes(tsr))
    return tsp.PKIStatusInfo.load(seq[0].dump())["status"].native


def _tst_info(tsr):
    try:
        if _status(tsr) not in ("granted", "granted_with_mods"):
            return None, "TSA_STATUS"
        resp = tsp.TimeStampResp.load(bytes(tsr))
        tok = resp["time_stamp_token"]
        if tok["content_type"].native != "signed_data":
            return None, "TSA_MALFORMED"
        eci = tok["content"]["encap_content_info"]
        if eci["content_type"].native != "tst_info":
            return None, "TSA_MALFORMED"
        tst = eci["content"].parsed
        tst.native                                   # forces a full parse: garbage fails here, not later
        return tst, None
    except Exception:   # noqa: BLE001  (hostile bytes: any parse error is MALFORMED)
        return None, "TSA_MALFORMED"


def _load_bundle(ca_bundle):
    items = []
    if isinstance(ca_bundle, (str, os.PathLike)):
        p = os.fspath(ca_bundle)
        paths = sorted(glob.glob(os.path.join(p, "*"))) if os.path.isdir(p) else [p]
        for f in paths:
            if os.path.isfile(f):
                with open(f, "rb") as fh:
                    items.append(fh.read())
    else:
        items = list(ca_bundle or [])
    out = []
    for b in items:
        b = bytes(b)
        ders = [d for _, _, d in pem.unarmor(b, multiple=True)] if pem.detect(b) else [b]
        for d in ders:
            out.append(x509.load_der_x509_certificate(d))
    return out


def _verify_sig(pub, sig, data, sig_algo, hash_name):
    h = HASHES[hash_name]()
    if isinstance(pub, rsa.RSAPublicKey):
        if sig_algo == "rsassa_pss":
            pub.verify(sig, data, padding.PSS(padding.MGF1(h), padding.PSS.AUTO), h)
        else:
            pub.verify(sig, data, padding.PKCS1v15(), h)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, data, ec.ECDSA(h))
    else:
        raise InvalidSignature("unsupported key")


def _valid_at(c, t):
    return c.not_valid_before_utc <= t <= c.not_valid_after_utc


def _name(c):
    try:
        cn = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return cn[0].value if cn else c.subject.rfc4514_string()
    except Exception:   # noqa: BLE001
        return "?"


def verify(tsr, digest32, ca_bundle):
    """Offline RFC 3161 check: status granted; TSTInfo imprint = SHA-256 digest32; signed attributes (content-type, message-digest);
    signature of the signer; signer cert has the (critical) timeStamping EKU; chain up to a certificate of ca_bundle;
    every certificate of the chain valid at genTime."""
    out = {"ok": False, "gen_time": None, "tsa": None, "reason": None}

    def fail(code):
        out["reason"] = code
        return out

    tst, why = _tst_info(tsr)
    if why:
        return fail(why)
    try:
        gt = tst["gen_time"].native
        out["gen_time"] = int(gt.timestamp())
        mi = tst["message_imprint"]
        if mi["hash_algorithm"]["algorithm"].native != "sha256" or mi["hashed_message"].native != bytes(digest32):
            return fail("TSA_IMPRINT")
        sd = tsp.TimeStampResp.load(bytes(tsr))["time_stamp_token"]["content"]
        econtent = sd["encap_content_info"]["content"].contents
        sis = sd["signer_infos"]
        if len(sis) != 1:
            return fail("TSA_MALFORMED")
        si = sis[0]
        certs = [c.chosen for c in (sd["certificates"] or []) if c.name == "certificate"]
        sid = si["sid"]
        signer = None
        for c in certs:
            if sid.name == "issuer_and_serial_number":
                if c.issuer == sid.chosen["issuer"] and c.serial_number == sid.chosen["serial_number"].native:
                    signer = c
            elif c.key_identifier == sid.chosen.native:
                signer = c
        if signer is None:
            return fail("TSA_CHAIN")                 # certReq=true: the signer certificate must be in the token
        hname = si["digest_algorithm"]["algorithm"].native
        if hname not in HASHES:
            return fail("TSA_SIG")
        attrs = si["signed_attrs"]
        if not attrs:
            return fail("TSA_SIG")
        got = {a["type"].native: a["values"][0] for a in attrs}
        if got.get("content_type") is None or got["content_type"].native != "tst_info":
            return fail("TSA_SIG")
        if got.get("message_digest") is None or got["message_digest"].native != hashlib.new(hname, econtent).digest():
            return fail("TSA_SIG")
        signed = b"\x31" + attrs.dump()[1:]            # the signature is over the SET OF attributes (tag 0x31), not the [0] IMPLICIT form
        scert = x509.load_der_x509_certificate(signer.dump())
        try:
            _verify_sig(scert.public_key(), si["signature"].native, signed, si["signature_algorithm"].signature_algo, hname)
        except (InvalidSignature, ValueError, TypeError):
            return fail("TSA_SIG")
        out["tsa"] = _name(scert)
        try:
            eku = scert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if not eku.critical or [o.dotted_string for o in eku.value] != [OID_TIMESTAMPING]:
                return fail("TSA_EKU")               # RFC 3161 2.3: exactly one KeyPurposeId, timeStamping, critical
        except x509.ExtensionNotFound:
            return fail("TSA_EKU")
        anchors = _load_bundle(ca_bundle)
        pool = [x509.load_der_x509_certificate(c.dump()) for c in certs] + anchors
        anchor_ders = {a.public_bytes(_DER) for a in anchors}
        cur, chain = scert, [scert]
        for _ in range(MAX_DEPTH):
            if cur.public_bytes(_DER) in anchor_ders:
                break
            parent = None
            for p in pool:
                if p.subject == cur.issuer and p.public_bytes(_DER) != cur.public_bytes(_DER):
                    try:
                        cur.verify_directly_issued_by(p)
                    except Exception:   # noqa: BLE001
                        continue
                    parent = p
                    if p.public_bytes(_DER) in anchor_ders:
                        break
            if parent is None:
                return fail("TSA_CHAIN")
            cur = parent
            chain.append(cur)
        else:
            return fail("TSA_CHAIN")
        if cur.public_bytes(_DER) not in anchor_ders:
            return fail("TSA_CHAIN")
        if not all(_valid_at(c, gt) for c in chain):
            return fail("TSA_TIME")
    except Exception:   # noqa: BLE001
        return fail("TSA_MALFORMED")
    out["ok"] = True
    return out

