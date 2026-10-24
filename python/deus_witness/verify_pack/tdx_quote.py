"""Offline checker of an Intel TDX quote (DCAP quote v4; v5 parsed as well) for the Deus Witness TEE binding (cloud/tee/DIZAIN-TDX.md).

STANDALONE: no imports from `app`; needs only the standard library and `cryptography` (already a dependency). A client copies this one
file and runs:  python tdx_quote.py QUOTE.bin --pub PUB_HEX [--iss ISS --t T | --batch BID --root ROOT_HEX] [--expect expect.json]
                                     [--intel-root intel_root.pem] [--collateral-dir DIR [--now T]]
       python tdx_quote.py QUOTE.bin --collateral-dir DIR --fetch-collateral      (the only networked step, Intel PCS)

What it checks (each check is reported as ok / FAIL / NOT VERIFIED - nothing is silently assumed):
  structure       header (version 4|5, ECDSA-P256 attestation key, TEE type TDX, Intel QE vendor id), TD report body, signature data
  quote_sig       ECDSA-P256 signature of header||body by the attestation key carried in the quote
  qe_binding      QE report.report_data[0:32] == SHA-256(attestation key || QE auth data)  (the QE vouches for the attestation key)
  qe_report_sig   QE report signed by the PCK leaf certificate's key
  pck_chain       each certificate of the PCK chain is signed by the next one
  intel_root      the chain ends in the PINNED Intel SGX Root CA (--intel-root); without the pinned file: NOT VERIFIED
  tcb_status      with --collateral-dir (Intel PCS files fetched ONCE by --fetch-collateral; the check itself is offline): TCB Info and
                  QE Identity signed by the TCB Signing cert issued by the pinned root, issueDate..nextUpdate, root CA CRL and PCK CRL
                  (signed, in date, PCK leaf / PCK CA / signers not revoked), FMSPC + PCE ID, QE identity (MRSIGNER, ISVPRODID, masked
                  MISCSELECT/ATTRIBUTES, ISVSVN level), PCK CPUSVN/PCESVN + TEE_TCB_SVN against the TCB levels, TDX module identity
                  -> UpToDate = ok; SWHardeningNeeded / ConfigurationNeeded / OutOfDate / ... = that status (verdict TCB_<status>);
                  Revoked or any collateral fault = FAIL. Without collateral: NOT VERIFIED
  debug           TD attributes DEBUG bit is 0 (a debug TD is readable by the host: rejected)
  report_data     equals the value computed from the witness key and the context (scheme deus-aar-tee-v1)
  measurements    MRTD / RTMR0..3 / MRCONFIGID / ... equal the expected values (--expect), from the reproducible image
GUESSES (to confirm on real hardware, see the TDX design notes): the v5 layout and which bytes its signature covers; the exact
PEM order in certification data type 5 (leaf first is assumed and checked, not trusted).
"""
import hashlib
import json
import struct
import sys

SCHEME = "deus-aar-tee-v1"
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
TEE_TYPE_TDX = 0x00000081
ATT_KEY_ECDSA_P256 = 2
HEADER_LEN = 48
TD10_BODY_LEN = 584
TD15_BODY_LEN = 648
QE_REPORT_LEN = 384
CERT_TYPE_QE_REPORT = 6
CERT_TYPE_PCK_CHAIN = 5
TD_ATTR_DEBUG = 1                       # TDATTRIBUTES bit 0

# TD report body v4 (TDX 1.0): name, length. TDX 1.5 (v5 body type 3) appends tee_tcb_svn2 (16) and mr_servicetd (48).
TD10_FIELDS = (("tee_tcb_svn", 16), ("mr_seam", 48), ("mr_signer_seam", 48), ("seam_attributes", 8), ("td_attributes", 8),
               ("xfam", 8), ("mr_td", 48), ("mr_config_id", 48), ("mr_owner", 48), ("mr_owner_config", 48),
               ("rtmr0", 48), ("rtmr1", 48), ("rtmr2", 48), ("rtmr3", 48), ("report_data", 64))
TD15_EXTRA = (("tee_tcb_svn2", 16), ("mr_servicetd", 48))
MEASUREMENT_FIELDS = ("mr_td", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mr_config_id", "mr_owner", "mr_owner_config", "mr_seam",
                      "td_attributes", "xfam")


class QuoteError(ValueError):
    """The bytes are not a well-formed TDX quote (structure check failed)."""


# ---------------------------------------------------------------- report_data scheme (the server builds it the same way)

def key_hash(pub):
    """First half of report_data: SHA-256("deus-aar-tee-v1:key" 0x00 || witness Ed25519 public key, 32 bytes)."""
    if len(pub) != 32:
        raise ValueError("witness public key must be 32 bytes")
    return hashlib.sha256(SCHEME.encode() + b":key\x00" + pub).digest()


def ctx_boot(iss, t):
    """Second half for the key quote taken at start: binds the service name and the claimed start time (not a proof of time)."""
    return hashlib.sha256(SCHEME.encode() + b":boot\x00" + iss.encode("utf-8") + b"\x00" + struct.pack(">Q", int(t))).digest()


def ctx_batch(bid, root):
    """Second half for an anchor-batch quote: binds the batch id and its Merkle root (which covers every tenant checkpoint)."""
    if len(root) != 32:
        raise ValueError("batch root must be 32 bytes")
    return hashlib.sha256(SCHEME.encode() + b":batch\x00" + bid.encode("utf-8") + b"\x00" + root).digest()


def report_data(pub, ctx32):
    return key_hash(pub) + ctx32


# ---------------------------------------------------------------- parsing

def _take(b, off, n, what):
    if off + n > len(b):
        raise QuoteError("truncated: %s needs %d bytes at %d, quote has %d" % (what, n, off, len(b)))
    return b[off:off + n], off + n


def parse_body(raw, fields):
    out, off = {}, 0
    for name, n in fields:
        out[name] = raw[off:off + n]
        off += n
    return out


def parse_quote(b):
    """-> dict with header fields, `body` (dict of bytes), `signed` (bytes covered by the quote signature), `sig`, `att_pub`,
    `qe_report`, `qe_report_sig`, `qe_auth`, `pck_pem` (bytes), `body_type`. Raises QuoteError."""
    b = bytes(b)
    h, off = _take(b, 0, HEADER_LEN, "header")
    version, att_key_type, tee_type, qe_svn, pce_svn = struct.unpack_from("<HHIHH", h, 0)
    q = {"version": version, "att_key_type": att_key_type, "tee_type": tee_type, "qe_svn": qe_svn, "pce_svn": pce_svn,
         "qe_vendor_id": h[12:28], "user_data": h[28:48]}
    if version == 4:
        raw, off = _take(b, off, TD10_BODY_LEN, "TD report body")
        q["body_type"], fields = 2, TD10_FIELDS
    elif version == 5:                                  # GUESS: v5 = header, u16 body type, u32 body size, body (signature covers all three)
        d, off = _take(b, off, 6, "v5 body descriptor")
        bt, bs = struct.unpack("<HI", d)
        if (bt, bs) == (2, TD10_BODY_LEN):
            fields = TD10_FIELDS
        elif (bt, bs) == (3, TD15_BODY_LEN):
            fields = TD10_FIELDS + TD15_EXTRA
        else:
            raise QuoteError("v5 body type %d size %d is not a TD report" % (bt, bs))
        raw, off = _take(b, off, bs, "TD report body")
        q["body_type"] = bt
    else:
        raise QuoteError("quote version %d (expected 4 or 5)" % version)
    q["signed"] = b[:off]
    q["body"] = parse_body(raw, fields)
    d, off = _take(b, off, 4, "signature data length")
    (sl,) = struct.unpack("<I", d)
    sd, end = _take(b, off, sl, "signature data")
    if end != len(b):
        # 23.10 L3 Phala: the real dstack quote carries 70 bytes after the signature data (buffer padding).
        # Zero padding is cut off; any non-zero tail is still refused (it would be unsigned data riding along).
        if any(b[end:]):
            raise QuoteError("%d non-zero trailing bytes after the signature data" % (len(b) - end))
        q["trailing_zero_pad"] = len(b) - end
    q["sig"], o = sd[0:64], 64
    q["att_pub"], o = sd[64:128], 128
    if len(sd) < 134:
        raise QuoteError("signature data too short")
    ct, cs = struct.unpack_from("<HI", sd, o)
    o += 6
    if ct != CERT_TYPE_QE_REPORT:
        raise QuoteError("certification data type %d (expected 6 = QE report certification data)" % ct)
    if o + cs != len(sd):
        raise QuoteError("certification data size %d does not match the signature data" % cs)
    cd = sd[o:o + cs]
    q["qe_report"], p = _take(cd, 0, QE_REPORT_LEN, "QE report")
    q["qe_report_sig"], p = _take(cd, p, 64, "QE report signature")
    d, p = _take(cd, p, 2, "QE auth data size")
    (al,) = struct.unpack("<H", d)
    q["qe_auth"], p = _take(cd, p, al, "QE auth data")
    d, p = _take(cd, p, 6, "inner certification data header")
    it, isz = struct.unpack("<HI", d)
    if it != CERT_TYPE_PCK_CHAIN:
        raise QuoteError("inner certification data type %d (expected 5 = PCK certificate chain, PEM)" % it)
    q["pck_pem"], p = _take(cd, p, isz, "PCK chain")
    if p != len(cd):
        raise QuoteError("trailing bytes in certification data")
    return q


# ---------------------------------------------------------------- crypto helpers

def _p256_pub(raw64):
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + bytes(raw64))


def _ecdsa_ok(pubkey, sig64, msg):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r, s = int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big")
    try:
        pubkey.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def _cert_signed_by(cert, issuer):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        return cert.issuer == issuer.subject
    except (InvalidSignature, TypeError, ValueError, AttributeError):
        return False


def replay_rtmr(digests):
    """RTMR extend: start at 48 zero bytes, RTMR = SHA-384(RTMR || digest48) for each event digest (in order)."""
    m = bytes(48)
    for d in digests:
        d = bytes.fromhex(d) if isinstance(d, str) else bytes(d)
        if len(d) != 48:
            raise ValueError("RTMR event digest must be 48 bytes")
        m = hashlib.sha384(m + d).digest()
    return m


DSTACK_RUNTIME_EVENT_TYPE = 0x08000001      # dstack cc-eventlog runtime_events.rs
TCG_EV_NO_ACTION = 0x00000003               # TCG PC Client spec: informational, never extended into a measurement register


def runtime_event_preimage(name, payload, version=1):
    """dstack runtime event digest preimage (dstack/cc-eventlog/src/runtime_events.rs, checked 23.10.2026 at commit 250334c):
      V1: event_type_le(4) || ":" || name || ":" || payload
      V2: JCS(RFC 8785) {"name": name, "payload": hex(payload), "type": 134217729}   (names are plain strings; json sort_keys = JCS here)"""
    if version in (None, 1):
        return struct.pack("<I", DSTACK_RUNTIME_EVENT_TYPE) + b":" + name.encode("utf-8") + b":" + payload
    if version == 2:
        return json.dumps({"name": name, "payload": payload.hex(), "type": DSTACK_RUNTIME_EVENT_TYPE}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    raise ValueError("unknown runtime event version %r" % (version,))


# Runtime event names that dstack legitimately emits several times with DIFFERENT payloads. dstack 0.5.x dstack-util system_setup.rs
# emits "mr-kms" inside the TLS cert_validator of the KMS client, i.e. once per KMS handshake (one per KMS URL tried, plus re-handshakes);
# seen twice with two different values on a real Phala CVM 23.10.2026. Reported as a list; any other name repeated with a different
# payload is ambiguous and refused.
MULTI_VALUED_EVENTS = ("mr-kms",)
EXACTLY_ONCE_EVENTS = ("compose-hash",)


def _hex_field(v, what):
    if v is None:
        return b""
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except ValueError:
            raise ValueError("%s is not hex" % what)
    return bytes(v)


def replay_event_log(events):
    """dstack event log (JSON array of {imr, event_type, digest, event, event_payload, version?, preimage?}; field names checked
    against dstack sdk/python dstack_client_v0.py EventLog and cc-eventlog tdx.rs TdxEvent) -> ({imr: replayed value}, app events).

    Two serialisations exist and both are read:
      - full (Info / Phala API tcb_info.event_log): every event has digest and payload;
      - stripped (GetQuote over dstack.sock, dstack <= 0.5.12 and 0.6.x before 7f3952bb "preserve stripped V2 event digests"):
        TdxEvent::stripped() sets digest = "" for runtime events (derivable) and event_payload = "" for boot events.
    A runtime event's payload is BOUND to its digest here: the digest is ALWAYS recomputed from (event, event_payload, version) and
    that recomputed value is what gets extended; an advertised non-empty digest must equal it (dstack does the same in
    TdxEvent::digest). Without this, a forged log could keep the real digests and carry any "compose-hash" payload. An empty
    advertised digest therefore gives the forger nothing: the replayed RTMR3 still has to equal the quoted one.
    App events are taken ONLY from RTMR3 runtime events. A name repeated with the same payload is accepted (one value); repeated with a
    different payload it is refused, except MULTI_VALUED_EVENTS (value = list in log order); "compose-hash" must occur exactly once
    whenever the log has RTMR3 runtime events."""
    by, app, seen = {}, {}, {}
    rt3 = False
    for e in events:
        imr, et = int(e["imr"]), e.get("event_type")
        et = int(et) if et is not None else None
        if et == TCG_EV_NO_ACTION:
            continue
        adv = _hex_field(e.get("digest"), "digest")
        if et == DSTACK_RUNTIME_EVENT_TYPE:
            name = e.get("event") or ""
            ver = e.get("version")
            pre = runtime_event_preimage(name, _hex_field(e.get("event_payload"), "event_payload"), ver)
            if e.get("preimage") is not None and _hex_field(e["preimage"], "preimage") != pre:
                raise ValueError("runtime event %r: preimage is not the canonical representation" % name)
            d = hashlib.sha384(pre).digest()
            if adv and adv != d:
                raise ValueError("runtime event %r: digest does not match its name/payload" % name)
            if imr == 3:
                rt3 = True
            if imr == 3 and name:
                pl = (e.get("event_payload") or "").lower()
                seen[name] = seen.get(name, 0) + 1
                if name in MULTI_VALUED_EVENTS:
                    app.setdefault(name, []).append(pl)
                elif name in app and (app[name] != pl or name in EXACTLY_ONCE_EVENTS):
                    raise ValueError("runtime event %r appears twice%s" % (name, "" if app[name] == pl else " with different payloads"))
                else:
                    app[name] = pl
        else:
            d = adv
        if len(d) != 48:
            raise ValueError("event %r (imr %d): digest must be 48 bytes" % (e.get("event"), imr))
        by.setdefault(imr, []).append(d)
    if rt3:
        for n in EXACTLY_ONCE_EVENTS:
            if seen.get(n, 0) != 1:
                raise ValueError("runtime event %r must occur exactly once in RTMR3 (found %d)" % (n, seen.get(n, 0)))
    return {i: replay_rtmr(d) for i, d in by.items()}, app


# ---------------------------------------------------------------- TCB status from Intel PCS collateral
# Logic cross-checked 23.10.2026 against Phala dcap-qvl (github.com/Phala-Network/dcap-qvl, commit 837e1fc, src/verify.rs:
# verify_tcb_info_signature, verify_qe_identity_signature, verify_qe_identity_policy, find_tcb_level, evaluate_tdx_tcb,
# verify_tdx_module_identity, match_qe_tcb_level; src/tcb_info.rs: converge_with_component, check_for_relaunch, merge).
# Network is used ONLY by fetch_collateral(); check_tcb() works on the saved files.

PCS_BASE = "https://api.trustedservices.intel.com"
SGX_EXT_OID = "1.2.840.113741.1.13.1"
TCB_STATUSES = ("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDate",
                "OutOfDateConfigurationNeeded", "Revoked")
TDX_MODULE_STATUSES = ("UpToDate", "OutOfDate", "Revoked")
QE_STATUSES = ("UpToDate", "OutOfDate", "ConfigurationNeeded", "Revoked", "OutOfDateConfigurationNeeded")
COLLATERAL_FILES = ("tcb_info.json", "tcb_info_issuer_chain.pem", "qe_identity.json", "qe_identity_issuer_chain.pem",
                    "pck_crl.der", "pck_crl_issuer_chain.pem", "root_ca_crl.der")


class TcbError(ValueError):
    """Collateral is malformed, forged, expired, revoked, or does not fit the quote: tcb_status FAIL."""


def _der_tlv(b, off):
    if off + 2 > len(b):
        raise TcbError("DER truncated")
    tag, ln = b[off], b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + n > len(b):
            raise TcbError("DER length")
        ln, off = int.from_bytes(b[off:off + n], "big"), off + n
    if off + ln > len(b):
        raise TcbError("DER truncated")
    return tag, bytes(b[off:off + ln]), off + ln


def _der_items(b):
    out, off = [], 0
    while off < len(b):
        t, v, off = _der_tlv(b, off)
        out.append((t, v))
    return out


def _oid_str(v):
    parts, n = [min(v[0] // 40, 2), v[0] - 40 * min(v[0] // 40, 2)], 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _oid_map(seq):
    """SEQUENCE OF SEQUENCE {OID, value} -> {oid: (tag, value)}; duplicates refused."""
    out = {}
    for t, v in _der_items(seq):
        items = _der_items(v) if t == 0x30 else []
        if len(items) != 2 or items[0][0] != 0x06:
            raise TcbError("SGX extension: entry is not {OID, value}")
        oid = _oid_str(items[0][1])
        if oid in out:
            raise TcbError("SGX extension: duplicate %s" % oid)
        out[oid] = items[1]
    return out


def pck_extensions(cert):
    """Intel SGX extension of a PCK certificate (OID 1.2.840.113741.1.13.1) -> fmspc, pce_id, cpu_svn (16), pce_svn, sgx_type."""
    from cryptography import x509
    try:
        raw = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(SGX_EXT_OID)).value.value
    except x509.ExtensionNotFound:
        raise TcbError("PCK certificate has no SGX extension")
    t, v, end = _der_tlv(raw, 0)
    if t != 0x30 or end != len(raw):
        raise TcbError("SGX extension is not one SEQUENCE")
    m = _oid_map(v)

    def need(oid, tag, n=None):
        if oid not in m or m[oid][0] != tag or (n is not None and len(m[oid][1]) != n):
            raise TcbError("SGX extension: %s missing or malformed" % oid)
        return m[oid][1]
    tcb = _oid_map(need(SGX_EXT_OID + ".2", 0x30))
    if tcb.get(SGX_EXT_OID + ".2.18", (0,))[0] != 0x04 or len(tcb[SGX_EXT_OID + ".2.18"][1]) != 16:
        raise TcbError("SGX extension: CPUSVN missing")
    if tcb.get(SGX_EXT_OID + ".2.17", (0,))[0] != 0x02:
        raise TcbError("SGX extension: PCESVN missing")
    return {"fmspc": need(SGX_EXT_OID + ".4", 0x04, 6), "pce_id": need(SGX_EXT_OID + ".3", 0x04, 2),
            "cpu_svn": tcb[SGX_EXT_OID + ".2.18"][1], "pce_svn": int.from_bytes(tcb[SGX_EXT_OID + ".2.17"][1], "big"),
            "sgx_type": int.from_bytes(need(SGX_EXT_OID + ".5", 0x0A), "big")}


def _raw_members(s):
    """Top-level members of a JSON object WITH their exact source text (Intel signs the bytes of the member value as served)."""
    dec, ws = json.JSONDecoder(), " \t\r\n"

    def skip(i):
        while i < len(s) and s[i] in ws:
            i += 1
        return i
    i, out = skip(0), {}
    if s[i:i + 1] != "{":
        raise TcbError("collateral JSON is not an object")
    i = skip(i + 1)
    while s[i:i + 1] != "}":
        k, i = dec.raw_decode(s, i)
        i = skip(i)
        if s[i:i + 1] != ":":
            raise TcbError("collateral JSON: ':' expected")
        i = skip(i + 1)
        v, j = dec.raw_decode(s, i)
        if not isinstance(k, str) or k in out:
            raise TcbError("collateral JSON: bad or duplicate key %r" % (k,))
        out[k], i = (v, s[i:j]), skip(j)
        if s[i:i + 1] == ",":
            i = skip(i + 1)
        elif s[i:i + 1] != "}":
            raise TcbError("collateral JSON: ',' or '}' expected")
    if s[skip(i + 1):]:
        raise TcbError("collateral JSON: trailing data")
    return out


def _signed_json(raw, key, signer):
    try:
        mem = _raw_members(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, IndexError) as e:
        raise TcbError("%s: unreadable (%s)" % (key, e))
    if set(mem) != {key, "signature"}:
        raise TcbError("%s: members %s (expected %s, signature)" % (key, sorted(mem), key))
    try:
        sig = bytes.fromhex(mem["signature"][0])
    except (TypeError, ValueError):
        sig = b""
    if len(sig) != 64 or not _ecdsa_ok(signer.public_key(), sig, mem[key][1].encode("utf-8")):
        raise TcbError("%s: signature invalid" % key)
    return mem[key][0]


def _ts(s):
    import datetime
    try:
        d = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        raise TcbError("bad date %r" % (s,))
    if d.tzinfo is None:
        raise TcbError("date without zone %r" % (s,))
    return d.timestamp()


def _window(what, start, end, now):
    if not start <= now <= end:
        raise TcbError("%s outside its validity window (now %d, valid %d..%d)%s" % (what, now, start, end,
                                                                                 ": EXPIRED" if now > end else ""))


def _signing_cert(pem, root, what):
    """TCB Info / QE Identity signer: [signer, root] chain; the signer must be issued DIRECTLY by the pinned root."""
    from cryptography import x509
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except ValueError as e:
        raise TcbError("%s issuer chain: %s" % (what, e))
    if not certs or not _cert_signed_by(certs[0], root):
        raise TcbError("%s signer is not issued by the pinned Intel root" % what)
    return certs[0]


def _converge(s, comp):
    if comp == "Revoked":
        return "Revoked"
    if comp == "OutOfDate" and s in ("UpToDate", "SWHardeningNeeded"):
        return "OutOfDate"
    if comp == "OutOfDate" and s in ("ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded"):
        return "OutOfDateConfigurationNeeded"
    return s


def _relaunch(launch, current):
    cfg = ("ConfigurationNeeded", "OutOfDateConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "TDRelaunchAdvisedConfigurationNeeded")
    if launch in ("OutOfDate", "OutOfDateConfigurationNeeded") and current in ("UpToDate", "SWHardeningNeeded", "ConfigurationNeeded",
                                                                               "ConfigurationAndSWHardeningNeeded"):
        return "TDRelaunchAdvisedConfigurationNeeded" if launch in cfg or current in cfg else "TDRelaunchAdvised"
    return launch


def _masked_eq(actual, expect_hex, mask_hex, what, outside_zero=False):
    exp, mask = bytes.fromhex(expect_hex), bytes.fromhex(mask_hex)
    if len(exp) != len(actual) or len(mask) != len(actual):
        raise TcbError("%s: length mismatch" % what)
    if any((a & m) != (e & m) for a, e, m in zip(actual, exp, mask)):
        raise TcbError("%s mismatch (masked)" % what)
    if outside_zero and any(a & ~m & 0xFF for a, m in zip(actual, mask)):
        raise TcbError("%s has bits outside the mask" % what)


def _tdx_level(ti, cpu_svn, pce_svn, tee):
    """dcap-qvl evaluate_tdx_tcb: first TCB level (canonical order) met by PCK cpu/pce SVN and TEE_TCB_SVN, converged with the
    TDX module level chosen by tee[1] (module version) / tee[0] (module ISVSVN)."""
    def key(lv):
        t = lv["tcb"]
        return ([c["svn"] for c in t["sgxtcbcomponents"]], t["pcesvn"], [c["svn"] for c in t["tdxtcbcomponents"]])
    found = None
    for lv in sorted(ti["tcbLevels"], key=key, reverse=True):
        sgx, pce, tdx = key(lv)
        if len(sgx) != 16 or len(tdx) != 16:
            raise TcbError("TCB level component count")
        if pce_svn < pce or any(a < b for a, b in zip(cpu_svn, sgx)):
            continue
        skip = 2 if tee[1] > 0 else 0                    # module SVNs (0, 1) are judged by the TDX module identity
        if any(a < b for a, b in list(zip(tee, tdx))[skip:]):
            continue
        found = lv
        break
    if found is None:
        raise TcbError("no TCB level of TCB Info matches this platform (PCK SVNs / TEE_TCB_SVN below every level)")
    st, adv, date = found["tcbStatus"], list(found.get("advisoryIDs") or []), found.get("tcbDate")
    if st not in TCB_STATUSES:
        raise TcbError("unknown TCB status %r" % st)
    if tee[1] > 0:
        mid = "TDX_%02X" % tee[1]
        ident = [m for m in ti.get("tdxModuleIdentities") or [] if m.get("id", "").upper() == mid]
        if not ident:
            raise TcbError("no TDX module identity %s in TCB Info" % mid)
        mlv = [m for m in sorted(ident[0]["tcbLevels"], key=lambda m: m["tcb"]["isvsvn"], reverse=True) if tee[0] >= m["tcb"]["isvsvn"]]
        if not mlv:
            raise TcbError("TDX module ISVSVN %d below every level of %s" % (tee[0], mid))
        if mlv[0]["tcbStatus"] not in TDX_MODULE_STATUSES:
            raise TcbError("unknown TDX module status %r" % mlv[0]["tcbStatus"])
        st = _converge(st, mlv[0]["tcbStatus"])
        adv += [a for a in mlv[0].get("advisoryIDs") or [] if a not in adv]
    return st, adv, date


def _tdx_module_identity(ti, body):
    tee = body["tee_tcb_svn"]
    mod = ti.get("tdxModule")
    if not mod:
        raise TcbError("TDX TCB Info has no tdxModule")
    if tee[1] > 0:
        mod = [m for m in ti.get("tdxModuleIdentities") or [] if m.get("id", "").upper() == "TDX_%02X" % tee[1]][0]
    if body["mr_signer_seam"] != bytes.fromhex(mod["mrsigner"]):
        raise TcbError("TDX module MRSIGNER (mr_signer_seam) is not Intel's")
    _masked_eq(body["seam_attributes"], mod["attributes"], mod["attributesMask"], "SEAM attributes", outside_zero=True)


def _qe_level(qe, qi):
    if qi.get("id") != "TD_QE" or qi.get("version") not in (2, 3):
        raise TcbError("QE Identity id/version %r/%r (expected TD_QE 2|3)" % (qi.get("id"), qi.get("version")))
    if qe[128:160] != bytes.fromhex(qi["mrsigner"]):
        raise TcbError("QE MRSIGNER mismatch")
    if qe[48] & 0x02:
        raise TcbError("QE is a debug enclave")
    if int.from_bytes(qe[256:258], "little") != int(qi["isvprodid"]):
        raise TcbError("QE ISVPRODID mismatch")
    _masked_eq(qe[16:20], qi["miscselect"], qi["miscselectMask"], "QE MISCSELECT")
    _masked_eq(qe[48:64], qi["attributes"], qi["attributesMask"], "QE ATTRIBUTES")
    isvsvn = int.from_bytes(qe[258:260], "little")
    for lv in sorted(qi["tcbLevels"], key=lambda x: x["tcb"]["isvsvn"], reverse=True):
        if isvsvn >= lv["tcb"]["isvsvn"]:
            if lv["tcbStatus"] not in QE_STATUSES:
                raise TcbError("unknown QE TCB status %r" % lv["tcbStatus"])
            return lv["tcbStatus"], list(lv.get("advisoryIDs") or []), isvsvn
    raise TcbError("QE ISVSVN %d below every QE Identity level" % isvsvn)


def load_collateral(d):
    import os
    miss = [f for f in COLLATERAL_FILES if not os.path.isfile(os.path.join(d, f))]
    if miss:
        raise TcbError("collateral dir %s lacks %s" % (d, ", ".join(miss)))
    out = {}
    for f in COLLATERAL_FILES:
        with open(os.path.join(d, f), "rb") as fh:
            out[f] = fh.read()
    return out


def check_tcb(q, chain, col, root, now):
    """Offline TCB appraisal. q = parse_quote(), chain = PCK chain (leaf first, already checked up to the pinned root), col =
    {COLLATERAL_FILES: bytes}, root = pinned Intel root certificate, now = unix seconds.
    -> {"status", "advisory_ids", "platform_status", "qe_status", "fmspc", "tcb_date", "tcb_eval_data_number", ...}; raises TcbError."""
    from cryptography import x509
    leaf, pck_ca = chain[0], chain[1]
    try:
        root_crl = x509.load_der_x509_crl(col["root_ca_crl.der"])
        pck_crl = x509.load_der_x509_crl(col["pck_crl.der"])
    except ValueError as e:
        raise TcbError("CRL unreadable: %s" % e)
    if root_crl.issuer != root.subject or not root_crl.is_signature_valid(root.public_key()):
        raise TcbError("root CA CRL is not signed by the pinned Intel root")
    if pck_crl.issuer != pck_ca.subject or not pck_crl.is_signature_valid(pck_ca.public_key()):
        raise TcbError("PCK CRL is not signed by the PCK leaf's issuer (%s)" % pck_ca.subject.rfc4514_string())
    for what, crl in (("root CA CRL", root_crl), ("PCK CRL", pck_crl)):
        if crl.next_update_utc is None:
            raise TcbError("%s has no nextUpdate" % what)
        _window(what, crl.last_update_utc.timestamp(), crl.next_update_utc.timestamp(), now)
    tcb_signer = _signing_cert(col["tcb_info_issuer_chain.pem"], root, "TCB Info")
    qe_signer = _signing_cert(col["qe_identity_issuer_chain.pem"], root, "QE Identity")
    for c in list(chain) + [tcb_signer, qe_signer]:
        _window("certificate " + c.subject.rfc4514_string(), c.not_valid_before_utc.timestamp(), c.not_valid_after_utc.timestamp(), now)
    for c, crl, what in ((leaf, pck_crl, "PCK certificate"), (pck_ca, root_crl, "PCK CA"), (tcb_signer, root_crl, "TCB signing cert"),
                         (qe_signer, root_crl, "QE Identity signing cert")):
        if crl.get_revoked_certificate_by_serial_number(c.serial_number) is not None:
            raise TcbError("%s serial %x is REVOKED (in CRL)" % (what, c.serial_number))
    ti = _signed_json(col["tcb_info.json"], "tcbInfo", tcb_signer)
    qi = _signed_json(col["qe_identity.json"], "enclaveIdentity", qe_signer)
    for what, j in (("TCB Info", ti), ("QE Identity", qi)):
        _window(what, _ts(j["issueDate"]), _ts(j["nextUpdate"]), now)
    if ti.get("id") != "TDX" or int(ti.get("version", 0)) < 3:
        raise TcbError("TCB Info id/version %r/%r is not TDX v3+" % (ti.get("id"), ti.get("version")))
    ext = pck_extensions(leaf)
    if bytes.fromhex(ti["fmspc"]) != ext["fmspc"]:
        raise TcbError("FMSPC mismatch: TCB Info %s, PCK %s" % (ti["fmspc"], ext["fmspc"].hex()))
    if bytes.fromhex(ti["pceId"]) != ext["pce_id"]:
        raise TcbError("PCE ID mismatch: TCB Info %s, PCK %s" % (ti["pceId"], ext["pce_id"].hex()))
    body = q["body"]
    qe_st, qe_adv, qe_svn = _qe_level(q["qe_report"], qi)
    plat_st, plat_adv, tcb_date = _tdx_level(ti, ext["cpu_svn"], ext["pce_svn"], body["tee_tcb_svn"])
    _tdx_module_identity(ti, body)
    st = _converge(plat_st, qe_st)
    adv = plat_adv + [a for a in qe_adv if a not in plat_adv]
    cur = None
    if "tee_tcb_svn2" in body:                           # TD 1.5: the current TCB must be appraisable too (dcap-qvl, Intel QVL)
        cur = _converge(_tdx_level(ti, ext["cpu_svn"], ext["pce_svn"], body["tee_tcb_svn2"])[0], qe_st)
        if cur == "Revoked":
            st = "Revoked"
    if st != "Revoked" and cur is not None:
        st = _relaunch(st, cur)
    return {"status": st, "advisory_ids": adv, "platform_status": plat_st, "qe_status": qe_st, "current_status": cur,
            "fmspc": ext["fmspc"].hex(), "pce_svn": ext["pce_svn"], "cpu_svn": ext["cpu_svn"].hex(), "qe_isvsvn": qe_svn,
            "tee_tcb_svn": body["tee_tcb_svn"].hex(), "tcb_date": tcb_date,
            "tcb_eval_data_number": min(int(ti.get("tcbEvaluationDataNumber", 0)), int(qi.get("tcbEvaluationDataNumber", 0))),
            "tcb_info_next_update": ti["nextUpdate"], "qe_identity_next_update": qi["nextUpdate"]}


def fetch_collateral(quote, out_dir, base=PCS_BASE, timeout=30):
    """THE ONLY NETWORK STEP: download the collateral this quote needs from Intel PCS (free, public, no key) into out_dir.
    Nothing downloaded is trusted: check_tcb verifies every file against the pinned root."""
    import datetime
    import os
    import urllib.parse
    import urllib.request
    from cryptography import x509
    q = parse_quote(quote)
    chain = x509.load_pem_x509_certificates(bytes(q["pck_pem"]).rstrip(b"\x00"))
    fmspc = pck_extensions(chain[0])["fmspc"].hex().upper()
    cn = chain[1].subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    ca = "platform" if "Platform" in cn else "processor"

    def get(url, header=None):
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "deus-tdx-quote"}), timeout=timeout) as r:
            body = r.read()
            hv = r.headers.get(header) if header else None
        if header and not hv:
            raise TcbError("%s: no %s header" % (url, header))
        return body, (urllib.parse.unquote(hv).encode() if hv else None)
    urls = {"tcb": "%s/tdx/certification/v4/tcb?fmspc=%s" % (base, fmspc), "qe": "%s/tdx/certification/v4/qe/identity" % base,
            "pckcrl": "%s/sgx/certification/v4/pckcrl?ca=%s&encoding=der" % (base, ca), "rootcacrl": "%s/sgx/certification/v4/rootcacrl" % base}
    files = {}
    files["tcb_info.json"], files["tcb_info_issuer_chain.pem"] = get(urls["tcb"], "TCB-Info-Issuer-Chain")
    files["qe_identity.json"], files["qe_identity_issuer_chain.pem"] = get(urls["qe"], "SGX-Enclave-Identity-Issuer-Chain")
    files["pck_crl.der"], files["pck_crl_issuer_chain.pem"] = get(urls["pckcrl"], "SGX-PCK-CRL-Issuer-Chain")
    try:
        rc, _ = get(urls["rootcacrl"])
    except OSError:                                      # Intel PCS answers 404 here (a PCCS serves it): use the root's CRL DP
        root = x509.load_pem_x509_certificates(files["qe_identity_issuer_chain.pem"])[-1]
        dp = root.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls["rootcacrl"] = [n.value for p in dp for n in (p.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)][0]
        rc, _ = get(urls["rootcacrl"])
    if rc[:1] != b"\x30":                                # PCS v4 may serve the root CA CRL hex-encoded
        rc = bytes.fromhex(rc.decode().strip())
    files["root_ca_crl.der"] = rc
    os.makedirs(out_dir, exist_ok=True)
    for f, b in files.items():
        with open(os.path.join(out_dir, f), "wb") as fh:
            fh.write(b)
    meta = {"fetched_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "fmspc": fmspc, "pck_ca": ca, "urls": urls}
    with open(os.path.join(out_dir, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=1)
    return meta


# ---------------------------------------------------------------- verification

OK, FAIL, NV = "ok", "FAIL", "NOT VERIFIED"


def verify(quote, expect_report_data=None, expect=None, intel_root_pem=None, event_log=None, collateral=None, now=None):
    """-> {"checks": [(name, status, detail)], "verdict": str, "body": {name: hex}, "app_events": {...}, "tcb": {...} | None}.
    collateral: None (tcb_status NOT VERIFIED), a directory saved by fetch_collateral, or {COLLATERAL_FILES name: bytes};
    now: unix seconds the collateral is judged at (default: the clock).
    verdict, first that applies: "FAIL" (any check failed, incl. bad/expired/revoked collateral or TCB Revoked); "INCOMPLETE" (root,
    measurements or report_data not checked); "TCB_<status>" (everything ok but the TCB is not UpToDate, e.g. TCB_OutOfDate,
    TCB_SWHardeningNeeded: the platform needs an Intel update / config change - NOT ok); "OK" (all checks ok, TCB UpToDate);
    "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED" (no collateral given). Nothing here says the platform is genuine unless intel_root is ok."""
    from cryptography import x509
    checks = []

    def add(n, st, d=""):
        checks.append((n, st, d))
    try:
        q = parse_quote(quote)
    except QuoteError as e:
        add("structure", FAIL, str(e))
        return {"checks": checks, "verdict": "FAIL", "body": {}, "app_events": {}}
    bad = []
    if q["att_key_type"] != ATT_KEY_ECDSA_P256:
        bad.append("attestation key type %d" % q["att_key_type"])
    if q["tee_type"] != TEE_TYPE_TDX:
        bad.append("tee type 0x%x" % q["tee_type"])
    if q["qe_vendor_id"] != INTEL_QE_VENDOR_ID:
        bad.append("QE vendor id %s" % q["qe_vendor_id"].hex())
    add("structure", FAIL if bad else OK, "; ".join(bad) or "v%d body type %d" % (q["version"], q["body_type"]))
    body = q["body"]
    try:
        att = _p256_pub(q["att_pub"])
        add("quote_sig", OK if _ecdsa_ok(att, q["sig"], q["signed"]) else FAIL, "attestation key %s.." % q["att_pub"][:8].hex())
    except ValueError:
        add("quote_sig", FAIL, "attestation key is not a P-256 point")
    qe_rd = q["qe_report"][320:384]
    want = hashlib.sha256(bytes(q["att_pub"]) + bytes(q["qe_auth"])).digest()
    add("qe_binding", OK if qe_rd[:32] == want and qe_rd[32:] == bytes(32) else FAIL, "QE report_data vs SHA-256(att key || auth data)")
    chain = []
    try:
        chain = x509.load_pem_x509_certificates(bytes(q["pck_pem"]).rstrip(b"\x00"))
    except ValueError as e:
        chain = []
        add("pck_chain", FAIL, "PEM: %s" % e)
    if chain:
        try:
            ok = _ecdsa_ok(chain[0].public_key(), q["qe_report_sig"], q["qe_report"])
        except Exception:  # noqa: a leaf that is not an EC key
            ok = False
        add("qe_report_sig", OK if ok else FAIL, "by PCK leaf %s" % chain[0].subject.rfc4514_string())
        links = [_cert_signed_by(chain[i], chain[i + 1]) for i in range(len(chain) - 1)]
        top = chain[-1]
        self_signed = _cert_signed_by(top, top)
        add("pck_chain", OK if (len(chain) >= 2 and all(links) and self_signed) else FAIL,
            "%d certificates, links %s, top self-signed %s" % (len(chain), links, self_signed))
        if intel_root_pem:
            pinned = x509.load_pem_x509_certificate(intel_root_pem)
            same = pinned.public_bytes(_der()) == top.public_bytes(_der())
            add("intel_root", OK if same else FAIL, "chain top vs pinned root %s" % pinned.subject.rfc4514_string())
        else:
            add("intel_root", NV, "no pinned Intel SGX Root CA given: the chain may be self-made")
    elif not any(c[0] == "pck_chain" for c in checks):
        add("pck_chain", FAIL, "no certificates")
    tcb = None
    if collateral is None:
        add("tcb_status", NV, "no Intel PCS collateral given (fetch it once: --fetch-collateral DIR)")
    elif not intel_root_pem or not chain or len(chain) < 2:
        add("tcb_status", NV, "collateral needs the pinned Intel root and a PCK chain")
    else:
        import time
        try:
            col = load_collateral(collateral) if isinstance(collateral, str) else collateral
            tcb = check_tcb(q, chain, col, x509.load_pem_x509_certificate(intel_root_pem), time.time() if now is None else now)
            st = tcb["status"]
            add("tcb_status", OK if st == "UpToDate" else FAIL if st == "Revoked" else st,
                "%s; advisories %s; FMSPC %s, TCB eval #%d, tcbDate %s (platform %s, QE %s)" % (
                    st, ",".join(tcb["advisory_ids"]) or "none", tcb["fmspc"], tcb["tcb_eval_data_number"], tcb["tcb_date"],
                    tcb["platform_status"], tcb["qe_status"]))
        except (TcbError, KeyError, TypeError, ValueError, IndexError) as e:
            add("tcb_status", FAIL, "collateral: %s" % (e if isinstance(e, TcbError) else "malformed (%s: %s)" % (type(e).__name__, e)))
    attrs = int.from_bytes(body["td_attributes"], "little")
    add("debug", FAIL if attrs & TD_ATTR_DEBUG else OK, "td_attributes %s" % body["td_attributes"].hex())
    if expect_report_data is not None:
        add("report_data", OK if body["report_data"] == bytes(expect_report_data) else FAIL,
            "quote %s.. vs expected %s.." % (body["report_data"][:8].hex(), bytes(expect_report_data)[:8].hex()))
    else:
        add("report_data", NV, "no expected report_data given")
    app_events = {}
    if event_log is not None:
        try:
            rep, app_events = replay_event_log(event_log)
            mism = [i for i, v in rep.items() if body.get("rtmr%d" % i) != v]
            add("event_log", FAIL if mism else OK, "replayed RTMR %s; mismatch %s" % (sorted(rep), mism))
        except (KeyError, ValueError, TypeError) as e:
            add("event_log", FAIL, "unreadable: %s" % e)
    if expect:
        miss = []
        expect = {k: v for k, v in expect.items() if not k.startswith("_")}     # "_comment", "_os_image": notes for humans, not checked
        for k, v in sorted(expect.items()):
            if k == "app_events":
                for ek, ev in v.items():
                    got = app_events.get(ek)
                    if isinstance(got, list):      # multi-valued (mr-kms): expect = allowed value or list; EVERY logged value must be allowed
                        allowed = {str(x).lower() for x in (ev if isinstance(ev, list) else [ev])}
                        if not got or any(x not in allowed for x in got):
                            miss.append("%s=%s" % (ek, got))
                    elif isinstance(ev, list) or got != str(ev).lower():
                        miss.append("%s=%s" % (ek, got))
                continue
            if k not in MEASUREMENT_FIELDS:
                miss.append("unknown field %s" % k)
            elif body[k].hex() != v.lower():
                miss.append(k)
        add("measurements", FAIL if miss else OK, ("mismatch: " + ", ".join(miss)) if miss else "%d fields equal" % len(expect))
    else:
        add("measurements", NV, "no expected measurements given: the code inside the TD is unknown")
    tcb_st = [c[1] for c in checks if c[0] == "tcb_status"][0]
    if any(c[1] == FAIL for c in checks):
        verdict = "FAIL"
    elif any(c[0] in ("intel_root", "measurements", "report_data") and c[1] == NV for c in checks):
        verdict = "INCOMPLETE"
    elif tcb_st == OK:
        verdict = "OK"
    elif tcb_st != NV:
        verdict = "TCB_" + tcb_st
    else:
        verdict = "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED"
    return {"checks": checks, "verdict": verdict, "body": {k: v.hex() for k, v in body.items()}, "app_events": app_events, "tcb": tcb}


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def main(argv=None):
    import argparse
    import base64
    ap = argparse.ArgumentParser(description="Offline check of a TDX quote bound to a Deus Witness key")
    ap.add_argument("quote", help="quote file: raw bytes, or JSON {quote_b64|quote_hex, event_log} as served by /v1/witness")
    ap.add_argument("--pub", help="witness public key, hex (from /v1/witness pub_hex)")
    ap.add_argument("--collateral-dir", help="Intel PCS collateral saved by --fetch-collateral; the TCB check is offline over these files")
    ap.add_argument("--fetch-collateral", action="store_true", help="ONLY download the collateral into --collateral-dir (network), then exit")
    ap.add_argument("--now", help="judge the collateral at this time (unix seconds or RFC 3339), default: now")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--iss")
    g.add_argument("--batch")
    ap.add_argument("--t", type=int)
    ap.add_argument("--root")
    ap.add_argument("--expect", help="JSON {mr_td, rtmr0..3, ..., app_events: {compose-hash: ...}}")
    ap.add_argument("--intel-root", help="pinned Intel SGX Root CA, PEM")
    o = ap.parse_args(argv)
    raw = open(o.quote, "rb").read()
    ev = None
    if raw[:1] == b"{":
        j = json.loads(raw)
        j = j.get("attestation", j) if isinstance(j.get("attestation"), dict) else j     # the whole /v1/witness answer is accepted too
        raw = base64.b64decode(j["quote_b64"]) if "quote_b64" in j else bytes.fromhex(j["quote_hex"])
        ev = j.get("event_log")
        if isinstance(ev, str):
            ev = json.loads(ev)
    if o.fetch_collateral:
        if not o.collateral_dir:
            ap.error("--fetch-collateral needs --collateral-dir")
        print(json.dumps(fetch_collateral(raw, o.collateral_dir), indent=1))
        return 0
    if not o.pub or (o.iss is None and o.batch is None):
        ap.error("--pub and one of --iss/--batch are required")
    pub = bytes.fromhex(o.pub)
    if o.iss is not None:
        if o.t is None:
            ap.error("--iss needs --t")
        rd = report_data(pub, ctx_boot(o.iss, o.t))
    else:
        if not o.root:
            ap.error("--batch needs --root")
        rd = report_data(pub, ctx_batch(o.batch, bytes.fromhex(o.root)))
    expect = json.load(open(o.expect)) if o.expect else None
    root = open(o.intel_root, "rb").read() if o.intel_root else None
    now = None
    if o.now:
        now = float(o.now) if o.now.replace(".", "", 1).isdigit() else _ts(o.now)
    r = verify(raw, rd, expect, root, ev, o.collateral_dir, now)
    for n, st, d in r["checks"]:
        print("%-14s %-13s %s" % (n, st, d))
    if r["tcb"]:
        print("tcb:", json.dumps(r["tcb"], sort_keys=True))
    print("verdict:", r["verdict"])
    return 0 if r["verdict"] in ("OK", "STRUCTURE_AND_BINDING_OK_TCB_NOT_VERIFIED") else 1


if __name__ == "__main__":
    sys.exit(main())
