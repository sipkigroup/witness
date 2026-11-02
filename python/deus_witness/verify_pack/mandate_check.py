"""0.2.52: "the decision is inside the mandate", checked offline by the public checker (not only "the signatures hold").

  * Verdict replay. aar_ref/decide.py is the witness's decision rules (the same bytes the server runs and puts into every pack as
    verify/, open-repo naming): aar_ref/state.py re-decides every RECEIPT entry from the signed mandate, the recorded action and the ledger
    state before it (expiry, revocation, recipients, per-action limit, budget and ceiling windows, classes, counts, allowances) and
    answers VERDICT_NOT_REPRODUCIBLE when the witness recorded another verdict or reason. decide_lines() reports what that covers.
  * What is NOT replayable. The action fields themselves (class, recipient, data tags) are the witness's classification of the tool call.
    For class `command` the fields that decide (command identifier, `dangerous`, `exec_changed`, `sandboxed`) come from the server's shell
    parser, which is not in this package and not portable: such a decision is replayed FROM the recorded fields, the classification is
    not. Code NOT_REPLAYABLE (a warning line, never a silent VALID).
  * The shown object (presentation view, pv2810). An approval signs SHA-256 over the RFC 8785 (JCS) form of what the page showed. When the
    evidence carries the view object (pack: views/<rid>.json, views/allowance-<id>.json; bundle: `views`), its hash must be the signed
    one (VIEW_MISMATCH), and a view object for an approval that signed none is VIEW_NOT_SIGNED. Without the object the hash cannot be
    tied to anything: VIEW_UNVERIFIABLE (a warning; INVALID with --require-views). 0.2.84 (R5): the walk is over the SIGNED records
    (every APPROVAL, ALLOWANCE and signed release advisory/<rid>.json -> views/release-<rid>.json), not over the files present; a release
    page that signed no hash is VIEW_NOT_SIGNED under --require-views; a repeated member name in a view file is MALFORMED (I-JSON);
    two signed records of one id are VIEW_DUPLICATE; files under views/ that are not read are warning VIEW_EXTRA_FILE.
  * check_bundle(): Mandate Receipt v0 conformance bundles (spec/conformance, `mr-bundle-0`: bundle.cbor + vector.json with the trust
    anchors). Last line RESULT: VALID | RESULT: UNPROVEN <CODES> (valid signatures and decisions, but a warning above) | RESULT: INVALID <CODE>.
"""
import hashlib
import json
import math
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

NOT_REPLAYABLE_CLASSES = {"command": "the shell parser of the server (command identifier, dangerous, exec_changed, sandboxed)"}


# ---- RFC 8785 (JCS), byte-equal to the server's signview.jcs and the page's signview.js -------------------------------------------
def _num(x):
    """RFC 8785 3.2.2.3 = ECMAScript Number::toString (R5-V6, 0.2.84): the shortest round-trip digits, plain notation from 1e-6
    up to 1e21, exponent form outside; an integer-valued float prints its shortest digits padded with zeros, never its exact binary value."""
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            raise ValueError("JCS: integer outside the IEEE-754 exact range")
        return str(x)
    if not math.isfinite(x):
        raise ValueError("JCS: not a finite number")
    if x == 0:
        return "0"
    sign, r = ("-", repr(-x)) if x < 0 else ("", repr(x))
    m, _, e = r.partition("e")
    ip, _, fp = m.partition(".")
    digits = (ip + fp).lstrip("0")
    n = len(ip.lstrip("0")) + int(e or 0) if ip.lstrip("0") else int(e or 0) - (len(fp) - len(fp.lstrip("0")))
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))
    return sign + out


def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v):
    def enc(x):
        if x is None:
            return "null"
        if isinstance(x, (bool, int, float)):
            return _num(x)
        if isinstance(x, str):
            return _str(x)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            if not all(isinstance(k, str) for k in x):
                raise ValueError("JCS: member names are strings")
            ks = sorted(x, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(_str(k) + ":" + enc(x[k]) for k in ks) + "}"
        raise ValueError("JCS: %s is not JSON" % type(x).__name__)
    return enc(v).encode("utf-8", "surrogatepass")


def view_digest(obj):
    return hashlib.sha256(jcs(obj)).digest()


# ---- what the ledger pass replayed ------------------------------------------------------------------------------------------------
def decide_lines(entries):
    """-> (lines, warnings). Call only after the ledger pass answered valid (then every verdict below was re-decided and matched)."""
    by_v, nr = {}, {}
    for e in entries:
        if e.get("type") != "RECEIPT" or not isinstance(e.get("body"), dict):
            continue
        b = e["body"]
        by_v[b.get("verdict")] = by_v.get(b.get("verdict"), 0) + 1
        c = (b.get("action") or {}).get("class") if isinstance(b.get("action"), dict) else None
        if c in NOT_REPLAYABLE_CLASSES:
            nr[c] = nr.get(c, 0) + 1
    n = sum(by_v.values())
    lines = ["decisions: %d/%d replayed against the signed mandate (allow %d, defer %d, deny %d): same verdict and reason"
             % (n, n, by_v.get("allow", 0), by_v.get("defer", 0), by_v.get("deny", 0))]
    warns = []
    for c, k in sorted(nr.items()):
        lines.append("decisions: NOT_REPLAYABLE %d `%s` decisions: the verdict is replayed from the recorded fields, the fields come from %s, "
                     "not in this package" % (k, c, NOT_REPLAYABLE_CLASSES[c]))
        warns.append("NOT_REPLAYABLE")
    return lines, warns


# ---- the shown object ---------------------------------------------------------------------------------------------------------------
def _signed_views(entries):
    """-> [(key, label, view hash bytes | None)] for every APPROVAL (each one is owner-signed: ledger step 4) and every ALLOWANCE."""
    out = []
    for e in entries:
        b = e.get("body") if isinstance(e.get("body"), dict) else {}
        if e.get("type") == "ALLOWANCE" and isinstance(b.get("allowance"), dict):
            out.append(("allowance-%s" % b["allowance"].get("id"), "allowance %s" % b["allowance"].get("id"), b["allowance"].get("view")))
        elif e.get("type") == "APPROVAL":
            out.append((str(b.get("receipt")), "approval %s" % b.get("receipt"), b.get("view")))
    return out


def view_checks(entries, views, require=False, cap=50):
    """views: {key: object} (key = receipt id, or "allowance-<id>"). -> (lines, invalid code | None, warnings)."""
    lines, warns, n_ok = [], [], 0
    sv = _signed_views(entries)
    seen = set()
    for key, label, _ in sv:          # R5-V5 (0.2.84): one view object per key cannot stand for two signed records of that key
        if key in seen:
            lines.append("%s: VIEW_DUPLICATE (two owner-signed records of one receipt / allowance id; the evidence carries one view object "
                         "per id, so what each of them showed cannot be told apart)" % label)
            return lines, "VIEW_DUPLICATE", warns
        seen.add(key)
    for key, label, vh in sv:
        signed = isinstance(vh, bytes) and len(vh) == 32
        has = key in views
        if not signed:
            if has or require:
                lines.append("%s: VIEW_NOT_SIGNED (%s)" % (label, "a view object is in the evidence, the owner's signature names none"
                                                          if has else "no presentation hash signed: an older approval page"))
                return lines, "VIEW_NOT_SIGNED", warns
            if len(warns) < cap:
                lines.append("%s: warning VIEW_NOT_SIGNED (an older approval page: what was shown is not tied to the signature)" % label)
            warns.append("VIEW_NOT_SIGNED")
            continue
        if not has:
            if require:
                lines.append("%s: VIEW_UNVERIFIABLE (view sha256 %s signed, the view object is not in the evidence)" % (label, vh.hex()[:16]))
                return lines, "VIEW_UNVERIFIABLE", warns
            if len(warns) < cap:
                lines.append("%s: warning VIEW_UNVERIFIABLE (view sha256 %s signed, the view object is not in the evidence)" % (label, vh.hex()[:16]))
            warns.append("VIEW_UNVERIFIABLE")
            continue
        try:
            good = view_digest(views[key]) == vh
        except (ValueError, TypeError, RecursionError):
            good = False
        if not good:
            lines.append("%s: VIEW_MISMATCH (the view object in the evidence does not hash to the signed view)" % label)
            return lines, "VIEW_MISMATCH", warns
        n_ok += 1
    known = seen
    stray = sorted(k for k in views if k not in known and not k.startswith("release-"))
    if stray:
        lines.append("views: VIEW_NOT_SIGNED (a view object for no signed approval: %s)" % ", ".join(stray[:5]))
        return lines, "VIEW_NOT_SIGNED", warns
    if n_ok or warns:
        lines.append("views: %d shown object(s) hash to the presentation hash the owner signed; %d without a checkable object%s"
                     % (n_ok, len(warns), "" if len(warns) <= cap else " (first %d listed)" % cap))
    return lines, None, warns


def _signed_releases(root):
    """advisory/<rid>.json -> {rid: view_sha256 str | None}: every person-signed release (or rejection) of a held action in the pack
    (verify_pack checks each envelope; an unreadable one fails the pack there). None = the release page signed no presentation hash."""
    out = {}
    d = os.path.join(root, "advisory")
    if not os.path.isdir(d):
        return out
    for f in sorted(os.listdir(d)):
        if not f.endswith(".json") or f.startswith("."):
            continue
        try:
            with open(os.path.join(d, f), "rb") as fh:
                vh = loads_ijson(fh.read().decode("utf-8")).get("view_sha256")
        except (OSError, ValueError, AttributeError, UnicodeDecodeError, RecursionError):
            vh = None
        out[f[:-5]] = vh if isinstance(vh, str) else None
    return out


def release_view_checks(root, views, require=False, cap=50):
    """R5-V1/V2 (0.2.84): walks the SIGNED releases (advisory/<rid>.json, the person's signature over `view_sha256` checked by verify_pack),
    not the files in views/. views/release-<rid>.json is the object that page showed. A signed hash without its object is warning
    VIEW_UNVERIFIABLE, a release page that signed no hash is warning VIEW_NOT_SIGNED; with --require-views both are INVALID, as for an
    approval. -> (lines, invalid code | None, warnings)."""
    lines, warns, n = [], [], 0
    signed = _signed_releases(root)
    for key in sorted(k for k in views if k.startswith("release-")):
        rid = key[len("release-"):]
        if signed.get(rid) is None:
            lines.append("release %s: VIEW_NOT_SIGNED (a view object is in the pack, no signed release names a presentation hash)" % rid)
            return lines, "VIEW_NOT_SIGNED", warns
    for rid, vh in sorted(signed.items()):
        key = "release-" + rid
        if vh is None:
            if require:
                lines.append("release %s: VIEW_NOT_SIGNED (no presentation hash signed: an older release page)" % rid)
                return lines, "VIEW_NOT_SIGNED", warns
            if len(warns) < cap:
                lines.append("release %s: warning VIEW_NOT_SIGNED (an older release page: what was shown is not tied to the signature)" % rid)
            warns.append("VIEW_NOT_SIGNED")
            continue
        if key not in views:
            if require:
                lines.append("release %s: VIEW_UNVERIFIABLE (view sha256 %s signed, the view object is not in the pack)" % (rid, vh[:16]))
                return lines, "VIEW_UNVERIFIABLE", warns
            if len(warns) < cap:
                lines.append("release %s: warning VIEW_UNVERIFIABLE (view sha256 %s signed, the view object is not in the pack)" % (rid, vh[:16]))
            warns.append("VIEW_UNVERIFIABLE")
            continue
        try:
            good = view_digest(views[key]).hex() == vh.lower()
        except (ValueError, TypeError, RecursionError):
            good = False
        if not good:
            lines.append("release %s: VIEW_MISMATCH (the view object in the pack does not hash to the signed view)" % rid)
            return lines, "VIEW_MISMATCH", warns
        n += 1
    if n or warns:
        lines.append("views: %d release page object(s) hash to the presentation hash the person signed; %d signed release(s) without a "
                     "checkable object%s" % (n, len(warns), "" if len(warns) <= cap else " (first %d listed)" % cap))
    return lines, None, warns


def _no_duplicate_names(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("I-JSON: duplicate member name %r (RFC 8785 input is I-JSON, RFC 7493 2.3)" % k[:40])
        d[k] = v
    return d


def loads_ijson(text):
    """json.loads that refuses a repeated member name at any depth (R5-V3, 0.2.84): a reader keeping the FIRST value would see another
    object than the one hashed."""
    return json.loads(text, object_pairs_hook=_no_duplicate_names)


def pack_views(root):
    """views/<key>.json of an unpacked evidence pack -> {key: object}. Absent folder = {} (packs up to server 0.2.81 carry none)."""
    out = {}
    d = os.path.join(root, "views")
    if not os.path.isdir(d):
        return out
    for f in sorted(os.listdir(d)):
        if f.endswith(".json") and not f.startswith("."):
            with open(os.path.join(d, f), "rb") as fh:
                out[f[:-5]] = loads_ijson(fh.read().decode("utf-8"))
    return out


def views_extra(root, manifest_files=None):
    """R5-V4 (0.2.84): files under views/ that are not read as a shown object (not `<key>.json`, hidden, nested) and files the signed
    manifest does not list. A warning line each, never silence: a forged `views/<rid>.json.bak` beside the honest object is named.
    -> (lines, warnings)."""
    d = os.path.join(root, "views")
    if not os.path.isdir(d):
        return [], []
    listed = set(manifest_files or ())
    skipped, unlisted = [], []
    for dp, dns, fs in os.walk(d):
        dns.sort()
        for f in sorted(fs):
            rel = os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/")
            if dp != d or not f.endswith(".json") or f.startswith("."):
                skipped.append(rel)
            elif manifest_files is not None and rel not in listed:
                unlisted.append(rel)
    lines = []
    if skipped:
        lines.append("views: warning VIEW_EXTRA_FILE %d file(s) not read as a shown object (not views/<key>.json): %s"
                     % (len(skipped), ", ".join(skipped[:5])))
    if unlisted:
        lines.append("views: warning VIEW_EXTRA_FILE %d file(s) not in the signed manifest: %s" % (len(unlisted), ", ".join(unlisted[:5])))
    return lines, ["VIEW_EXTRA_FILE"] if lines else []


# ---- Mandate Receipt v0 bundles ---------------------------------------------------------------------------------------------------
def _imports():
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    from aar_ref import cose
    from aar_ref.aar import tool_accept
    from aar_ref.verify import load_entries, verify_file
    from registry_wa import WaRegistry
    return cose, tool_accept, load_entries, verify_file, WaRegistry


def check_bundle(vdir, require_views=False):
    """-> (lines, invalid code | None, warnings). Trust anchors come from vector.json (`trust`), never from the bundle."""
    cose, tool_accept, load_entries, verify_file, WaRegistry = _imports()
    with open(os.path.join(vdir, "vector.json"), encoding="utf-8") as f:
        trust = json.load(f)["trust"]
    with open(os.path.join(vdir, "bundle.cbor"), "rb") as f:
        b = cose.loads(f.read())
    out = []
    wk = cose.Key.public(cose.ALG_EDDSA, bytes.fromhex(trust["witness_pub"]))
    if b.get("witness_kid") != wk.kid:
        out.append("witness: the bundle names another kid than the pinned one (every signature is checked against the pinned key only)")
    reg = WaRegistry.for_account(b["principal"], trust["principal_key"])
    with tempfile.TemporaryDirectory() as td:
        lp = os.path.join(td, "ledger.cose")
        with open(lp, "wb") as f:
            for raw in b["ledger"]:
                f.write(raw.hex().encode() + b"\n")
        presented = [{"aar": p["aar"], "proof": p.get("proof")} for p in b.get("presented", [])]
        r = verify_file(lp, [wk], [], reg, b["principal"], checkpoint=b.get("checkpoint"), require_cose=True, presented=presented or None)
        if r["result"] != "valid":
            out.append("ledger: invalid %s%s" % (r["reason"], ("@%s" % r["at"]) if "at" in r else ""))
            return out, r["reason"], []
        entries = load_entries(lp, [wk])
    out.append("ledger: valid (%d entries)" % len(entries))
    dl, warns = decide_lines(entries)
    out += dl
    vl, why, vw = view_checks(entries, b.get("views") or {}, require_views)
    out += vl
    warns += vw
    if why:
        return out, why, warns
    replay = set()
    for p in b.get("presented", []):
        for _ in range(p.get("times", 1)):
            res = tool_accept(p["aar"], [wk], p["audience"], p["request"], b["now"], p.get("proof"), True, replay=replay)
            if res["result"] != "accept":
                out.append("receipt: rejected %s" % res["reason"])
                return out, res["reason"], warns
        out.append("receipt: accepted (audience %s)" % p["audience"])
    return out, None, warns


def result_line(why, warns):
    if why is not None:
        return "RESULT: INVALID %s" % why
    if warns:
        return "RESULT: UNPROVEN %s" % ",".join(sorted(set(warns)))
    return "RESULT: VALID"


def main_bundle(argv):
    """`deus-witness-verify-pack <vector dir> [--require-views]` -> exit 0 VALID, 1 INVALID, 3 UNPROVEN."""
    vd = [a for a in argv if not a.startswith("--")][0]
    try:
        lines, why, warns = check_bundle(vd, "--require-views" in argv)
    except Exception as e:  # noqa: BLE001  any unreadable input is INVALID, never a crash
        lines, why, warns = ["error: %s" % type(e).__name__], "MALFORMED", []
    for x in lines:
        print(x)
    print(result_line(why, warns))
    return 1 if why is not None else 3 if warns else 0


def is_bundle(path):
    return os.path.isdir(path) and os.path.isfile(os.path.join(path, "bundle.cbor")) and os.path.isfile(os.path.join(path, "vector.json")) \
        and not os.path.isfile(os.path.join(path, "manifest.json"))
