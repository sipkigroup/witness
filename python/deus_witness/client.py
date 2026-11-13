"""Deus Witness SDK (Python). Minimal, self-contained AAR check (draft-deus-aar-04 Section 8) (no server code)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import re

import cbor2
import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import _compat

DEFAULT_URL = "https://witness.sipkigroup.com"
TYP_AAR = "application/aar-receipt+cbor"
ALG_EDDSA = -8
# r0286 (crypto agility, POSTKVANT-1311): the COSE algorithms this client verifies, by the pinned key's type (an Ed25519 key is 32 bytes).
# A receipt whose alg is not in the list of the pinned key is ALG_MISMATCH; a pinned key of a type this client cannot use (another length,
# e.g. a future ML-DSA-65 key) is ALG_UNSUPPORTED -- "cannot check", never accepted, never a crash.
SIG_ALGS = {32: (ALG_EDDSA,)}
H_ALG, H_KID, H_TYP = 1, 4, 16
AGENT_PATHS = ("/v1/actions", "/v1/catalog", "/v1/coverage", "/v1/hook/", "/v1/salt")     # paths that carry the agent key


class WitnessError(Exception):
    """HTTP-level error of the witness API (status, code e.g. BAD_KEY, RATE_LIMIT, QUOTA, NOT_FOUND) or network failure (status 0)."""

    def __init__(self, status: int, code: str, detail: str = "", retry_after: Optional[float] = None):
        super().__init__("%s %s %s" % (status, code, detail))
        self.status, self.code, self.detail = status, code, detail
        self.retry_after = retry_after       # seconds from a Retry-After header (429/503), else None


def busy(e) -> bool:
    """r0285: the witness refused only because it is busy at this moment, before doing anything: too many requests of this key / account
    at once (429 RATE_LIMIT "... at a time"), or the whole server (503 OVERLOADED). Not: the per-minute rate, the daily quota (429 QUOTA)."""
    st, code = getattr(e, "status", None), getattr(e, "code", None)
    return (st == 429 and code == "RATE_LIMIT" and "at a time" in str(getattr(e, "detail", ""))) or (st == 503 and code == "OVERLOADED")


class WitnessKeyChanged(Exception):
    """The witness key differs from the one pinned at first use."""


class WitnessNotPinned(WitnessKeyChanged):
    """0.2.32 (K1): the URL has no pinned key and this client may not pin a new one silently (pin_new=False): another witness is already
    pinned on this machine, so a new URL is a different witness, not a first use."""


class AARError(Exception):
    """str(e) is a reason code: MALFORMED, TYP_MISMATCH, KID_UNKNOWN, ALG_MISMATCH, ALG_UNSUPPORTED (r0286: the pinned key is of a type
    this client cannot verify), SIGNATURE_INVALID, NOT_ALLOWED, REQUEST_MISMATCH, RECEIPT_EXPIRED, AUDIENCE, NO_RECEIPT."""


@dataclass
class ActionResult:
    rid: str
    verdict: str
    reason: str
    status: str
    action: Optional[dict] = None
    expires: Optional[int] = None
    aar_b64: Optional[str] = None
    proof: Optional[dict] = None
    approval_url: Optional[str] = None
    raw: dict = field(default_factory=dict, repr=False)

    @staticmethod
    def from_json(d: dict) -> "ActionResult":
        return ActionResult(rid=d["rid"], verdict=d["verdict"], reason=d.get("reason", ""), status=d.get("status", ""),
                            action=d.get("action"), expires=d.get("expires"), aar_b64=d.get("aar_b64"), proof=d.get("proof"),
                            approval_url=d.get("approval_url"), raw=d)

    @property
    def aar(self) -> Optional[bytes]:
        return b64u_dec(self.aar_b64) if self.aar_b64 else None


def b64u_dec(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _plain(x):
    if isinstance(x, cbor2.CBORTag):
        return cbor2.CBORTag(x.tag, _plain(x.value))
    if isinstance(x, (list, tuple)):
        return [_plain(i) for i in x]
    if hasattr(x, "items") and not isinstance(x, (bytes, str)):
        return {k: _plain(v) for k, v in x.items()}
    return x


def _pub_bytes(pub) -> bytes:
    if isinstance(pub, str):
        try:
            pub = bytes.fromhex(pub)
        except ValueError:
            raise AARError("KID_UNKNOWN")
    if not isinstance(pub, (bytes, bytearray)) or not pub:
        raise AARError("KID_UNKNOWN")
    if len(pub) not in SIG_ALGS:              # r0286: a key of another algorithm: this client cannot check it (not "invalid", not "valid")
        raise AARError("ALG_UNSUPPORTED")
    return bytes(pub)


def _kid(pub: bytes) -> bytes:
    """COSE Key Thumbprint (RFC 9679) of an Ed25519 key."""
    return hashlib.sha256(cbor2.dumps({1: 1, -1: 6, -2: pub}, canonical=True)).digest()


_TOOLMAP_KEY = "toolmap_sha256"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def cbor_form(x):
    """Canonicalisation of the action for the request hash (same as server app/wire.cbor_form and web/js/cde.js, draft-deus-aar-05 8.6):
    ONLY the top-level member `toolmap_sha256`, when it is exactly 64 lower-case hex (no newline), becomes `bstr .size 32`."""
    if isinstance(x, dict) and isinstance(x.get(_TOOLMAP_KEY), str) and _HEX64.fullmatch(x[_TOOLMAP_KEY]):
        return dict(x, **{_TOOLMAP_KEY: bytes.fromhex(x[_TOOLMAP_KEY])})
    return x


def request_hash(action: dict) -> bytes:
    return hashlib.sha256(cbor2.dumps(cbor_form(dict(action)), canonical=True)).digest()


def verify_aar(aar_bytes: Optional[bytes], witness_pub, expect_request: dict, now: Optional[int] = None,
               audience: Optional[str] = None) -> dict:
    """Check a receipt (AAR, COSE_Sign1 Ed25519) against the pinned witness key and `expect_request` (the action map the SERVER returned; whether that is the call you sent is checked by Witness.check(sent=...), R-09).
    Returns the AAR map; raises AARError(code). Checks: structure, typ, alg/kid, signature, decision == allow,
    binding_request_hash == SHA-256(CDE(expect_request)), not expired, optional audience."""
    if not aar_bytes:
        raise AARError("NO_RECEIPT")
    pub = _pub_bytes(witness_pub)
    try:
        t = _plain(cbor2.loads(aar_bytes))
        if not (isinstance(t, cbor2.CBORTag) and t.tag == 18 and isinstance(t.value, list) and len(t.value) == 4):
            raise ValueError
        pb, _un, payload, sig = t.value
        if not (isinstance(pb, bytes) and isinstance(payload, bytes) and isinstance(sig, bytes)):
            raise ValueError
        prot = _plain(cbor2.loads(pb))
        if cbor2.dumps(prot, canonical=True) != pb:
            raise ValueError
        aar = _plain(cbor2.loads(payload))
        if cbor2.dumps(aar, canonical=True) != payload:
            raise ValueError
    except AARError:
        raise
    except Exception:
        raise AARError("MALFORMED")
    if prot.get(H_ALG) is None or prot.get(H_KID) is None:
        raise AARError("MALFORMED")
    if prot.get(H_TYP) != TYP_AAR:
        raise AARError("TYP_MISMATCH")
    if prot[H_KID] != _kid(pub):
        raise AARError("KID_UNKNOWN")
    if prot[H_ALG] not in SIG_ALGS[len(pub)]:
        raise AARError("ALG_MISMATCH")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(
            sig, cbor2.dumps(["Signature1", pb, b"", payload], canonical=True))
    except (InvalidSignature, ValueError):
        raise AARError("SIGNATURE_INVALID")
    try:
        if aar["verdict"]["decision"] != "allow":
            raise AARError("NOT_ALLOWED")
        if audience is not None and aar["audience"] != audience:
            raise AARError("AUDIENCE")
        if aar["action"]["binding_request_hash"] != request_hash(expect_request):
            raise AARError("REQUEST_MISMATCH")
        if (now if now is not None else time.time()) > aar["expires"]:
            raise AARError("RECEIPT_EXPIRED")
    except (KeyError, TypeError):
        raise AARError("MALFORMED")
    return aar


TYP_SCANLIST = "application/dw-scanlist+cbor"
TYP_STATEMENT = "application/dw-hook-judge+cbor"       # 0.2.17 (R9-01): the witness' signed statement of one judge answer


def open_signed(data: bytes, witness_pub, typ: str) -> bytes:
    """0.2.16: a COSE_Sign1 of the witness of type `typ` (e.g. the fingerprint list) -> its payload; AARError(code) otherwise."""
    pub = _pub_bytes(witness_pub)
    try:
        t = _plain(cbor2.loads(data))
        if not (isinstance(t, cbor2.CBORTag) and t.tag == 18 and isinstance(t.value, list) and len(t.value) == 4):
            raise ValueError
        pb, _un, payload, sig = t.value
        if not (isinstance(pb, bytes) and isinstance(payload, bytes) and isinstance(sig, bytes)):
            raise ValueError
        prot = _plain(cbor2.loads(pb))
    except Exception:
        raise AARError("MALFORMED")
    if not isinstance(prot, dict) or prot.get(H_TYP) != typ:
        raise AARError("TYP_MISMATCH")
    if prot.get(H_KID) != _kid(pub):
        raise AARError("KID_UNKNOWN")
    if prot.get(H_ALG) not in SIG_ALGS[len(pub)]:
        raise AARError("ALG_MISMATCH")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, cbor2.dumps(["Signature1", pb, b"", payload], canonical=True))
    except (InvalidSignature, ValueError):
        raise AARError("SIGNATURE_INVALID")
    return payload


def _jcs_num(x) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            raise ValueError("JCS: integer outside the IEEE-754 exact range")
        return str(x)
    import math
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


def _jcs_str(s: str) -> str:
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


def jcs(v) -> bytes:
    """RFC 8785 (JCS), the same bytes as the server's signview.jcs."""
    def enc(x):
        if x is None:
            return "null"
        if isinstance(x, (bool, int, float)):
            return _jcs_num(x)
        if isinstance(x, str):
            return _jcs_str(x)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            if not all(isinstance(k, str) for k in x):
                raise ValueError("JCS: member names are strings")
            return "{" + ",".join(_jcs_str(k) + ":" + enc(x[k]) for k in sorted(x, key=lambda k: k.encode("utf-16-be"))) + "}"
        raise ValueError("JCS: %s is not JSON" % type(x).__name__)
    return enc(v).encode("utf-8", "surrogatepass")


def args_sha256(tool: str, args: Optional[dict], salt: Optional[bytes] = None, v: int = 1) -> str:
    """The witness' binding of a call: SHA-256 of the canonical JSON of [tool, args] (server action.args_sha256).
    0.2.26: with the account salt the server sends (GET /v1/salt, DW_ARGS_SALT=transition|on) it is HMAC-SHA-256(salt, "dw-args1\\0" + canonical).
    r0269: v=2 (server action `args_v: 2`, rule mr-args-2): the bytes are "mr-args-2\\0" + RFC 8785 JCS of [tool, args] (bare SHA-256 or
    the same HMAC); arguments JCS cannot encode fall back to the v1 bytes, as the server does."""
    if v == 2:
        try:
            raw2 = b"mr-args-2\0" + jcs([tool, args or {}])
        except (ValueError, TypeError, RecursionError):
            raw2 = None
        if raw2 is not None:
            return hmac.new(salt, raw2, hashlib.sha256).hexdigest() if salt is not None else hashlib.sha256(raw2).hexdigest()
    raw = json.dumps([tool, args or {}], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if salt is not None:
        return hmac.new(salt, b"dw-args1\0" + raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def request_sha256(body: dict) -> str:
    """0.2.17 (R9-01): the hook's binding of a judge request: SHA-256 of the canonical JSON (sorted keys, no spaces, ASCII) of the body as sent."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _default_pin_path() -> str:
    base = os.environ.get("DEUS_WITNESS_HOME") or os.path.join(_compat.home(), ".config", "deus-witness")
    return os.path.join(base, "witness.json")


class Witness:
    """Witness(url, key). Sync client. verify=True: every `allow` AAR is checked against the pinned witness key
    (pinned at first use in ~/.config/deus-witness/witness.json; change => WitnessKeyChanged)."""

    def __init__(self, url: Optional[str] = None, key: Optional[str] = None, *, verify: bool = True,
                 pin_path: Optional[str] = None, timeout: float = 30.0, transport: Optional[httpx.BaseTransport] = None,
                 pin_new: bool = True, connect_timeout: Optional[float] = None):
        self.url = (url or os.environ.get("DEUS_WITNESS_URL") or DEFAULT_URL).rstrip("/")
        self.args_v = 2 if os.environ.get("DEUS_WITNESS_ARGS_V") == "2" else 1     # r0269: X-DW-Args-V opt-in (server r0269+)
        self.pin_new = pin_new           # 0.2.32 (K1): False = a URL without a pin is refused (WitnessNotPinned), not pinned at first use
        self.key = key or os.environ.get("DEUS_WITNESS_KEY")
        self.verify = verify
        self.pin_path = pin_path or _default_pin_path()
        # 0.2.63 (ISPYTANIE-PERED-LYUDMI-1211 Н1): a separate, short connect timeout (a black hole or a dead host is known in seconds, not
        # after the whole read timeout); None = one timeout for everything, as before
        self.connect_timeout = connect_timeout
        self._http = httpx.Client(base_url=self.url, timeout=self._timeout(timeout), transport=transport)
        self._pub: Optional[bytes] = None
        self._pub_from_pin = False       # 0.2.63: the key was taken from the pin file (no GET /v1/witness); see judge_statement
        self._salt: Any = False          # False = not asked yet; None = the server uses the bare SHA-256; bytes = the account salt
        self.salt_cache = False          # 0.2.63: keep the salt next to the pin (salt.json); the hook turns it on (one request less per call)
        self._salt_cached = False        # the salt in use came from that file (a mismatch asks the server once: refresh_salt)
        # r0285 (NAGRUZKA-I-EKONOMIKA-1311 p.1): a request the witness refused only because it is busy at this moment (busy()) is sent again
        # after a short pause, for at most busy_wait s from its first refusal and never past time.monotonic() == busy_until (None = never
        # repeated, as before); busy_retries counts the repeats, busy_last keeps the last such refusal
        self.busy_until: Optional[float] = None
        self.busy_wait = 5.0
        self.busy_retries = 0
        self.busy_last: Optional[WitnessError] = None

    def _timeout(self, t):
        if self.connect_timeout is None or isinstance(t, httpx.Timeout):
            return t
        return httpx.Timeout(t, connect=min(float(self.connect_timeout), float(t)))

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---- HTTP ----
    def _call(self, method: str, path: str, **kw) -> Any:
        headers = {"Authorization": "Bearer " + self.key, "X-DW-Args-Salt": "1"} if self.key and path.startswith(AGENT_PATHS) else {}
        rn = getattr(self, "run_nonce", None)             # RT-0.2.41 F1: the nonce of a `deus-witness run` (server 0.2.63+ counts the call)
        if headers and rn and path in ("/v1/hook/judge", "/v1/hook/run/start"):
            headers["X-DW-Run"] = rn
        if headers and path == "/v1/actions" and getattr(self, "args_v", 1) == 2:
            headers["X-DW-Args-V"] = "2"                  # r0269: opt-in to the JCS rule (DEUS_WITNESS_ARGS_V=2)
        timeout = kw.pop("timeout", None)
        if timeout is not None:
            kw["timeout"] = self._timeout(timeout)
        pause, first = 0.05, None
        while True:
            try:
                return self._call_once(method, path, headers, kw)
            except WitnessError as e:
                until = getattr(self, "busy_until", None)
                if until is None or not busy(e):
                    raise
                self.busy_last = e
                first = time.monotonic() if first is None else first
                until = min(until, first + float(getattr(self, "busy_wait", 5.0)))
                # the server refused before any work (Shed, the judge's waiting room): repeating the same request is safe
                wait = pause * (0.5 + random.random())
                if e.status == 503 and e.retry_after:
                    wait = max(wait, min(e.retry_after, 1.0))
                if time.monotonic() + wait >= until:
                    raise
                time.sleep(wait)
                self.busy_retries += 1
                pause = min(pause * 2, 0.8)

    def _call_once(self, method, path, headers, kw) -> Any:
        try:
            r = self._http.request(method, path, headers=headers, **kw)
        except httpx.HTTPError as e:
            raise WitnessError(0, "NETWORK", type(e).__name__)
        if r.status_code >= 400:
            ra = None
            try:
                ra = max(0.0, min(float(r.headers.get("retry-after", "")), 60.0))
            except ValueError:
                pass
            try:
                j = r.json()
                err = WitnessError(r.status_code, str(j.get("error", "HTTP_ERROR")), str(j.get("detail", "")), ra)
            except ValueError:
                err = WitnessError(r.status_code, "HTTP_ERROR", r.text[:100], ra)
            raise err
        try:
            return r.json()
        except ValueError:
            raise WitnessError(r.status_code, "BAD_RESPONSE")

    # ---- 0.2.26: salt of args_sha256 ----
    def salt(self) -> Optional[bytes]:
        """The account salt of args_sha256 (GET /v1/salt, asked once), or None when the server does not use one (mode off, or a server older than 0.2.35: 404).
        0.2.63: with salt_cache on, the salt saved next to the pin for this URL and key is used first (no request)."""
        if self._salt is False and self.salt_cache:
            c = self._salt_file_get()
            if c is not False:
                self._salt, self._salt_cached = c, True
        if self._salt is False:
            try:
                j = self._call("GET", "/v1/salt")
            except WitnessError as e:
                if e.status not in (404, 405):
                    raise
                j = {}
            s = j.get("salt") if isinstance(j, dict) else None
            self._salt = b64u_dec(s) if isinstance(s, str) and s else None
            self._salt_cached = False
            if self.salt_cache:
                self._salt_file_put(s if isinstance(s, str) and s else None)
        return self._salt

    def refresh_salt(self) -> bool:
        """0.2.63: the salt in use came from the cache file and a hash did not match: ask the server once. -> True when it was asked."""
        if not self._salt_cached:
            return False
        self._salt, self._salt_cached = False, False
        on, self.salt_cache = self.salt_cache, False
        try:
            self.salt()
        finally:
            self.salt_cache = on
        if on:
            s = self._salt
            self._salt_file_put(base64.urlsafe_b64encode(s).decode().rstrip("=") if isinstance(s, bytes) else None)
        return True

    def _salt_slot(self):
        return os.path.join(os.path.dirname(self.pin_path), "salt.json"), hashlib.sha256((self.key or "").encode()).hexdigest()[:32]

    def _salt_file_get(self):
        """-> bytes / None (the cached answer for this URL and key), or False when there is none (or the file is not trusted)."""
        try:
            p, k = self._salt_slot()
            if not self._pin_file_ok(p):
                return False
            with open(p, encoding="utf-8") as f:
                e = json.load(f).get(self.url)
            if not isinstance(e, dict) or e.get("k") != k or "salt" not in e:
                return False
            v = e["salt"]
            return b64u_dec(v) if isinstance(v, str) and v else None
        except (OSError, ValueError, AttributeError, TypeError):
            return False

    def _salt_file_put(self, s):
        try:
            p, k = self._salt_slot()
            d = {}
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f) if self._pin_file_ok(p) else {}
            except (OSError, ValueError):
                d = {}
            d = d if isinstance(d, dict) else {}
            d[self.url] = {"k": k, "salt": s}
            os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
            tmp = p + ".tmp%d" % os.getpid()
            _compat.write_private_text(tmp, json.dumps(d))
            os.replace(tmp, p)
        except OSError:
            pass

    def args_hash(self, tool: str, args: Optional[dict], v: int = 1) -> str:
        """args_sha256 of a call the way THIS server computes it (salted or bare; v=2: the JCS rule, see args_sha256)."""
        return args_sha256(tool, args, self.salt(), v)

    # ---- witness key pinning ----
    def witness_info(self) -> dict:
        """GET /v1/witness; pins the key on first use, raises WitnessKeyChanged when it differs from the pinned one."""
        info = self._call("GET", "/v1/witness")
        pin = self._read_pins()
        mine = {"kid_hex": info.get("kid_hex"), "pub_hex": info.get("pub_hex")}
        old = pin.get(self.url)
        if old is None and not self.pin_new:
            raise WitnessNotPinned("no pinned key for %s (pinned here: %s)" % (self.url, ", ".join(sorted(pin)) or "none"))
        if old is None:
            pin[self.url] = mine
            self._write_pins(pin)
        elif old != mine:
            raise WitnessKeyChanged("witness key of %s changed: pinned %s, now %s" % (self.url, old.get("kid_hex"), mine["kid_hex"]))
        self._pub = bytes.fromhex(mine["pub_hex"])
        return info

    def _pin_candidates(self) -> list:
        """Primary pin path, then fallbacks: DEUS_WITNESS_HOME, XDG_CONFIG_HOME, ~/.deus-witness, a temp dir."""
        c = [self.pin_path]
        home = _compat.home()
        for base in (os.environ.get("DEUS_WITNESS_HOME"),
                     os.path.join(os.environ["XDG_CONFIG_HOME"], "deus-witness") if os.environ.get("XDG_CONFIG_HOME") else None,
                     os.path.join(home, ".deus-witness"),
                     os.path.join(tempfile.gettempdir(), "deus-witness-%s" % getattr(os, "getuid", lambda: "u")())):
            if base:
                p = os.path.join(base, "witness.json")
                if p not in c:
                    c.append(p)
        return c

    def _pin_file_ok(self, p: str) -> bool:
        """N-08: a pin file is believed only when it and its directory belong to THIS user and nobody else can write them;
        the shared temp directory additionally needs a private (0700) directory."""
        if not hasattr(os, "getuid"):
            return True
        try:
            d = os.path.dirname(p)
            sf, sd = os.stat(p), os.stat(d)
            if sf.st_uid != os.getuid() or sd.st_uid != os.getuid() or (sf.st_mode & 0o022) or (sd.st_mode & 0o022):
                return False
            if os.path.abspath(d).startswith(os.path.abspath(tempfile.gettempdir()) + os.sep) and (sd.st_mode & 0o077):
                return False
            return True
        except OSError:
            return False

    def _read_pins(self) -> dict:
        for p in self._pin_candidates():
            if not self._pin_file_ok(p):
                continue
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                if isinstance(d, dict):
                    return d
            except (OSError, ValueError):
                continue
        return {}

    def _write_pins(self, d: dict):
        last = None
        for i, p in enumerate(self._pin_candidates()):
            try:
                os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
                if hasattr(os, "getuid") and os.stat(os.path.dirname(p)).st_uid != os.getuid():
                    raise OSError("directory belongs to another user")
                tmp = p + ".tmp%d" % os.getpid()
                _compat.write_private_text(tmp, json.dumps(d, indent=1))
                os.replace(tmp, p)
            except OSError as e:
                last = e
                continue
            if i > 0:
                print("deus-witness: warning: cannot write the key pin to %s (%s); pinned in %s instead. Set DEUS_WITNESS_HOME to a writable directory."
                      % (self.pin_path, type(last).__name__ if last else "error", p), file=sys.stderr)
            return
        print("deus-witness: warning: no writable place for the key pin (%s); the key is NOT pinned across runs." % (last,), file=sys.stderr)

    # ---- actions ----
    def check(self, res: ActionResult, sent: Optional[tuple] = None) -> ActionResult:
        """Verify the AAR of an allow result against the pinned key and res.action. Raises AARError / WitnessKeyChanged.
        sent=(tool, args): the call that was actually sent; the action of the answer must carry args_sha256 of exactly that call (AARError REQUEST_MISMATCH).
        Without `sent` only the receipt against the action the server returned is checked (the receipt does not prove which call it was asked for)."""
        if self._pub is None:
            self.witness_info()
        verify_aar(res.aar, self._pub, res.action or {})
        av = 2 if (res.action or {}).get("args_v") == 2 else 1         # r0269: the action names its rule; absent = v1
        if av == 2 and getattr(self, "args_v", 1) != 2:
            raise AARError("REQUEST_MISMATCH")                          # a v2 binding this client did not ask for
        if sent is not None and (res.action or {}).get("args_sha256") != self.args_hash(sent[0], sent[1], av):
            if not self.refresh_salt():                  # 0.2.63: a salt from salt.json is asked once more from the server
                self._salt = False                       # the server may have changed DW_ARGS_SALT since the salt was fetched: ask once more
            try:
                again = self.args_hash(sent[0], sent[1], av)
            except WitnessError:
                again = None
            if (res.action or {}).get("args_sha256") != again:
                raise AARError("REQUEST_MISMATCH")
        return res

    def act(self, tool: str, args: Optional[dict] = None, client: Optional[dict] = None, verify: Optional[bool] = None) -> ActionResult:
        body = {"tool": tool, "args": args or {}}
        if client:
            body["client"] = client
        res = ActionResult.from_json(self._call("POST", "/v1/actions", json=body))
        if res.verdict == "allow" and (self.verify if verify is None else verify):
            self.check(res, sent=(tool, args or {}))
        return res

    def get(self, rid: str, wait: int = 0, final: bool = False) -> ActionResult:
        """final (0.2.43, server 0.2.43b): this is the caller's last poll; if it ends with the call still waiting, the caller gives up and
        the witness marks the call "not run: timeout" in the journal (an older witness ignores the parameter)."""
        wait = max(0, min(int(wait), 25))
        params = {"wait": wait, "final": 1} if final else {"wait": wait}
        return ActionResult.from_json(self._call("GET", "/v1/actions/%s" % rid, params=params, timeout=wait + 15))

    def wait(self, rid: str, timeout: float = 50.0, verify: Optional[bool] = None, sent: Optional[tuple] = None) -> ActionResult:
        """Long-poll until the action leaves pending_approval / held or `timeout` seconds pass (then returns the waiting result).
        0.2.47 (R1): a call held by the witness (status held) is waited for too; the owner's Release makes it allow/allowed."""
        end = time.monotonic() + timeout
        pause = 0.5
        while True:
            left = end - time.monotonic()
            t_req = time.monotonic()
            try:
                # server-side long poll: wait=N holds the request up to N s (1..25), never a tight wait=0 loop
                res = self.get(rid, wait=int(min(25, max(1, -(-left // 1)))))
            except WitnessError as e:
                if e.status != 429 or time.monotonic() + (e.retry_after or pause) >= end:
                    raise
                time.sleep(max(e.retry_after or 0.0, pause))     # respect Retry-After, else exponential pause
                pause = min(pause * 2, 8.0)
                continue
            if res.status not in ("pending_approval", "held") or time.monotonic() >= end:
                break
            if time.monotonic() - t_req < 0.5:                   # the server answered at once: back off exponentially
                time.sleep(min(pause, max(0.0, end - time.monotonic())))
                pause = min(pause * 2, 8.0)
            else:
                pause = 0.5
        if res.verdict == "allow" and (self.verify if verify is None else verify):
            self.check(res, sent=sent)
        return res

    def present(self, rid: str) -> dict:
        return self._call("POST", "/v1/actions/%s/present" % rid, json={})

    def report(self, rid: str, executed: bool) -> dict:
        return self._call("POST", "/v1/actions/%s/report" % rid, json={"executed": bool(executed)})

    # ---- 0.2.16: the thin Claude Code hook ----
    def hook_judge(self, body: dict) -> dict:
        """POST /v1/hook/judge: raw facts in, the witness' classification and decisions out (see deus_witness/hook/main.py)."""
        return self._call("POST", "/v1/hook/judge", json=body)

    # ---- RT-0.2.41 F1 (server 0.2.63+): `deus-witness run` asks the witness, not a file ----
    def run_new(self) -> dict:
        """POST /v1/hook/run -> {"run": nonce, "exp": t}: a one-time nonce for one run of Claude Code."""
        return self._call("POST", "/v1/hook/run", json={})

    def run_start(self, session: Optional[str]) -> dict:
        """POST /v1/hook/run/start (X-DW-Run: self.run_nonce): the hook's SessionStart of that run."""
        return self._call("POST", "/v1/hook/run/start", json={"session": session})

    def run_view(self, nonce: str) -> dict:
        """GET /v1/hook/run/<nonce> -> {"starts", "judged", "sessions"} as the witness counted them."""
        return self._call("GET", "/v1/hook/run/%s" % nonce)

    def use_pin(self) -> bool:
        """0.2.63: take the witness key from the pin file (no GET /v1/witness). -> False when this URL has no pinned key."""
        pin = self._read_pins().get(self.url)
        if not isinstance(pin, dict) or not isinstance(pin.get("pub_hex"), str):
            return False
        try:
            self._pub = bytes.fromhex(pin["pub_hex"])
        except ValueError:
            return False
        self._pub_from_pin = True
        return True

    def judge_statement(self, b64: str) -> dict:
        """0.2.17 (R9-01): the statement of a judge answer (COSE_Sign1 by the witness key, checked against the pin) -> its payload.
        AARError(code) when it does not verify or is not a statement.
        0.2.63: with the key taken from the pin (use_pin), a statement that does not verify asks GET /v1/witness once: a changed key is
        WitnessKeyChanged (as before 0.2.63), the same key keeps the AARError."""
        if self._pub is None:
            self.witness_info()
        try:
            raw = open_signed(b64u_dec(str(b64 or "")), self._pub, TYP_STATEMENT)
        except AARError:
            if self._pub_from_pin:
                self._pub_from_pin = False
                self.witness_info()
            raise
        st = _plain(cbor2.loads(raw))
        if not isinstance(st, dict) or st.get("v") != "dw-judge-1":
            raise AARError("MALFORMED")
        return st

    def scan_list(self, rev: Optional[str] = None, cached_only: bool = False) -> Optional[dict]:
        """The fingerprint list, signed by the witness key (checked against the pin, also when read from the cache next to the pin).
        cached_only: no network at all; None when there is no valid cached list (or no pinned key yet)."""
        if self._pub is None:
            if cached_only:
                pin = self._read_pins().get(self.url)
                if not isinstance(pin, dict) or not isinstance(pin.get("pub_hex"), str):
                    return None
                self._pub = bytes.fromhex(pin["pub_hex"])
            else:
                self.witness_info()
        cache = os.path.join(os.path.dirname(self.pin_path), "scanlist.json")
        lst = None
        try:
            if self._pin_file_ok(cache):
                with open(cache, encoding="utf-8") as f:
                    c = json.load(f).get(self.url)
                if isinstance(c, dict) and (rev is None or c.get("rev") == rev):
                    lst = self._scan_list_of(c)
        except (OSError, ValueError, AARError, AttributeError):
            lst = None
        if lst is None and cached_only:
            return None
        if lst is None:
            c = self._call("GET", "/v1/hook/scanlist")
            lst = self._scan_list_of(c)
            try:
                d = {}
                try:
                    with open(cache, encoding="utf-8") as f:
                        d = json.load(f) if self._pin_file_ok(cache) else {}
                except (OSError, ValueError):
                    d = {}
                d = d if isinstance(d, dict) else {}
                d[self.url] = {"rev": lst["rev"], "cose_b64": c.get("cose_b64")}
                os.makedirs(os.path.dirname(cache), mode=0o700, exist_ok=True)
                tmp = cache + ".tmp%d" % os.getpid()
                _compat.write_private_text(tmp, json.dumps(d))
                os.replace(tmp, cache)
            except OSError:
                pass                                      # no cache: the list is fetched again next time
        if rev is not None and lst.get("rev") != rev:
            raise AARError("SCANLIST_REV")
        return lst

    def _scan_list_of(self, c: dict) -> dict:
        lst = _plain(cbor2.loads(open_signed(b64u_dec(str(c.get("cose_b64", ""))), self._pub, TYP_SCANLIST)))
        if not isinstance(lst, dict) or lst.get("v") != "dw-scanlist-1" or not isinstance(lst.get("rev"), str):
            raise AARError("MALFORMED")
        return lst

    # ---- 0.2: tool catalog and declared coverage ----
    def catalog(self, tools: list) -> dict:
        """POST /v1/catalog with the tools/list of the MCP server: [{name, description, inputSchema}].
        -> {catalog_sha256, n_tools, changed[, pass_net_tools]} (pass_net_tools: pass tools with a network effect by the agent toolmap)."""
        body = [{k: t[k] for k in ("name", "description", "inputSchema") if k in t} for t in tools]
        return self._call("POST", "/v1/catalog", json={"tools": body})

    def coverage(self, report: Optional[dict] = None, pass_net_tools: Optional[list] = None) -> dict:
        """POST /v1/coverage: the operator-declared coverage level (a claim, not a proof).
        report=None: runs the light doctor here (configs only, no network probes) and sends its result."""
        if report is None:
            from .doctor import coverage_body, diagnose
            report = coverage_body(diagnose(network=False, pass_net_tools=pass_net_tools), pass_net_tools)
        return self._call("POST", "/v1/coverage", json=report)
