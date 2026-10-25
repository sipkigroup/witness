"""extension-http (spec/extension-http.md, PH-4): canonical form and matching of HTTP request targets and of the rules of
`permissions.http.allow`. Pure functions, no I/O, no regular expressions over anything the agent or the owner wrote.

Request target (action.recipient): "<METHOD> <host>:<port><path>" (port always explicit; no query, no fragment).
Rule: "<METHOD|*> <host|*.suffix>[:<port>]<path-pattern>" (port absent = 443; path segments: literal, "*" = one segment, last "**" =
one or more). canon_target() -> a tuple or None ("unmatchable": no rule ever covers it); canon_rule() -> the canonical text or None.
"""
import unicodedata

MAX_RULES = 200
MAX_RULE_LEN = 512
MAX_TARGET_LEN = 8192
DEFAULT_PORT = 443

_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCHAR_RAW = _UNRESERVED | frozenset(b"!$&'()*+,;=:@")            # RFC 3986 pchar without pct-encoded
_FORBIDDEN_PCT = frozenset([0x2F, 0x5C, 0x25, 0x7F] + list(range(0x20)))   # encoded "/", "\", "%" (double encoding), controls
_HOST_CH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = frozenset("0123456789ABCDEFabcdef")
_BAD_CAT = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")


def canon_method(m):
    """1..16 ASCII letters -> upper case; else None."""
    if isinstance(m, str) and 1 <= len(m) <= 16 and m.isascii() and m.isalpha():
        return m.upper()
    return None


def _port(s):
    if not isinstance(s, str) or not s or len(s) > 5 or not s.isascii() or not s.isdigit() or s[0] == "0":
        return None
    p = int(s)
    return p if 1 <= p <= 65535 else None


def canon_host(h, wildcard=False):
    """ASCII host -> lower case, one trailing dot removed, labels [a-z0-9_-]{1,63}; all-numeric = canonical dotted IPv4 only;
    a numeric last label otherwise = None. wildcard=True also accepts "*." + a name of >= 2 labels (never an address)."""
    if not isinstance(h, str) or not h or not h.isascii():
        return None
    h = h.lower()
    if h.endswith("."):
        h = h[:-1]
    star = False
    if wildcard and h.startswith("*."):
        star, h = True, h[2:]
    if not h or len(h) > 253:
        return None
    labels = h.split(".")
    for lb in labels:
        if not 1 <= len(lb) <= 63 or any(c not in _HOST_CH for c in lb):
            return None
    if all(lb.isdigit() for lb in labels):
        if star or len(labels) != 4 or any((len(lb) > 1 and lb[0] == "0") or int(lb) > 255 for lb in labels):
            return None
    elif labels[-1].isdigit():
        return None
    if star and len(labels) < 2:
        return None
    return ("*." if star else "") + h


def canon_segment(seg):
    """One path segment (between "/") -> canonical text, or None (unmatchable). PH-4 step 4."""
    if not isinstance(seg, str):
        return None
    out, raw, i, n = [], bytearray(), 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "%":
            hx = seg[i + 1:i + 3]
            if len(hx) != 2 or any(x not in _HEX for x in hx):
                return None
            b = int(hx, 16)
            if b in _FORBIDDEN_PCT:
                return None
            raw.append(b)
            out.append(chr(b) if b in _UNRESERVED else "%" + hx.upper())
            i += 3
            continue
        o = ord(c)
        if o > 127 or o not in _PCHAR_RAW:
            return None
        raw.append(o)
        out.append(c)
        i += 1
    try:
        text = raw.decode("utf-8")                      # strict: overlong forms, surrogates, bad sequences -> None
    except UnicodeDecodeError:
        return None
    if unicodedata.normalize("NFKC", text) != text or any(unicodedata.category(ch) in _BAD_CAT for ch in text):
        return None
    if text.split(";", 1)[0] in (".", ".."):            # dot segment, also "..;x" (Tomcat) and encoded forms
        return None
    return "".join(out)


def canon_path(path):
    """"/a/b/" -> ("a", "b", ""), or None. An empty segment is allowed only as the last one (trailing slash)."""
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_TARGET_LEN:
        return None
    segs = path[1:].split("/")
    out = []
    for k, s in enumerate(segs):
        if s == "":
            if k != len(segs) - 1:
                return None
            out.append("")
            continue
        c = canon_segment(s)
        if not c:
            return None
        out.append(c)
    return tuple(out)


def canon_target(t):
    """Request target "<METHOD> <host>:<port><path>" -> (method, host, port, segments) or None (unmatchable)."""
    if not isinstance(t, str) or len(t) > MAX_TARGET_LEN:
        return None
    sp = t.find(" ")
    if sp <= 0:
        return None
    m, rest = canon_method(t[:sp]), t[sp + 1:]
    sl = rest.find("/")
    if m is None or sl <= 0:
        return None
    auth, path = rest[:sl], rest[sl:]
    host, colon, port = auth.rpartition(":")
    if not colon:
        return None                                     # the request side has no default port
    host, port, segs = canon_host(host), _port(port), canon_path(path)
    if host is None or port is None or segs is None:
        return None
    return (m, host, port, segs)


def parse_rule(r):
    """Rule text (canonical or not) -> (method or "*", host pattern, port, segment patterns), or None."""
    if not isinstance(r, str) or not 0 < len(r) <= MAX_RULE_LEN or "," in r:
        return None
    sp = r.find(" ")
    if sp <= 0:
        return None
    mt, rest = r[:sp], r[sp + 1:]
    m = "*" if mt == "*" else canon_method(mt)
    sl = rest.find("/")
    if m is None or sl <= 0 or " " in rest:
        return None
    auth, path = rest[:sl], rest[sl:]
    if ":" in auth:
        host, _, ps = auth.rpartition(":")
        port = _port(ps)
    else:
        host, port = auth, DEFAULT_PORT
    host = canon_host(host, wildcard=True)
    if host is None or port is None:
        return None
    segs = path[1:].split("/")
    out = []
    for k, s in enumerate(segs):
        last = k == len(segs) - 1
        if s in ("*", "**"):
            if s == "**" and not last:
                return None
            out.append(s)
        elif s == "":
            if not last:
                return None
            out.append("")
        else:
            c = canon_segment(s)
            if not c or "*" in c:
                return None
            out.append(c)
    return (m, host, port, tuple(out))


def rule_text(p):
    m, host, port, segs = p
    return "%s %s%s/%s" % (m, host, "" if port == DEFAULT_PORT else ":%d" % port, "/".join(segs))


def canon_rule(r):
    """-> the canonical text of the rule, or None when it cannot be one."""
    p = parse_rule(r)
    if p is None:
        return None
    t = rule_text(p)
    return t if len(t) <= MAX_RULE_LEN else None


def is_canonical_rule(r):
    return isinstance(r, str) and canon_rule(r) == r


def _host_ok(rule_host, host):
    if rule_host.startswith("*."):
        suf = rule_host[1:]                             # ".example.com"
        return host.endswith(suf) and len(host) > len(suf)
    return rule_host == host


def rule_covers(rule, tgt):
    """rule: parse_rule() tuple; tgt: canon_target() tuple."""
    rm, rh, rp, rs = rule
    m, h, p, segs = tgt
    if (rm != "*" and rm != m) or rp != p or not _host_ok(rh, h):
        return False
    if rs and rs[-1] == "**":
        pre = rs[:-1]
        if len(segs) <= len(pre):
            return False
    else:
        pre = rs
        if len(segs) != len(rs):
            return False
    for a, b in zip(pre, segs):
        if a == "*":
            if b == "":
                return False
        elif a != b:
            return False
    return True


def allowed(rules, target):
    """Does any CANONICAL rule of the list cover the request target? A non-canonical entry never matches (fail closed)."""
    tgt = canon_target(target)
    if tgt is None or not isinstance(rules, list):
        return False
    for r in rules:
        if is_canonical_rule(r) and rule_covers(parse_rule(r), tgt):
            return True
    return False
