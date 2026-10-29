"""0.2.43 (server 0.2.43b, O2): the masker of the witness' previews, copied here so that a file's text is masked BEFORE it leaves the machine.

The witness masks again (app/toolmap.py mask_value: these shapes plus the account's closed-data literals); this copy holds only the shapes
(server/tests/test_0243b_pesochnica.py keeps them equal to the server's). Used for `facts.exec.preview`: the first PREVIEW_MAX characters
of a changed executed file the witness asked about (need.preview)."""
import re

SECRET_RE = [
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("api_key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"))]
# 29.10 (ReDoS, OTCHET-REDOS-AUDIT-2910 #1): `[A-Za-z0-9_]*KW[A-Za-z0-9_]*` with no left edge re-split the same name from every position
# ('PASS' x 1000: 0.7 s, x 1024: > 20 s, cubic). Now a name is tried ONCE, from its first character (the lookbehind), the keyword is looked
# for by a lookahead and the name is taken whole. Same matches as before (group 1 was always the whole name: it must be followed by \s or
# [=:]), checked on a 92 000-line corpus with 0 differences (server/tests/test_redos_2910.py). No atomic group: the client runs on 3.10.
# 29.10 MTYPE (cloud/OTCHET-MASKA-TIP-2910.md, RT-MASKA-UKRYTIE-2910): a bare [masked] hid exactly what the witness asked the person to decide
# (`AUTH_URL=https://host/x; curl "$AUTH_URL"`, `passthrough_cmd='curl ...'; eval ...`). A masked value that looks like a URL is now shown as
# `[masked URL host=<host>]` (never userinfo, port, path, query; a subdomain label not in MARK_SUB_OK is `*`: a secret can ride in a DNS
# label), one that looks like a command as `[masked command: <program>]` (the program only when it is in MARK_PROGRAMS, never its arguments),
# anything else `[masked]` as before. "Already masked" now means any of these markers (MASK_MARK). In the TEXT OF A SHELL COMMAND (shell=True:
# the Bash* tools) a bare value ends at an unquoted ; & | ) or a line end: `PASS=1;rm -rf build` -> `PASS=[masked];rm -rf build` (it ate `;rm`).
MASK_MARK = r"\[masked(?: URL host=[a-z0-9.*\-]+| command: [A-Za-z0-9._+\-]+)?\]"
ASSIGN_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(?=[A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH))([A-Za-z0-9_]+)(\s*[=:]\s*)(?!" + MASK_MARK + r")((?:Bearer|Basic|Token)\s+\S+|\S+)")
# 29.10 QMASK (cloud/OTCHET-QMASK-2910.md): ASSIGN_RE never masked a name in QUOTES: `"password": "hunter2"` (JSON, a dict, YAML) left the
# machine open in a file preview, `password: "two words"` / `DB_PASSWORD="a b"` lost only the first word. Widening ASSIGN_RE itself made 142
# corpus cases softer, so this is a SECOND pass: its value spans are added to ASSIGN_RE's on the same string (a union: it only adds masks).
# Name: optionally in quotes (' " or the JSON-escaped \"), then `]` (d['token'] = ...), the same words as ASSIGN_RE (API_KEY/PRIVATE_KEY also
# with '-': X-Api-Key), also '-' and '.' inside; value: a quoted string (escapes inside, to the line end if unterminated), Bearer/Basic/Token
# + value, or a bare word. A value already [masked] is left. Linear: every quoted body has one tokenisation, a name is tried once (lookbehind).
QUOTED_ASSIGN_RE = re.compile(
    r"""(?i)(?P<kq>\\"|["'])?(?<![A-Za-z0-9_.\-])(?=[A-Za-z0-9_.\-]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API[_\-]?KEY|PRIVATE[_\-]?KEY|AUTH))"""
    r"""(?P<k>[A-Za-z0-9_.\-]+)(?(kq)(?P=kq)\]?)\s*[=:]\s*(?!(?:\\"|["'])?""" + MASK_MARK + r""")"""
    r"""(?P<v>(?:Bearer|Basic|Token)\s+[^\s"'\\,;{}\[\]]+"""
    r"""|"(?:[^"\\\n]|\\.)*(?:"|(?=\\?[\r\n])|\\?\Z)"""
    r"""|'(?:[^'\\\n]|\\.)*(?:'|(?=\\?[\r\n])|\\?\Z)"""
    r"""|\\"(?:[^"\\\n]|\\\\(?:\\.|[^"\\\n])|\\[^"\\\n])*(?:\\"|(?=\\?[\r\n])|\\?\Z)"""
    r"""|[^\s"'\\,;{}\[\]]+)""")


# the same two shapes for shell text: the bare value (and the Bearer value) stops at ; & | ) (a quoted value is still taken whole)
ASSIGN_SH_RE = re.compile(ASSIGN_RE.pattern.replace(r"\s+\S+|\S+)", r"\s+[^\s;&|)]+|[^\s;&|)]+)"))
QUOTED_ASSIGN_SH_RE = re.compile(QUOTED_ASSIGN_RE.pattern.replace("\\,;{}\\[\\]]+", "\\,;{}\\[\\]&|)]+"))
assert ASSIGN_SH_RE.pattern.count("[^\\s;&|)]+") == 2 and QUOTED_ASSIGN_SH_RE.pattern.count("&|)]+") == 2
MARK_PROGRAMS = frozenset((
    "curl wget nc ncat netcat socat ssh scp sftp rsync ftp telnet bash sh zsh dash ksh fish eval exec source python python2 python3 node "
    "deno bun perl ruby php lua powershell pwsh osascript rm dd mkfs chmod chown sudo su doas git docker kubectl base64 openssl gpg xxd "
    "nslookup dig host ping env xargs sed awk tar zip unzip mv cp cat echo printf tee crontab launchctl systemctl npm npx pip pip3 make").split())
MARK_SUB_OK = frozenset((
    "www api apis docs doc raw cdn static files file upload uploads download downloads git gist gitlab github auth login oauth sso id app "
    "apps m mail smtp imap s3 storage objects registry pypi npm hooks hook webhook webhooks dev staging stage prod test beta api2 v1 v2 "
    "rpc ws wss ftp sftp cloud console admin dashboard portal pay checkout billing").split())
_MARK_URL = re.compile(r"(?i)[a-z][a-z0-9+.\-]{0,15}://(?:[^/?#\s'\"\\@]*@)?([a-z0-9.\-]{1,253})(?![a-z0-9.\-@])")
_MARK_CMD = re.compile(r"(?:(?:\$\(|`)\s*|(?=\S+\s+\S))(?:[A-Za-z0-9._\-]*/)*([A-Za-z0-9._+\-]{1,32})(?![A-Za-z0-9._+\-/])")
_MARK_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?")


def _mark_host(h):
    """the host as the marker shows it, or None: an IPv4 as is; a name: its last two labels (three under co/com/net/org/gov/edu/ac + a
    two-letter TLD) plus the subdomain labels found in MARK_SUB_OK, any other label as `*` (runs of them collapsed)."""
    h = h.lower().rstrip(".")
    labels = h.split(".")
    if len(labels) < 2 or not all(_MARK_LABEL.fullmatch(l) for l in labels):
        return None
    if all(l.isdigit() for l in labels):
        return h if len(labels) == 4 and all(int(l) < 256 for l in labels) else None
    if labels[-1].isdigit():
        return None
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") else 2
    sub = []
    for l in labels[:-n]:
        l = l if l in MARK_SUB_OK else "*"
        if not (l == "*" and sub and sub[-1] == "*"):
            sub.append(l)
    return ".".join(sub + labels[-n:])


def mask_marker(v):
    """The marker that replaces the masked value `v` (see MASK_MARK): URL -> host, command -> program, else [masked]."""
    t = v.strip()
    for q in ('\\"', '"', "'"):
        if t.startswith(q):
            t = t[len(q):]
            break
    m = _MARK_URL.match(t)
    if m:
        h = _mark_host(m.group(1))
        return "[masked URL host=%s]" % h if h else "[masked]"
    m = _MARK_CMD.match(t)
    if m and m.group(1) in MARK_PROGRAMS:
        return "[masked command: %s]" % m.group(1)
    return "[masked]"


_SH_SEP = ";&|)"


def _shell_stops(s):
    """stop[i]: the first j >= i where s[j] is whitespace or a separator OUTSIDE shell quotes (len(s) if none); nsep[i]: the first j >= i
    where s[j] is a separator outside quotes; quoted[i]: s[i] is inside quotes or escaped. Quotes: '...' (no escapes),
    "..." (backslash escapes), a backslash outside quotes escapes the next character; an unterminated quote runs to the end (masks more)."""
    n = len(s)
    stop = [n] * (n + 1)
    nsep = [n] * (n + 1)
    quoted = bytearray(n)
    st, i = 0, 0                     # 0 outside, 1 in '...', 2 in "..."
    while i < n:
        ch = s[i]
        if st == 0:
            if ch == "\\":
                quoted[i] = 1
                if i + 1 < n:
                    quoted[i + 1] = 1
                i += 2
                continue
            if ch == "'":
                st = 1
            elif ch == '"':
                st = 2
        elif st == 1:
            quoted[i] = 1
            if ch == "'":
                st = 0
        else:
            quoted[i] = 1
            if ch == "\\" and i + 1 < n:
                quoted[i + 1] = 1
                i += 2
                continue
            if ch == '"':
                st = 0
        i += 1
    for j in range(n - 1, -1, -1):
        c = s[j]
        sep = c in _SH_SEP and not quoted[j]
        nsep[j] = j if sep else nsep[j + 1]
        stop[j] = j if (sep or c.isspace()) else stop[j + 1]
    return stop, quoted, nsep


def assign_spans(s, shell=False):
    """The spans masked in `s`: ASSIGN_RE's values united with QUOTED_ASSIGN_RE's (overlaps merged). shell=True (the text of a shell
    command): the _SH_ shapes, a bare value ending at a separator; one INSIDE shell quotes (`-H 'Authorization: Bearer a;b'`) is part of the
    value, so such a span runs on to the next whitespace or unquoted separator (_shell_stops). United with the plain spans each cut at its
    first unquoted separator: what the shell text shows more than the plain one always starts at an unquoted separator."""
    sp = sorted([m.span(3) for m in ASSIGN_RE.finditer(s)] + [m.span("v") for m in QUOTED_ASSIGN_RE.finditer(s)])
    if shell and sp:
        stops = None
        for k, (a, b) in enumerate(sp):              # the plain spans, cut at their first unquoted separator
            if any(ch in _SH_SEP for ch in s[a:b]):
                if stops is None:
                    stops = _shell_stops(s)
                sp[k] = (a, min(b, stops[2][a]))
        for m, g in [(m, 3) for m in ASSIGN_SH_RE.finditer(s)] + [(m, "v") for m in QUOTED_ASSIGN_SH_RE.finditer(s)]:
            a, b = m.span(g)                          # + the shell spans (a later NAME= after a separator), run on over quoted separators
            if b < len(s) and s[b] in _SH_SEP:
                if stops is None:
                    stops = _shell_stops(s)
                if stops[1][b]:
                    b = stops[0][b + 1]
            sp.append((a, b))
        sp = sorted(x for x in sp if x[1] > x[0])
    out = []
    for a, b in sp:
        if out and a < out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def mask_assign(s, shell=False):
    """Every span of assign_spans(s, shell) replaced by its marker (mask_marker; ASSIGN_RE.sub's output exactly when the quoted pass adds
    nothing and no value is a URL or a command)."""
    out, i = [], 0
    for a, b in assign_spans(s, shell):
        out += [s[i:a], mask_marker(s[a:b])]
        i = b
    out.append(s[i:])
    return "".join(out)
# a PEM block whole (the server's shape masks only its first line: the key itself would leave the machine)
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)


def mask_value(s: str, limit: int) -> str:
    s = s[:limit + 512]
    s = PEM_RE.sub("[masked]", s)
    for _, rx in SECRET_RE:
        s = rx.sub("[masked]", s)
    s = mask_assign(s)
    return s[:limit]
