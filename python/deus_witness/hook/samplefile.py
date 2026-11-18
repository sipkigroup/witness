"""r0335 (live run nabor-1 17.11, S034 `Read .env.example` asked as a credential): is a SAMPLE of a credential file (`.env.example`,
`.env.sample`, `.env.template`) only a template -- names with empty or placeholder values -- or does it hold a real value?

The same file is in the hook (mcp/deus_witness/hook/samplefile.py, which answers the witness's `sample` question on the user's machine) and
here (the server's LocalFS: tests, the fatigue harness). The name alone never decides: a sample is judged as the credential it copies
unless its text was looked at and found to be a template. answer(p) -> True (a template), False (a value that looks like a credential,
binary, or too big to look at), None (cannot be read: judged as a credential).

Looks like a credential (False): a private key block; a URL with a password in it (`postgres://u:S3cret@h`) that is not a placeholder;
a token of a known kind (AKIA..., ghp_..., github_pat_..., glpat-..., xox?-..., sk-..., sk_live_..., rk_live_..., AIza..., a JWT); any
run of 20+ token characters with at least 3 digits and 3 letters that is not a placeholder (`your-...`, `xxxx`, `example`, `changeme`).
Short values (`changeme`, `8080`, `true`, `postgres`) and `<...>` / `${VAR}` are a template."""
import re

MAX_BYTES = 64 * 1024
_KNOWN = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|"
                    r"xox[abposr]-[A-Za-z0-9-]{10,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}|"
                    r"AIza[0-9A-Za-z_-]{30,}|ya29\.[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_RUN = re.compile(r"[A-Za-z0-9+/=_.-]{20,}")
_PLACEHOLDER = re.compile(r"your|example|xxxx|change|placeholder|replace|dummy|sample|todo|insert|fill|here|redacted|\*\*\*", re.I)
_URL_PASS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]*:([^@\s/]*)@")
_PASS_OK = re.compile(r"(?:|password|passwd|pass|pw|secret|changeme|change_me|postgres|root|admin|user|test|example|xxx+|\*+|"
                      r"<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)", re.I)


def _value_secret(v: str) -> bool:
    if _KNOWN.search(v):
        return True
    for m in _URL_PASS.finditer(v):
        if not _PASS_OK.fullmatch(m.group(1)):
            return True
    for m in _RUN.finditer(v):
        t = m.group(0)
        if sum(c.isdigit() for c in t) >= 3 and sum(c.isalpha() for c in t) >= 3 and not _PLACEHOLDER.search(t) \
                and not re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}", t):      # a host name, not a token
            return True
    return False


def text_is_template(text: str) -> bool:
    if "\x00" in text or "-----BEGIN" in text:
        return False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        v = s.split("=", 1)[1].strip() if "=" in s else s
        if _value_secret(v):
            return False
    return True


def answer(p):
    """-> True / False / None (see above). `p` is the real path (the witness resolved links before asking)."""
    import os
    import stat
    try:
        st = os.stat(p)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > MAX_BYTES:
            return False
        with open(p, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except (OSError, ValueError, TypeError):
        return None
    if len(raw) > MAX_BYTES:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return text_is_template(text)
