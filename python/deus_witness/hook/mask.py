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
ASSIGN_RE = re.compile(r"(?i)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AUTH)[A-Za-z0-9_]*)(\s*[=:]\s*)(?!\[masked\])((?:Bearer|Basic|Token)\s+\S+|\S+)")
# a PEM block whole (the server's shape masks only its first line: the key itself would leave the machine)
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)


def mask_value(s: str, limit: int) -> str:
    s = s[:limit + 512]
    s = PEM_RE.sub("[masked]", s)
    for _, rx in SECRET_RE:
        s = rx.sub("[masked]", s)
    s = ASSIGN_RE.sub(lambda m: m.group(1) + m.group(2) + "[masked]", s)
    return s[:limit]
