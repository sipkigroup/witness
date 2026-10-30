"""0.2.73 (N13, polygon series 9): the links an archive makes when it is extracted. Facts only, no decision.

`tar xf ln.tar` with one entry h3.txt (a hard link, linkname .env) puts a second name of .env into the project: the extraction was asked as
"writes files whose text the witness cannot see", and nothing on the page said that one of them is the secret. The witness asks the hook
(need `archive`) what links the archive of the line holds; the hook reads the archive's headers here (never extracts, never runs a
program) and sends {"links": [[kind, name, target], ...], "more": bool}; kind "hard" (the target is a name inside the extraction) or "sym".
None: not a tar / zip archive this module reads, too big, unreadable. The server judges the targets (a credential file -> dangerous).
Same file on both sides (a test keeps the two copies byte-equal, as gitref.py)."""
from __future__ import annotations

import os
import stat
import tarfile
import time
import zipfile

MAX_PLAIN = 256 << 20         # an uncompressed tar: headers are read, the data is skipped (seek)
MAX_PACKED = 16 << 20         # a compressed tar is decompressed to be read: smaller
MAX_MEMBERS = 50000
MAX_LINKS = 64
MAX_NAME = 1024
MAX_SECONDS = 2.0


def _cut(s):
    return s[:MAX_NAME] if isinstance(s, str) else ""


def answer(p):
    """-> {"links": [[kind, name, target]], "more": bool} or None."""
    try:
        st = os.stat(p)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(p, "rb") as f:
            head = f.read(6)
    except (OSError, ValueError, TypeError):
        return None
    packed = head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"
    links, more, t0 = [], False, time.monotonic()
    try:
        if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
            if st.st_size > MAX_PLAIN:
                return None
            with zipfile.ZipFile(p) as z:
                for n, i in enumerate(z.infolist()):
                    if n >= MAX_MEMBERS or time.monotonic() - t0 > MAX_SECONDS:
                        more = True
                        break
                    if stat.S_ISLNK((i.external_attr >> 16) & 0xFFFF):
                        if len(links) >= MAX_LINKS:
                            more = True
                            break
                        tgt = z.read(i).decode("utf-8", "replace") if i.file_size <= MAX_NAME else ""
                        links.append(["sym", _cut(i.filename), _cut(tgt)])
            return {"links": links, "more": more}
        if st.st_size > (MAX_PACKED if packed else MAX_PLAIN) or not tarfile.is_tarfile(p):
            return None
        with tarfile.open(p, "r:*") as t:
            for n, m in enumerate(t):
                if n >= MAX_MEMBERS or time.monotonic() - t0 > MAX_SECONDS:
                    more = True
                    break
                if m.islnk() or m.issym():
                    if len(links) >= MAX_LINKS:
                        more = True
                        break
                    links.append(["hard" if m.islnk() else "sym", _cut(m.name), _cut(m.linkname)])
    except Exception:      # noqa: BLE001  a broken archive: no fact (the extraction stays the question it was)
        return None
    return {"links": links, "more": more}
