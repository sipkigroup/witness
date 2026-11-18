"""r0338 (SIGNATURY-BAZA-FABLE52-1711 §1 "the lesson of Rm", §5 step 1): the IDENTITY of a program, by the file on disk, not by its name.
Facts only, no decision (the witness judges; this file is byte-equal in the hook and on the server, a test keeps the two copies equal).

A name is not a program. `cp /bin/rm ~/.local/bin/cat` makes `cat -rf ~` the rm it is; `ln -s /bin/rm ~/.local/bin/head` the same; `./r`
copied from rm is rm under another name. Before r0338 the witness knew the file behind a word only when it asked the realpath of a PATH
word (`./g`); a bare word was judged by its spelling, and a copy (no link, one name) by nothing.

  ident(path, root, home)    -> {"path", "real", "link", "dev", "ino", "nlink", "size", "zone", "same"} for the regular file `path` (as
                               found), or None. zone: "sys" (a system directory the user cannot write: the program IS what its directory
                               holds) | "proj" | "tmp" | "home" | "other". same: the names of the files of the system directories that
                               are this file byte for byte (a copy, a hard link) -- [] when none or when the file is itself a system file.
  fact(cmd, cwd, path_env, root, home)
                             -> {"v": 1, "w": {word: ident | None}, "p": {absolute path: ident | None}}: every bare word of the line found on the PATH
                               Claude Code runs commands with, every path word that names a regular file. A word is the line's text with
                               quotes and backslashes taken out (`"r"m` -> rm), so it is what the shell would look up.
  answer_path(p, root, home): the same for one path the witness asks about (a word is never asked: every word of the line is looked up).

Cost: one stat per word and PATH entry; the system directories are read (sizes only) once per call and only when a file outside them
could be a copy; a file is hashed only when its size is the size of a system file."""
from __future__ import annotations

import hashlib
import os
import re
import stat as _stat
import tempfile

V = 1
SYS_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
MAX_WORDS = 48                   # bare words looked up on the PATH per call
MAX_PATHS = 32                   # path words looked at per call
MAX_SAME = 128                   # names reported for one file (the Xcode shim has 78)
MAX_HASH = 64 * 1024 * 1024      # a bigger file is not hashed (no system program is that big)
_SPLIT = re.compile(r"[\s;|&<>()`{}]+")
_UNQ = re.compile(r"""['"\\]""")
_BARE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}")
_SEG = re.compile(r"[;|&()`{}\n]+")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_LEAD = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "time", "command", "builtin", "exec", "env", "nohup", "nice",
                   "sudo", "doas", "xargs", "timeout", "stdbuf", "setsid", "caffeinate", "unbuffer", "chronic", "flock"})
_SIZES = []                      # the size index of SYS_DIRS for this process: [{size: [path, ...]}]


def _under(p, d):
    d = d.rstrip("/")
    return isinstance(p, str) and (p == d or p.startswith(d + "/"))


def _tmp_dirs():
    out = {"/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm"}
    for t in (tempfile.gettempdir(), os.environ.get("TMPDIR")):
        if isinstance(t, str) and t.startswith("/"):
            out.add(t.rstrip("/") or "/")
            try:
                out.add(os.path.realpath(t))
            except (OSError, ValueError):
                pass
    return out


def zone(real, root=None, home=None):
    """-> where the file lies: "sys" | "proj" | "tmp" | "home" | "other" (a symlink already resolved)."""
    d = os.path.dirname(real)
    if any(_under(real, s) for s in SYS_DIRS + ("/usr/libexec", "/System")):
        try:
            if not os.access(d, os.W_OK) and os.stat(real).st_uid == 0:
                return "sys"                          # a directory the user (and so the agent) cannot write
        except OSError:
            pass
    for r in (root, os.path.realpath(root) if isinstance(root, str) and root else None):
        if isinstance(r, str) and r.startswith("/") and r != "/" and _under(real, r):
            return "proj"
    if any(_under(real, t) for t in _tmp_dirs()) or re.match(r"^/(private/)?var/folders/", real):
        return "tmp"
    for h in (home, os.path.realpath(home) if isinstance(home, str) and home else None):
        if isinstance(h, str) and h.startswith("/") and h != "/" and _under(real, h):
            return "home"
    return "other"


def _size_index():
    if _SIZES:
        return _SIZES[0]
    idx = {}
    for d in SYS_DIRS:
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    if e.is_file(follow_symlinks=False):
                        idx.setdefault(e.stat(follow_symlinks=False).st_size, []).append(e.path)
                except OSError:
                    continue
    _SIZES.append(idx)
    return idx


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def same_names(real, st=None):
    """-> sorted names of the system files that are `real` byte for byte (a copy or a hard link of a system program); [] for none."""
    try:
        st = st or os.stat(real)
        if not _stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > MAX_HASH or not st.st_mode & 0o111:
            return []                                 # not a program (no x bit: the shell cannot run it by its name)
        cands = [c for c in _size_index().get(st.st_size, ()) if c != real]
        if not cands:
            return []
        h, out = _sha(real), set()
        for c in cands:
            try:
                cs = os.stat(c)
                if (cs.st_dev, cs.st_ino) == (st.st_dev, st.st_ino) or _sha(c) == h:
                    out.add(os.path.basename(c))
            except OSError:
                continue
        return sorted(out)[:MAX_SAME]
    except (OSError, ValueError):
        return []


def ident(path, root=None, home=None):
    try:
        lst = os.lstat(path)
        real = os.path.realpath(path)
        st = os.stat(real)
    except (OSError, ValueError):
        return None
    if not _stat.S_ISREG(st.st_mode):
        return None
    z = zone(real, root, home)
    return {"path": path, "real": real, "link": _stat.S_ISLNK(lst.st_mode), "dev": st.st_dev, "ino": st.st_ino, "nlink": st.st_nlink,
            "size": st.st_size, "zone": z, "same": [] if z == "sys" else same_names(real, st)}


def _path_list(path_env):
    if not isinstance(path_env, str) or not path_env:
        return None
    ps = path_env.split(os.pathsep)
    if any(not x.startswith("/") for x in ps):
        return None                                   # an empty or relative entry is the shell's cwd, not ours: no fact
    return ps


def _which(w, dirs):
    for d in dirs:
        p = os.path.join(d, w)
        try:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        except (OSError, ValueError):
            continue
    return None


def answer_word(w, path_env, root=None, home=None):
    dirs = _path_list(path_env)
    if dirs is None or not isinstance(w, str) or not _BARE.fullmatch(w):
        return None
    p = _which(w, dirs)
    return ident(p, root, home) if p else None


def answer_path(p, root=None, home=None):
    if not isinstance(p, str) or not p.startswith("/") or len(p) > 4096:
        return None
    return ident(p, root, home)


# One form before any comparison (§5 step 1): bash's ANSI-C quoting `$'\x72m'` is the word `rm`, and
# `$"rm"` (a locale string: no catalogue = itself) is `"rm"`. Read as written they were `$\x72m` / `$rm` (an expansion: opaque). Decoded
# here, before the words are cut, into the single-quoted literal bash makes of them; an escape bash itself reads differently (\c, a NUL)
# keeps the word as written (opaque, as before).
_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
                "'": "'", '"': '"', "?": "?"}


def _ansi_body(line, i):
    """-> (decoded text, index after the closing quote) for the $'...' whose body starts at line[i]; None when it cannot be decoded."""
    out, n = [], len(line)
    while i < n:
        ch = line[i]
        if ch == "'":
            return "".join(out), i + 1
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            return None
        e = line[i + 1]
        if e in _ANSI_SIMPLE:
            out.append(_ANSI_SIMPLE[e])
            i += 2
        elif e in "01234567":
            m = re.match(r"[0-7]{1,3}", line[i + 1:])
            v = int(m.group(0), 8) & 0xFF
            if v == 0:
                return None                          # a NUL ends the word in bash: not ours to guess
            out.append(chr(v))
            i += 1 + len(m.group(0))
        elif e in "xuU":
            m = re.match(r"[0-9A-Fa-f]{1,%d}" % {"x": 2, "u": 4, "U": 8}[e], line[i + 2:])
            if not m:
                return None
            v = int(m.group(0), 16)
            if v == 0 or v > 0x10FFFF or 0xD800 <= v <= 0xDFFF:
                return None
            out.append(chr(v))
            i += 2 + len(m.group(0))
        elif e == "c":
            return None                              # a control character by name: left as written (opaque)
        else:
            out.append("\\" + e)                    # bash keeps an unknown escape as written
            i += 2
    return None


def ansi_c(line, bad=()):
    if "$'" not in line and '$"' not in line:
        return line
    out, q, i, n = [], None, 0, len(line)
    while i < n:
        ch = line[i]
        if q is None and ch == "\\" and i + 1 < n:
            out.append(line[i:i + 2])
            i += 2
            continue
        if q is None and ch == "$" and line[i + 1:i + 2] == "'":
            r = _ansi_body(line, i + 2)
            if r is not None and not any(ord(x) in bad for x in r[0]):
                out.append("'" + r[0].replace("'", "'\\''") + "'")
                i = r[1]
                continue
        if q is None and ch == "$" and line[i + 1:i + 2] == '"':
            i += 1                                   # $"..." is "..." (no message catalogue)
            continue
        if q is None and ch in "'\"":
            q = ch
        elif q == ch:
            q = None
        elif q == '"' and ch == "\\" and i + 1 < n:
            out.append(line[i:i + 2])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def words(cmd):
    """-> the words of a line as the shell would look them up (quotes and backslashes out), in order, without repeats"""
    out = {}
    if not isinstance(cmd, str) or len(cmd) > 65536:
        return []
    line = ansi_c(cmd)
    heads = []                                        # the word at the place of a command first (a padded line keeps its programs)
    for seg in _SEG.split(line):
        toks = seg.split()
        while toks and (_ASSIGN.match(toks[0]) or _UNQ.sub("", toks[0]) in _LEAD):
            toks = toks[1:]
        if toks:
            heads.append(toks[0])
    for t in heads + _SPLIT.split(line):
        w = _UNQ.sub("", t)
        if w and w not in out and not re.search(r"[$*?\[\]~=]", w.lstrip("~")) and not w.startswith("-"):
            out[w] = None
            if len(out) >= MAX_WORDS + MAX_PATHS + 64:
                break                                 # a longer line: the first words only (the rest is judged by the name)
    return list(out)


def fact(cmd, cwd, path_env, root=None, home=None):
    dirs = _path_list(path_env)
    out = {"v": V, "w": {}, "p": {}}
    nw = np_ = 0
    for w in words(cmd):
        if "/" in w or w.startswith("~"):
            if np_ >= MAX_PATHS:
                continue
            e = w
            if e == "~" or e.startswith("~/"):
                if not isinstance(home, str) or not home.startswith("/"):
                    continue
                e = home + e[1:]
            if not e.startswith("/"):
                if not isinstance(cwd, str) or not cwd.startswith("/"):
                    continue
                e = os.path.join(cwd, e)
            e = os.path.normpath(e)
            if e in out["p"]:
                continue
            np_ += 1
            out["p"][e] = ident(e, root, home)          # None: no regular file there (looked at: the witness need not ask)
        elif dirs is not None and _BARE.fullmatch(w) and nw < MAX_WORDS:
            nw += 1
            p = _which(w, dirs)
            out["w"][w] = ident(p, root, home) if p else None     # None: not on the PATH (looked up)
    return out
