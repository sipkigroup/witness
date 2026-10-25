"""0.2.16: SHA-256 fingerprints of project files, by a list the witness signs (GET /v1/hook/scanlist).

The hook does not know why a file is on the list: the list carries file shapes only (names, name prefixes and suffixes, directory rules),
a few executable names to look up in a project's bin directories, and bounds. The witness asks for a walk of the project root when it
needs one (`need.scan`); the report goes back as a fact. Nothing in the list is executed: names are compared, one regular expression
(a line filter for one file name) is matched against file bytes.
Report: {"root", "files": {relative path: sha256 hex | "unreadable"}, "sizes": {relative path: bytes} (optional, 0.2.22), "git": {absolute path: digest}, "truncated": bool, "rev"}.
0.2.33 (witness 0.2.46): + "gitcfg": {absolute path of a git config file: [[key, value], ...]} (program keys only) and "gitcfg_cut"."""
from __future__ import annotations

import hashlib
import os
import re
import time
import unicodedata


def fold(name: str) -> str:
    """The form a case-insensitive file system compares: NFC, casefold, no trailing dots/spaces (Windows)."""
    return unicodedata.normalize("NFC", name).casefold().rstrip(". ") or name


class Spec:
    """The signed list, ready to match."""

    def __init__(self, lst: dict):
        self.rev = str(lst["rev"])
        self.names = frozenset(lst["names"])
        self.prefixes = tuple(lst["prefixes"])
        self.suffixes = tuple(lst["suffixes"])
        self.dirs = tuple((str(d), str(f)) for d, f in lst["dirs"])
        self.bin_names = tuple(lst["bin_names"])
        self.skip = frozenset(lst["skip_dirs"])
        lim = lst["limits"]
        self.max_entries, self.max_files, self.max_depth = int(lim["entries"]), int(lim["files"]), int(lim["depth"])
        self.max_bytes, self.max_seconds = int(lim["bytes"]), float(lim["seconds"])
        self.filters = {str(k): re.compile(str(v).encode()) for k, v in (lst.get("line_filters") or {}).items()}
        vs = lst.get("venv_site") or {}
        self.site_suffixes, self.site_names = tuple(vs.get("suffixes", ())), frozenset(vs.get("names", ()))
        gc = lst.get("git_config")                    # 0.2.33: the program keys of git's own config files (witness 0.2.46); absent -> not sent
        self.gitcfg = None
        if isinstance(gc, dict):
            self.gitcfg = (tuple(str(x) for x in gc.get("files") or ("config", "config.worktree")), re.compile(str(gc["keys"]), re.I),
                           int(gc["max_entries"]), int(gc["max_value"]))

    def listed(self, path: str) -> bool:
        p = path.replace("\\", "/").rstrip("/")
        parts = [fold(x) for x in p.split("/") if x]
        if not parts:
            return False
        name = parts[-1]
        if name in self.names or any(name.startswith(x) for x in self.prefixes) or any(name.endswith(x) and len(name) > len(x) for x in self.suffixes):
            return True
        dirs = parts[:-1]
        for d, f in self.dirs:
            dp = d.split("/")
            n = len(dp)
            if f == "**":
                if any(dirs[i:i + n] == dp for i in range(len(dirs) - n + 1)) and not name.endswith(".sample"):
                    return True
            elif len(parts) >= n + 1 and parts[-1 - n:-1] == dp:
                if (f == "*" and not name.endswith(".sample")) or (f.startswith("*.") and name.endswith(f[1:])) or f == name:
                    return True
        return False

    def prio(self, rel):
        """Order of the bounded report: an exact name or a directory rule first, then a name pattern; shallow before deep."""
        parts = rel.replace("\\", "/").split("/")
        name = fold(parts[-1])
        named = name in self.names or any(len(parts) > 1 and fold(parts[-2]) == d.split("/")[-1] for d, f in self.dirs)
        return (0 if named else 1, len(parts), rel)


def file_digest(path: str, spec: Spec) -> str:
    h = hashlib.sha256()
    try:
        if os.path.islink(path):
            h.update(b"link:" + os.path.realpath(path).encode("utf-8", "surrogateescape") + b"\0")
        with open(path, "rb") as f:
            data = f.read(spec.max_bytes + 1)
        keep_re = spec.filters.get(os.path.basename(path))
        if keep_re is not None:
            keep, block = [], False
            for line in data.splitlines():
                s = line.strip()
                if block:
                    keep.append(line)
                    block = s != b")"
                elif keep_re.match(line):
                    keep.append(line)
                    block = s.endswith(b"(")
            data = b"\n".join(keep)
        h.update(data)
        return h.hexdigest()
    except (OSError, ValueError):
        return "unreadable"


def _bin_extras(bindir, out, root, spec):
    try:
        have = set(os.listdir(bindir))
    except OSError:
        return
    for n in spec.bin_names:
        for v in (n, n + ".exe", n + ".cmd", n + "-script.py"):
            if v in have:
                full = os.path.join(bindir, v)
                out[os.path.relpath(full, root)] = full


def _venv_extras(d, out, root, spec):
    for b in ("bin", "Scripts"):
        _bin_extras(os.path.join(d, b), out, root, spec)
    for lib in ("lib", "Lib"):
        base = os.path.join(d, lib)
        try:
            pys = [os.path.join(base, x, "site-packages") for x in os.listdir(base) if x.startswith("python")] if lib == "lib" else [os.path.join(base, "site-packages")]
        except OSError:
            continue
        for sp in pys:
            try:
                names = sorted(os.listdir(sp))
            except OSError:
                continue
            for n in names[:2000]:
                if n.endswith(spec.site_suffixes) or n in spec.site_names:
                    full = os.path.join(sp, n)
                    out[os.path.relpath(full, root)] = full


def _git_config_value(path, section, key, spec):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read(spec.max_bytes).splitlines()
    except OSError:
        return None
    cur, val = None, None
    for line in lines:
        t = line.strip()
        if not t or t[0] in "#;":
            continue
        if t.startswith("["):
            cur = t[1:t.find("]")].strip().split()[0].lower() if "]" in t else None
            continue
        if cur == section and "=" in t:
            k, v = t.split("=", 1)
            if k.strip().lower() == key.lower():
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] == '"':
                    v = v[1:-1]
                val = v
    return val


def _git_dirs(root):
    g = os.path.join(root, ".git")
    if os.path.isdir(g):
        return g, g
    if not os.path.isfile(g):
        return None, None
    try:
        with open(g, "r", encoding="utf-8", errors="replace") as f:
            line = f.read(4096).strip().splitlines()[0]
    except (OSError, IndexError):
        return None, None
    if not line.startswith("gitdir:"):
        return None, None
    gd = line[len("gitdir:"):].strip()
    gd = os.path.normpath(gd if os.path.isabs(gd) else os.path.join(root, gd))
    common = gd
    try:
        with open(os.path.join(gd, "commondir"), "r", encoding="utf-8", errors="replace") as f:
            cd = f.read(4096).strip()
        if cd:
            common = os.path.normpath(cd if os.path.isabs(cd) else os.path.join(gd, cd))
    except OSError:
        pass
    return (gd, common) if os.path.isdir(gd) else (None, None)


def git_files(root, spec):
    """git's own files of this working copy, by absolute path: config, config.worktree, info/attributes, hooks/* (git dir, common git dir,
    core.hooksPath)."""
    gd, common = _git_dirs(root)
    if gd is None:
        return {}
    out = {}
    for base in dict.fromkeys((gd, common)):
        for rel in ("config", "config.worktree", "info/attributes"):
            p = os.path.join(base, rel)
            if os.path.isfile(p):
                out[p] = file_digest(p, spec)
    hooks_dirs = [os.path.join(common, "hooks")]
    hp = None
    for cfg in (os.path.join(gd, "config.worktree"), os.path.join(common, "config")):
        hp = hp or _git_config_value(cfg, "core", "hooksPath", spec)
    if hp:
        hp = os.path.expanduser(hp)
        hooks_dirs.append(os.path.normpath(hp if os.path.isabs(hp) else os.path.join(root, hp)))
    for hd in hooks_dirs:
        try:
            names = sorted(os.listdir(hd))
        except OSError:
            continue
        for n in names[:64]:
            p = os.path.join(hd, n)
            if not n.endswith(".sample") and os.path.isfile(p):
                out[p] = file_digest(p, spec)
    return dict(sorted(out.items()))


def with_sizes(rep, root):
    """0.2.22: `rep` + the optional field "sizes" = {relative path: bytes} for the same files (the approval page shows "N bytes" next to the
    digest). A separate step on purpose: `scan` stays the reference walk of the server (a test keeps them equal); an older witness ignores
    the field. A file that cannot be stat'ed has no size. Nothing but integers leaves the machine."""
    if not isinstance(rep, dict) or not isinstance(rep.get("files"), dict):
        return rep
    sizes = {}
    for rel in rep["files"]:
        try:
            sizes[rel] = int(os.stat(os.path.join(root, rel)).st_size)
        except (OSError, ValueError):
            pass
    return dict(rep, sizes=dict(sorted(sizes.items()))) if sizes else rep


_ESC = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}
_GSP = " \t\n\r"                                            # git's isspace (sane_ctype): not \f \v, not Unicode blanks


def _galpha(c):
    return ("a" <= c <= "z") or ("A" <= c <= "Z")          # ASCII only, as git (str.isalpha would take "é")


def _gkey(c):
    return _galpha(c) or ("0" <= c <= "9") or c == "-"


def _gbytes(s):
    """A string read with errors="surrogateescape" -> as git prints it (bytes joined first, then decoded with replace): a continuation
    or an escape may join the halves of a UTF-8 sequence that a decode-first reader would turn into two U+FFFD."""
    try:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return s


def parse_git_config(text: str) -> list:
    """0.2.33: a git config file -> [[key, value], ...] in file order, named as `git config --list --no-includes` names them. See
    read_git_config (the same reader, with its "unsure" flag)."""
    return read_git_config(text)[0]


def read_git_config(text: str) -> tuple:
    """0.2.33: -> (entries, bad). entries: [[key, value], ...] in file order as `git config --list --no-includes` prints them (section and
    the old `[a.B]` form lower case, a quoted subsection as written, a variable without `=` -> "true"). git's rules (config.c
    git_parse_source / get_base_var / get_extended_base_var / parse_value): a UTF-8 BOM at the start is skipped, CRLF is LF, blanks are
    " \\t\\r\\n" only, keys and section names are ASCII, comments # ; outside quotes, quotes, escapes \\n \\t \\b \\" \\\\, a backslash
    before the line end continues the line, blanks inside a value kept, dropped at both ends. Git is not run, includes are not followed.

    bad (fail-closed, the caller sets gitcfg_cut and the witness asks): every line git calls fatal ("bad config line": a broken header or
    one with junk after the subsection, a blank in a header without a quoted subsection, a line that is not `key [= value]`, a key not
    starting with an ASCII letter, an unknown escape, a newline or the end of the file inside quotes), and, though git takes them, what
    the witness's own reader is unsure of: a key before any section, an empty section name, a backslash at the very end of the file, a
    NUL byte (git cuts the value there). After a bad line the reader keeps going from the next line: more keys only cost a question."""
    text = text.replace("\r\n", "\n")
    if text.startswith("﻿"):
        text = text[1:]
    out, sect, i, n = [], None, 0, len(text)
    bad = "\0" in text

    def eol(k):
        while k < n and text[k] != "\n":
            k += 1
        return k

    def header(j):
        """text[j] follows "[" -> (section name, index after "]") or (None, None) where git refuses the header."""
        name = []
        while j < n:
            c = text[j]
            j += 1
            if c == "]":
                return "".join(name).lower(), j
            if c == "\n":
                return None, None
            if c in _GSP:
                while j < n and text[j] in _GSP and text[j] != "\n":
                    j += 1
                if j >= n or text[j] != '"':
                    return None, None
                j, sub = j + 1, []
                while j < n:
                    c = text[j]
                    j += 1
                    if c == "\n":
                        return None, None
                    if c == '"':
                        if j < n and text[j] == "]":
                            return ("".join(name).lower() + "." + "".join(sub) if name else ""), j + 1     # `[ "x"]`: unsure
                        return None, None
                    if c == "\\":
                        if j >= n or text[j] == "\n":
                            return None, None
                        c = text[j]
                        j += 1
                    sub.append(c)
                return None, None
            if not (_gkey(c) or c == "."):
                return None, None
            name.append(c)
        return None, None

    def value(j):
        """text[j] follows "=" -> (value, index, bad)."""
        buf, ln, quote, space, comment, vbad = [], 0, False, "", False, False
        while True:
            if j >= n:
                return "".join(buf), j, vbad or quote          # the end of the file inside quotes
            c = text[j]
            j += 1
            if c == "\n":
                return "".join(buf), j, vbad or quote          # a newline inside quotes
            if comment:
                continue
            if c in _GSP and not quote:
                if ln:
                    space += c
                continue
            if not quote and c in "#;":
                comment = True
                continue
            if space:
                buf.append(space)
                ln, space = ln + len(space), ""
            if c == '"':
                quote = not quote
                continue
            if c == "\\":
                if j >= n:
                    return "".join(buf), j, True               # git takes it (continuation into EOF); we are unsure
                nx = text[j]
                j += 1
                if nx == "\n":
                    continue
                if nx not in _ESC:
                    vbad = True                                # git: an unknown escape is fatal
                buf.append(_ESC.get(nx, nx))
                ln += 1
                continue
            buf.append(c)
            ln += 1

    while i < n:
        c = text[i]
        if c in _GSP:
            i += 1
        elif c in "#;":
            i = eol(i)
        elif c == "[":
            name, j = header(i + 1)
            if not name:
                bad, sect = True, None                        # a broken header: nothing below it is attributed to a section
                i = eol(i) if j is None else j
                continue
            sect, i = name, j
        elif not _galpha(c):
            bad, i = True, eol(i)                             # a key not starting with a letter, junk
        else:
            j = i
            while j < n and _gkey(text[j]):
                j += 1
            key = text[i:j].lower()
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] not in "=\n":
                bad, i = True, eol(i)                         # not `key [= value]` (also `key ; comment`, `key_x`)
                continue
            if j >= n or text[j] == "\n":
                val, i = "true", j
            else:
                val, i, vb = value(j + 1)
                bad = bad or vb
            if sect is None:
                bad = True                                    # a key before any section (git lists it bare; no program key looks so)
            else:
                out.append([_gbytes(sect + "." + key), _gbytes(val)])
    return out, bad


def git_config_report(root, spec: Spec):
    """-> ({absolute path of config / config.worktree of the git dir and the common git dir: [[key, value] whose key matches the list]},
    cut) or (None, False) when the list does not ask for it or there is no git dir. Only matching keys leave the machine (remote URLs and
    their tokens never do); values are cut at max_value, at most max_entries per file; cut = something was cut or could not be read, or
    read_git_config was unsure of a file (a line git refuses: fail-closed, the witness asks)."""
    if spec.gitcfg is None:
        return None, False
    files, rx, max_entries, max_value = spec.gitcfg
    gd, common = _git_dirs(root)
    if gd is None:
        return None, False
    out, cut = {}, False
    for base in dict.fromkeys((gd, common)):
        for rel in files:
            p = os.path.join(base, rel)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="surrogateescape", newline="") as f:  # \r is git's blank; bytes as git
                    text = f.read(spec.max_bytes + 1)
            except (OSError, ValueError):
                cut = True
                continue
            if len(text) > spec.max_bytes:
                text, cut = text[:spec.max_bytes], True
            ent, unsure = [], False
            try:
                got, unsure = read_git_config(text)
            except Exception:      # noqa: BLE001  a reader fault is "unsure", never a silent empty list
                got, unsure = [], True
            cut = cut or unsure                     # a line git refuses (or we are unsure of) -> cut -> the witness asks
            for k, v in got:
                if rx.fullmatch(k):
                    if len(v) > max_value:
                        v, cut = v[:max_value], True
                    ent.append([k, v])
            if len(ent) > max_entries:
                ent, cut = ent[:max_entries], True
            out[p] = ent
    return out, cut


def with_gitcfg(rep, root, spec: Spec):
    """0.2.33: `rep` + "gitcfg" (always when the project has a git dir and the list asks for it, empty lists too) and "gitcfg_cut": true
    when something was cut or unreadable. A separate step, like with_sizes: `scan` stays equal to the witness's reference walk."""
    if not isinstance(rep, dict) or not isinstance(rep.get("files"), dict):
        return rep
    try:
        g, cut = git_config_report(root, spec)
    except Exception:      # noqa: BLE001  never a crash in the hook: the witness asks every time about a cut list
        g, cut = ({}, True) if spec.gitcfg is not None else (None, False)
    if g is None:
        return rep
    rep = dict(rep, gitcfg=g)
    if cut:
        rep["gitcfg_cut"] = True
    return rep


def scan(root, spec: Spec):
    """-> the report for `root`, or None when root is not a directory."""
    if not isinstance(root, str) or not os.path.isabs(root) or not os.path.isdir(root):
        return None
    found = {}
    n, trunc, end = 0, False, time.monotonic() + spec.max_seconds
    extras = {}
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        if time.monotonic() > end:
            trunc = True
            break
        try:
            it = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in it:
            n += 1
            if n > spec.max_entries:
                trunc = True
                stack = []
                break
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if e.name == ".git":
                    continue
                if os.path.isfile(os.path.join(e.path, "pyvenv.cfg")):
                    _venv_extras(e.path, extras, root, spec)
                    continue
                if e.name == "node_modules":
                    _bin_extras(os.path.join(e.path, ".bin"), extras, root, spec)
                    continue
                if e.name in spec.skip:
                    continue
                if depth + 1 <= spec.max_depth:
                    stack.append((e.path, depth + 1))
                else:
                    trunc = True
                continue
            rel = os.path.relpath(e.path, root)
            if spec.listed(rel):
                found[rel] = e.path
    found.update(extras)
    out = {}
    for rel in sorted(found, key=spec.prio):
        if len(out) >= spec.max_files:
            trunc = True
            break
        out[rel] = file_digest(found[rel], spec)
    rep = {"root": root, "files": dict(sorted(out.items())), "truncated": bool(trunc)}
    g = git_files(root, spec)
    if g:
        rep["git"] = g
    return rep
