"""0.2.58 (server 0.2.90; FABLE-NOL 03.11 p.5.3, QA 03.11 D6): shadow copies of files the agent writes OUTSIDE the project.

Under the standing mandate a write outside the project (a note in ~/Vault, a file in ~/Documents) is not refused RESOURCE any more: the
witness asks this hook for a shadow copy of the file BEFORE the call runs (`need.shadow = [paths]`), the hook copies it here and answers
`facts.fs.shadow[path] = {"copy", "sha256", "size"}` (or `{"absent": true}` when the file does not exist yet, or `{"failed": why}`), and
the witness judges the write as the pseudo-command "(write outside the project) <path>" of class command, with a receipt. No copy -> the
witness asks the owner instead (never a silent run). The copy is what makes the write reversible, and only a verified copy counts:
`restore()` puts the bytes back exactly (test_0_2_58_shadow.py: write -> undo -> byte for byte), `deus-witness-hook --undo PATH` runs it
for a person at a terminal (the classifier refuses `--undo` from an agent's line: it is a write outside the project again).

Where: <DEUS_WITNESS_HOME or ~/.local/share/deus-witness>/shadow/<16 hex of sha256(path)>/<utc time>-<basename> plus index.jsonl
(one line per copy: path, copy, sha256, size, t). Files over MAX_BYTES, links, directories and anything unreadable are not copied
(`failed`: the witness asks). Copies are never deleted here (a person decides; `prune(days)` is offered for that)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time

MAX_BYTES = 64 * 1024 * 1024
MAX_PER_CALL = 32
MAX_STORE = 1024 * 1024 * 1024      # 0.2.58 (QA G13): the whole store; past it a write outside the project is asked, not copied


def shadow_dir(env=None, home=None) -> str:
    e = os.environ if env is None else env
    base = e.get("DEUS_WITNESS_HOME")
    if not base:
        h = home or e.get("HOME") or os.path.expanduser("~")
        base = os.path.join(h, ".local", "share", "deus-witness")
    return os.path.join(base, "shadow")


def _key(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def save(path: str, env=None, home=None, after_sha256=None) -> dict:
    """-> {"copy", "sha256", "size"} | {"absent": true} | {"failed": why}. Never raises."""
    try:
        if not os.path.isabs(path):
            return {"failed": "relative path"}
        if os.path.islink(path):
            return {"failed": "a symbolic link"}
        if not os.path.lexists(path):
            return {"absent": True}
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return {"failed": "not a regular file"}
        if st.st_size > MAX_BYTES:
            return {"failed": "larger than %d MB" % (MAX_BYTES // (1024 * 1024))}
        d = os.path.join(shadow_dir(env, home), _key(path))
        os.makedirs(d, mode=0o700, exist_ok=True)
        h0 = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h0.update(b)
        prev = entries(path, env, home)
        if prev and prev[-1].get("sha256") == h0.hexdigest() and isinstance(prev[-1].get("copy"), str) and os.path.isfile(prev[-1]["copy"]):
            rec = dict(prev[-1], t=int(time.time()), after=after_sha256)          # G13: the same bytes already kept: one copy, a new record
            with open(os.path.join(shadow_dir(env, home), "index.jsonl"), "a", encoding="utf-8") as ix:
                ix.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return {"copy": rec["copy"], "sha256": rec["sha256"], "size": rec["size"]}
        total = sum(r.get("size") or 0 for r in entries(None, env, home) if isinstance(r.get("copy"), str))
        if total + st.st_size > MAX_STORE:
            return {"failed": "the shadow store is over %d MB: prune it (deus-witness-hook --undo --prune DAYS)" % (MAX_STORE // (1024 * 1024))}
        ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        base = os.path.basename(path)[:120] or "file"
        dst = os.path.join(d, "%s-%06d-%s" % (ts, int((time.time() % 1) * 1e6), base))
        h = hashlib.sha256()
        with open(path, "rb") as f, open(dst, "wb") as g:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
                g.write(b)
        os.chmod(dst, 0o600)
        rec = {"path": path, "copy": dst, "sha256": h.hexdigest(), "size": st.st_size, "mode": st.st_mode & 0o7777, "t": int(time.time()),
               "after": after_sha256}                        # 0.2.58 (QA Н11): what the agent's write will leave (known for Write: its content)
        with open(os.path.join(shadow_dir(env, home), "index.jsonl"), "a", encoding="utf-8") as ix:
            ix.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return {"copy": dst, "sha256": rec["sha256"], "size": st.st_size}
    except (OSError, ValueError) as e:
        return {"failed": (type(e).__name__ + ": " + str(e))[:120]}


def record_absent(path: str, env=None, home=None, after_sha256=None) -> None:
    """The file did not exist before the write: remembered, so that `restore` can remove what the agent created."""
    try:
        d = shadow_dir(env, home)
        os.makedirs(d, mode=0o700, exist_ok=True)
        with open(os.path.join(d, "index.jsonl"), "a", encoding="utf-8") as ix:
            ix.write(json.dumps({"path": path, "absent": True, "t": int(time.time()), "after": after_sha256}, ensure_ascii=False) + "\n")
    except OSError:
        pass


def entries(path: str | None = None, env=None, home=None) -> list:
    """The index, oldest first (all of it, or the copies of one path)."""
    out = []
    try:
        with open(os.path.join(shadow_dir(env, home), "index.jsonl"), encoding="utf-8") as ix:
            for line in ix:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and isinstance(r.get("path"), str) and (path is None or r["path"] == path):
                    out.append(r)
    except OSError:
        pass
    return out


def restore(path: str, env=None, home=None, which: int = -1, force: bool = False) -> dict:
    """Put the shadow copy of `path` back (the latest one by default; `which` indexes its copies, oldest first). An `absent` record
    removes the file the agent created. The copy is verified against its recorded sha256 before anything is written; the bytes are
    written to a temporary file next to the target and renamed over it (never a half-written file). -> {"ok": True, "copy"...} or
    {"ok": False, "why"}."""
    ents = entries(path, env, home)
    if not ents:
        return {"ok": False, "why": "no shadow copy of %s" % path}
    try:
        r = ents[which]
    except IndexError:
        return {"ok": False, "why": "no copy #%d of %s (%d kept)" % (which, path, len(ents))}
    try:
        # 0.2.58 (QA Н11): never erase what a PERSON wrote after the agent: the file must still hold the agent's text (its sha256 was
        # recorded for a Write); when that is unknown (a shell write) or differs, only --force puts the copy back
        if os.path.isfile(path) and not force:
            cur = hashlib.sha256()
            with open(path, "rb") as f:
                for b in iter(lambda: f.read(1 << 20), b""):
                    cur.update(b)
            if not isinstance(r.get("after"), str):
                return {"ok": False, "why": "the agent's write of %s was a shell write (its text unknown): check the file yourself, then --force" % path}
            if cur.hexdigest() != r["after"]:
                return {"ok": False, "why": "%s changed since the agent's write (a person's edit?): not restored; --force overwrites it" % path}
        if r.get("absent"):
            if os.path.lexists(path):
                os.remove(path)
            return {"ok": True, "removed": path, "t": r.get("t")}
        src = r.get("copy")
        if not isinstance(src, str) or not os.path.isfile(src):
            return {"ok": False, "why": "the copy %s is gone" % src}
        h = hashlib.sha256()
        with open(src, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
        if h.hexdigest() != r.get("sha256"):
            return {"ok": False, "why": "the copy %s does not match its recorded sha256: not restored" % src}
        tmp = os.path.join(os.path.dirname(path) or ".", ".%s.dw-undo-%d" % (os.path.basename(path), os.getpid()))
        shutil.copyfile(src, tmp)
        if isinstance(r.get("mode"), int):
            os.chmod(tmp, r["mode"])
        os.replace(tmp, path)
        return {"ok": True, "restored": path, "copy": src, "sha256": r.get("sha256"), "size": r.get("size"), "t": r.get("t")}
    except OSError as e:
        return {"ok": False, "why": (type(e).__name__ + ": " + str(e))[:200]}


def prune(days: int, env=None, home=None) -> int:
    """Delete copies older than `days` (a person's choice, never run by the hook itself). -> number removed."""
    cut = time.time() - days * 86400
    n = 0
    keep = []
    for r in entries(None, env, home):
        if isinstance(r.get("t"), int) and r["t"] < cut:
            if isinstance(r.get("copy"), str):
                try:
                    os.remove(r["copy"])
                    n += 1
                except OSError:
                    pass
            continue
        keep.append(r)
    try:
        with open(os.path.join(shadow_dir(env, home), "index.jsonl"), "w", encoding="utf-8") as ix:
            for r in keep:
                ix.write(json.dumps(r, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return n
