"""0.2.73 (N13, polygon series 9): a hard link is the same file under another name. Facts only, no decision.

`realpath` follows a symlink to its target, so `cat link.txt` (a symlink to .env) is judged as reading .env. A hard link has no target:
`h3.txt` made by `ln .env h3.txt` or by a tar entry (LNKTYPE, linkname .env) IS the inode of .env, and before 0.2.73 `cat h3.txt` / Read
h3.txt read the secret with no question and no "secret seen" mark (polygon series 9, N13).

  links(p)          -> the os.stat_result of `p` when it is a regular file with more than one name (st_nlink > 1), else None
  Secrets(...)      -> the credential files of the project root (a breadth-first walk, at most MAX_ENTRIES entries, heavy tool directories
                       left out) and of the home directory (a fixed list), keyed by (st_dev, st_ino); built once, only when asked
  Secrets.alias(p)  -> the credential file that `p` is another name of, or None

Who names a file a credential is the caller's rule (`is_secret`: the server's classifier, or the hook's copy of its two patterns), so this
file is the same on both sides (a test keeps the two copies byte-equal, as gitref.py). The hook sends what alias() found as the fact
`fs.samefile` {path: credential path}; the witness then judges the path as that credential file."""
from __future__ import annotations

import collections
import os
import stat

MAX_ENTRIES = 20000           # directory entries looked at per call (a project bigger than that: what the walk reached first, top level first)
# never a place of the project's own credentials, often huge: skipped by the walk (the LINK may lie there; it is the target that is looked up)
PRUNE = frozenset({"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
                   ".ruff_cache", ".gradle", ".next", ".cache"})
HOME_FILES = (".netrc", ".git-credentials", ".pgpass", ".npmrc", ".pypirc", ".vault-token", ".terraformrc", ".s3cfg", ".boto", ".my.cnf",
              ".authinfo", ".aws/credentials", ".aws/config", ".docker/config.json", ".kube/config", ".config/gh/hosts.yml",
              ".config/gcloud/application_default_credentials.json", ".azure/accessTokens.json")
HOME_DIRS = (".ssh", ".gnupg", ".aws")      # listed one level deep


def links(p):
    """-> os.stat_result when `p` (not followed: the caller already took its realpath) is a regular file with st_nlink > 1, else None."""
    try:
        st = os.lstat(p)
    except (OSError, ValueError, TypeError):
        return None
    return st if stat.S_ISREG(st.st_mode) and st.st_nlink > 1 else None


class Secrets:
    def __init__(self, root, home, is_secret, extra=()):
        self.root = root if isinstance(root, str) and root else None
        self.home = home if isinstance(home, str) and home else None
        self.is_secret = is_secret
        self.extra = tuple(x for x in extra if isinstance(x, str) and x)
        self.cut = False              # the walk stopped at MAX_ENTRIES
        self._map = None

    def map(self):
        """-> {(st_dev, st_ino): path} of the credential files found (regular files only, the first name found wins)."""
        if self._map is None:
            self._map = {}
            for p in self.extra:
                self._add(p)
            self._home()
            self._walk()
        return self._map

    def _add(self, p, st=None):
        try:
            st = st if st is not None else os.lstat(p)
        except (OSError, ValueError):
            return
        if stat.S_ISREG(st.st_mode):
            self._map.setdefault((st.st_dev, st.st_ino), p)

    def _home(self):
        h = self.home
        if h is None:
            return
        for n in HOME_FILES:
            self._add(os.path.join(h, n))
        for d in HOME_DIRS:
            try:
                with os.scandir(os.path.join(h, d)) as it:
                    for k, e in enumerate(it):
                        if k >= 256:
                            break
                        try:
                            if e.is_file(follow_symlinks=False):
                                self._add(e.path, e.stat(follow_symlinks=False))
                        except OSError:
                            continue
            except (OSError, ValueError):
                continue

    def _walk(self):
        root = self.root
        if root is None:
            return
        q, n = collections.deque([root]), 0
        while q:
            d = q.popleft()
            try:
                it = os.scandir(d)
            except (OSError, ValueError):
                continue
            with it:
                for e in it:
                    n += 1
                    if n > MAX_ENTRIES:
                        self.cut = True
                        return
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name not in PRUNE:
                                q.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        rel = e.path[len(root):] if e.path.startswith(root) else e.path
                        if self.is_secret(e.path) or self.is_secret(rel):
                            self._add(e.path, e.stat(follow_symlinks=False))
                    except OSError:
                        continue

    def alias(self, p):
        """-> the credential file `p` is another name of (a hard link), or None (one name only, not a regular file, or no such credential
        file found). A path that is itself a credential by name is judged by its name already: None."""
        st = links(p)
        if st is None:
            return None
        try:
            if self.is_secret(p):
                return None
        except Exception:      # noqa: BLE001
            return None
        hit = self.map().get((st.st_dev, st.st_ino))
        return hit if isinstance(hit, str) and hit != p else None

    def any_linked(self):
        """-> a credential file of the map that has more than one name (somewhere a hard link to it exists), or None."""
        for (_dev, _ino), p in self.map().items():
            if links(p) is not None:
                return p
        return None
