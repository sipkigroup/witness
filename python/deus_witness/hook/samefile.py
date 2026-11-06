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
`fs.samefile` {path: credential path}; the witness then judges the path as that credential file.

0.2.77 (red team 31.10, H3; hook 0.2.51): `protected=True` also maps the files a write to which is always the owner's -- the agent's own
configuration (.claude/**, .mcp.json ...: is_agent_config_path) and git's configuration and hooks (is_git_exec_path). Before, an existing
hard link `notes.md` of .claude/settings.json was a plain project file: `echo '{"hooks": {}}' > notes.md` removed the witness' own hook
with no question. PROTECTED is a copy of the server's two patterns (a server test keeps them equal); git's files are looked up by name
(the walk skips .git)."""
from __future__ import annotations

import collections
import os
import re
import stat

MAX_ENTRIES = 20000           # directory entries looked at per call (a project bigger than that: what the walk reached first, top level first)
# never a place of the project's own credentials, often huge: skipped by the walk (the LINK may lie there; it is the target that is looked up)
PRUNE = frozenset({"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
                   ".ruff_cache", ".gradle", ".next", ".cache"})
HOME_FILES = (".netrc", ".git-credentials", ".pgpass", ".npmrc", ".pypirc", ".vault-token", ".terraformrc", ".s3cfg", ".boto", ".my.cnf",
              ".authinfo", ".aws/credentials", ".aws/config", ".docker/config.json", ".kube/config", ".config/gh/hosts.yml",
              ".config/gcloud/application_default_credentials.json", ".azure/accessTokens.json")
HOME_DIRS = (".ssh", ".gnupg", ".aws")      # listed one level deep
# 0.2.77 (H3): bashparse.AGENT_CONFIG_PATH | bashparse.GIT_EXEC_PATH (copies; server test_0277_redteam keeps them equal)
AGENT_CONFIG = re.compile(r"(/\.claude(/(?!projects/[^/]+/memory/)|$)|/\.claude\.json$|/\.mcp\.json$|/\.cursor/(mcp|hooks)\.json$|/\.vscode/(mcp|tasks)\.json$|/claude_desktop_config\.json$|"
                          r"/\.config/claude(/|$)|/Library/Application Support/Claude/|/\.gemini/settings\.json$|/\.windsurf/[^/]+\.json$|"
                          r"/\.codeium/windsurf/mcp_config\.json$|/\.roo/mcp\.json$|/\.kiro/(settings|hooks)/|/\.amazonq/(mcp\.json$|(cli-)?agents/)|"
                          r"/opencode\.jsonc?$)", re.I)
GIT_EXEC = re.compile(r"(/\.gitattributes$|/\.gitmodules$|/\.git[. ]*$|/\.git[. ]*/(.+/)?(config|config\.worktree)$|/\.git[. ]*/(.+/)?hooks(/|$)|/\.gitconfig$|/\.config/git/config$)", re.I)
UNMAPPED = ".claude/(a hard link the witness could not map: the project walk was cut)"   # 0.2.77b (R2-5)
HOME_PROTECTED = (".claude/settings.json", ".claude/settings.local.json", ".claude.json", ".mcp.json", ".gitconfig", ".config/git/config")


# 0.2.77 (red team R2-2): core.hooksPath (husky, .githooks ...). git runs the files named as hooks (githooks(5)) from that directory, not
# from .git/hooks; husky 9 sets it to `.husky/_`, whose stubs run `.husky/<hook>`. A write there is judged like .git/hooks (git-config).
# One rule on both sides (the server judge with the hook's exec report, the hook's K1 guard reading .git/config): a write lands in a
# hooks directory of the repository and either has a hook's name or lies under a directory named like one (`.husky/_/h`, the helper
# every husky stub runs). A file of another name in an unusual hooks directory is a script a hook may run, as any other project script.
GIT_HOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "commit-msg",
    "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
    "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change"})
HOOKS_DIR_WORDS = frozenset({".husky", ".githooks", "githooks", ".git-hooks", "git-hooks"})   # not "hooks": src/hooks of React apps


def hooks_gate(p):
    """R2-2: could a write to `p` be a hook git runs from core.hooksPath (a hook's name, or a directory named like a hooks folder)?
    Cheap, on the path alone: only then does the server ask the hook for the repository's report."""
    if not isinstance(p, str) or not p:
        return False
    parts = [x for x in p.replace("\\", "/").split("/") if x]
    if not parts:
        return False
    return parts[-1].lower() in GIT_HOOK_NAMES or any(x.lower() in HOOKS_DIR_WORDS for x in parts[:-1])


def hooks_dirs(root, values, home=None):
    """R2-2: core.hooksPath values (as read from the repository's config) -> the absolute directories git runs hooks from, normalized;
    a relative value is relative to the working tree (`root`), `~/` to `home`. husky 9 (`.husky/_`): its parent too (the scripts the
    stubs run). Values that cannot be placed are skipped."""
    out = []
    for v in values or ():
        if not isinstance(v, str) or "\0" in v:
            continue
        v = v.strip()
        if not v:
            continue
        if v == "~" or v.startswith("~/"):
            if not (isinstance(home, str) and home):
                continue
            v = home + v[1:]
        if not os.path.isabs(v):
            if not (isinstance(root, str) and root):
                continue
            v = os.path.join(root, v)
        d = os.path.normpath(v)
        out.append(d)
        if os.path.basename(d) == "_":
            out.append(os.path.dirname(d))
    return list(dict.fromkeys(out))


GLOBAL_GIT_CONFIGS = ("/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig")
MAX_HOOKSPATH = 16


def global_hooks_values(home, env, read, max_bytes=1 << 20, seeds=()):
    """0.2.77c (round 2b, residual risk 1): the core.hooksPath values of git's global and system configuration -- ~/.gitconfig,
    $XDG_CONFIG_HOME/git/config (else ~/.config/git/config), GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM, the system files above -- and of
    every file they (or `seeds`: the repository's own config files) include by include.path / includeIf.*.path, followed whatever the
    condition (more directories only cost a question). `read(text) -> (entries, bad)` is the caller's git config reader. Files only, no
    git process: the hook runs on every call. -> [value, ...] as written (the caller places `~/` and relative ones with hooks_dirs)."""
    env = env if isinstance(env, dict) else {}
    h = home if isinstance(home, str) and home else None
    files = list(GLOBAL_GIT_CONFIGS)
    for k in ("GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"):
        if isinstance(env.get(k), str) and os.path.isabs(env[k]):
            files.append(env[k])
    x = env.get("XDG_CONFIG_HOME")
    if isinstance(x, str) and os.path.isabs(x):
        files.append(os.path.join(x, "git", "config"))
    elif h:
        files.append(os.path.join(h, ".config", "git", "config"))
    if h:
        files.append(os.path.join(h, ".gitconfig"))
    own = [s for s in seeds if isinstance(s, str)]
    queue, seen, vals = [(f, 0, False) for f in files] + [(f, 0, True) for f in own], set(), []
    while queue and len(seen) < 32:
        f, depth, is_seed = queue.pop(0)
        f = os.path.normpath(f)
        if f in seen:
            continue
        seen.add(f)
        try:
            with open(f, "r", encoding="utf-8", errors="surrogateescape", newline="") as fh:
                text = fh.read(max_bytes)
            entries = read(text)[0]
        except Exception:      # noqa: BLE001  missing / unreadable / a reader fault: nothing from that file
            continue
        for k, v in entries:
            lk = k.lower() if isinstance(k, str) else ""
            if not isinstance(v, str):
                continue
            if lk == "core.hookspath" and not is_seed:
                vals.append(v)
            elif (lk == "include.path" or (lk.startswith("includeif.") and lk.endswith(".path"))) and depth < 4 and v.strip():
                q = v.strip()
                if q == "~" or q.startswith("~/"):
                    if not h:
                        continue
                    q = h + q[1:]
                if not os.path.isabs(q):
                    q = os.path.join(os.path.dirname(f), q)
                queue.append((q, depth + 1, False))
    return list(dict.fromkeys(vals))[:MAX_HOOKSPATH]


def hooks_path_hit(p, dirs):
    """R2-2: True when a write to `p` lands directly in one of `dirs` (hooks_dirs) and passes hooks_gate. Compared without case (APFS)."""
    if not isinstance(p, str) or not dirs or not hooks_gate(p):
        return False
    d = os.path.dirname(os.path.normpath(p)).lower()
    return any(isinstance(h, str) and d == os.path.normpath(h).lower() for h in dirs)


def protected(p):
    """0.2.77 (H3): a write to `p` is always the owner's (the agent's configuration, git's configuration or hooks)."""
    return isinstance(p, str) and bool(AGENT_CONFIG.search(p) or GIT_EXEC.search(p))


def links(p):
    """-> os.stat_result when `p` (not followed: the caller already took its realpath) is a regular file with st_nlink > 1, else None."""
    try:
        st = os.lstat(p)
    except (OSError, ValueError, TypeError):
        return None
    return st if stat.S_ISREG(st.st_mode) and st.st_nlink > 1 else None


class Secrets:
    def __init__(self, root, home, is_secret, extra=(), protected=False):
        self.protected = bool(protected)      # 0.2.77 (H3): also the agent's and git's configuration files
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
            if self.protected:
                self._protected()
            self._walk()
        return self._map

    def _protected(self):
        """0.2.77 (H3): git's configuration and hooks of the project (the walk skips .git), and the agent's / git's files of home."""
        if self.home is not None:
            for n in HOME_PROTECTED:
                self._add(os.path.join(self.home, n))
        if self.root is None:
            return
        g = os.path.join(self.root, ".git")
        for p in (g, os.path.join(g, "config"), os.path.join(g, "config.worktree"), os.path.join(self.root, ".mcp.json")):
            self._add(p)
        # 0.2.77b (red team R2-5): the project's .claude by name, before the walk (a big directory scanned first cut the walk before it)
        q, k = collections.deque([os.path.join(self.root, ".claude")]), 0
        while q and k < 256:
            try:
                it = os.scandir(q.popleft())
            except (OSError, ValueError):
                continue
            with it:
                for e in it:
                    k += 1
                    if k >= 256:
                        break
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name != "worktrees":
                                q.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            self._add(e.path, e.stat(follow_symlinks=False))
                    except OSError:
                        continue
        try:
            with os.scandir(os.path.join(g, "hooks")) as it:
                for k, e in enumerate(it):
                    if k >= 256:
                        break
                    try:
                        if e.is_file(follow_symlinks=False):
                            self._add(e.path, e.stat(follow_symlinks=False))
                    except OSError:
                        continue
        except (OSError, ValueError):
            pass

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
                        if self.is_secret(e.path) or self.is_secret(rel) or (self.protected and protected(e.path)):
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
        if hit is None and self.protected and self.cut and self.root is not None:
            # 0.2.77b (red team R2-5): the walk stopped at MAX_ENTRIES and this file has another name somewhere: it may be a hard link of
            # a protected file the walk never reached. Closed by default: judged as the agent's configuration (the owner is asked).
            return os.path.join(self.root, UNMAPPED)
        return hit if isinstance(hit, str) and hit != p else None

    def any_linked(self):
        """-> a credential file of the map that has more than one name (somewhere a hard link to it exists), or None."""
        for (_dev, _ino), p in self.map().items():
            if links(p) is not None:
                return p
        return None
