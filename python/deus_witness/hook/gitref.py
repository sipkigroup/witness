"""0.2.53 (red team, `branch`): what switching the working copy at `top` to `ref` would rewrite. ONE file, two copies kept byte-equal
(server/app/hookjudge/gitref.py and mcp/deus_witness/hook/gitref.py; server/tests/test_0253_branch.py compares them): the thin hook runs it on
the user's machine and sends the answer as a fact (facts.fs.gitref), the server's LocalFS runs it in tests and the fatigue harness.

  answer(top, ref, avoid=(the project root,)) -> None                     git could not say (no git, not this repository's top, unborn HEAD, a timeout ...)
                    | {"commit": False}        `ref` names no commit (git checkout X then means the path X; switch fails or guesses)
                    | {"commit": True, "paths": [changed paths relative to top], "more": bool, "special": [why it is more than files]}

The server decides (bashparse._lw_ref): the switch is the plain listed form only when every changed path is an ordinary project file.
Only git plumbing that reads objects and refs runs (rev-parse, for-each-ref, diff-tree): no work tree, no index, no fsmonitor, no textconv,
no external diff, no hooks, no pager; GIT_* variables that point git elsewhere are dropped.
`ref` "-" means the previous branch (@{-1}). A name that is no commit but is a branch of exactly one remote is what `git checkout/switch X`
guesses (--guess, the default): answered for that remote branch."""
from __future__ import annotations

import os
import shutil
import subprocess

MAX_PATHS = 1000
MAX_BYTES = 64 * 1024
TIMEOUT = 5
HOOKS = ("post-checkout", "reference-transaction")      # run by checkout/switch after the tree changed: may read the new tree
_KEEP = ("PATH", "HOME", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "USERPROFILE", "XDG_CONFIG_HOME")


def _git_exe(env, avoid):
    """git from PATH, never from a relative entry or from inside the repository / project (direnv `PATH_add bin`: the agent may write
    there without a question, and the hook would run its `git`)."""
    bad = [os.path.realpath(a) for a in avoid if a]
    dirs = []
    for d in (env.get("PATH") or os.defpath).split(os.pathsep):
        if not d or not os.path.isabs(d):
            continue
        r = os.path.realpath(d)
        if any(r == b or r.startswith(b.rstrip(os.sep) + os.sep) for b in bad):
            continue
        dirs.append(d)
    exe = shutil.which("git", path=os.pathsep.join(dirs)) if dirs else None
    if exe is not None and any(os.path.realpath(exe).startswith(b.rstrip(os.sep) + os.sep) for b in bad):
        return None                                      # a link out of PATH into the project
    return exe


def _run(exe, top, env, *args):
    r = subprocess.run([exe, "--no-pager", "-C", top, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"] + list(args),
                       capture_output=True, timeout=TIMEOUT, env=env, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout


def answer(top, ref, env=None, avoid=()):
    try:
        return _answer(top, ref, os.environ if env is None else env, (top,) + tuple(avoid))
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeDecodeError):
        return None


def _answer(top, ref, src_env, avoid):
    if not isinstance(top, str) or not isinstance(ref, str) or not ref or "\n" in ref or "\0" in ref or len(ref) > 1024:
        return None
    exe = _git_exe(src_env, avoid)
    if exe is None or not os.path.isdir(os.path.join(top, ".git")):
        return None
    env = {k: v for k, v in src_env.items() if k in _KEEP}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
    rc, out = _run(exe, top, env, "rev-parse", "--show-toplevel")
    if rc != 0 or os.path.realpath(out.decode("utf-8").strip()) != os.path.realpath(top):
        return None
    rc, head = _run(exe, top, env, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    if rc != 0:
        return None
    want = "@{-1}" if ref == "-" else ref
    rc, sha = _run(exe, top, env, "rev-parse", "--verify", "--quiet", "--end-of-options", want + "^{commit}")
    if rc != 0 and ref != "-" and not ref.startswith("-") and not any(c in ref for c in "*?[\\"):
        rc2, refs = _run(exe, top, env, "for-each-ref", "--format=%(refname)", "refs/remotes/*/" + ref)
        names = [x for x in refs.decode("utf-8").split("\n") if x] if rc2 == 0 else []
        if len(names) == 1:
            rc, sha = _run(exe, top, env, "rev-parse", "--verify", "--quiet", "--end-of-options", names[0] + "^{commit}")
    if rc != 0:
        return None if ref == "-" else {"commit": False}
    rc, raw = _run(exe, top, env, "diff-tree", "-r", "-z", "--no-renames", "--no-ext-diff", "--no-textconv", "--raw",
                   head.decode().strip(), sha.decode().strip())
    if rc != 0:
        return None
    paths, special, more, size = [], [], False, 0
    f = raw.split(b"\0")
    i = 0
    while i + 1 < len(f):
        meta, p = f[i].decode("ascii"), f[i + 1].decode("utf-8", "surrogateescape")
        i += 2
        modes = meta.lstrip(":").split(" ")[:2]
        if "160000" in modes:
            special.append("submodule " + p)             # a submodule's commit changes: its own tree is not seen here
        if len(paths) >= MAX_PATHS or size + len(p) > MAX_BYTES:
            more = True
            continue
        paths.append(p)
        size += len(p) + 1
    rc, hd = _run(exe, top, env, "rev-parse", "--git-path", "hooks")
    if rc != 0:
        return None
    hooks = os.path.realpath(os.path.join(top, hd.decode("utf-8").strip()))
    for h in HOOKS:
        if os.path.isfile(os.path.join(hooks, h)):
            special.append("hook " + h)                  # it runs right after the switch, with the new tree in place
    gitdir = os.path.realpath(os.path.join(top, ".git"))
    rtop = os.path.realpath(top)
    if hooks.startswith(rtop + os.sep) and not (hooks == gitdir or hooks.startswith(gitdir + os.sep)):
        first = os.path.relpath(hooks, rtop).replace(os.sep, "/").split("/")[0]
        if any(p == first or p.startswith(first + "/") for p in paths) or more:
            special.append("hooks directory " + first)  # core.hooksPath in the tree (husky ...): the branch brings its own hooks
    return {"commit": True, "paths": paths, "more": more, "special": special[:64]}
