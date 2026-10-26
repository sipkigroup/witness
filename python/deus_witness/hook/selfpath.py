"""0.2.40 (HN rehearsal 6, K1): where THIS running client lives, so that the agent cannot rewrite the hook that judges it.

A client installed in a venv inside the project (`.venv` activated before `claude`, direnv `PATH_add`) was an ordinary project file
for the default rules: one allowed write to `.venv/bin/deus-witness-hook`, to `site-packages/deus_witness/...` or a new `.pth`, and the
next call ran the agent's code instead of the witness. These places are now the agent's harness (owner-only), wherever they are:
  - the deus_witness package directory this code runs from;
  - sys.prefix / sys.exec_prefix (the venv: bin/, lib/, pyvenv.cfg, every site-packages `.pth`), sys.executable;
  - the site-packages directories this interpreter loads (system and user site);
  - the hook's own executable: sys.argv[0] when it is the hook, and `deus-witness-hook` as found on the PATH of the event.
"/" and anything that would cover the whole home directory are left out (they would make every write owner-only)."""
from __future__ import annotations

import os
import re
import shutil
import site
import sys

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))      # .../deus_witness

# when the client lives inside the project, commands that install into its environment rewrite the hook too (`pip install x` in an
# activated venv): owner-only as well. Only then: a client outside the project leaves these commands alone.
INSTALL_WORDS = re.compile(r"(deus_witness|deus-witness-hook(?!\s+--(?:doctor|version|help|print-form)\b)|site-packages|dist-packages|"
                           r"\.pth(?![\w-])|pyvenv\.cfg|(?<![\w.-])(?:pip3?|uv|uvx|poetry|pdm|pipenv|hatch|conda|mamba|micromamba|"
                           r"virtualenv|ensurepip|easy_install)(?![\w.-])|(?<![\w-])venv(?![\w-]))", re.I)


def _sources(env):
    out = [PKG, sys.prefix, sys.exec_prefix, sys.executable]
    try:
        out += list(site.getsitepackages())
    except AttributeError:                                              # some embedded / old virtualenv builds
        pass
    try:
        if site.ENABLE_USER_SITE:
            out.append(site.getusersitepackages())
    except AttributeError:
        pass
    a0 = sys.argv[0] if sys.argv else ""
    if isinstance(a0, str) and os.path.basename(a0).lower().startswith("deus-witness"):
        out.append(a0)
    path = (env or {}).get("PATH") if isinstance((env or {}).get("PATH"), str) else os.environ.get("PATH")
    w = shutil.which("deus-witness-hook", path=path)
    if w:
        out.append(w)
    return out


def _parts(p):
    return [c for c in re.split(r"[/\\]+", p) if c]


def places(env=None, home=None):
    """-> the set of absolute paths (as given and resolved) of this client's own install."""
    homes = {h for h in (home, (env or {}).get("HOME"), os.path.expanduser("~")) if isinstance(h, str) and h}
    homes |= {os.path.realpath(h) for h in set(homes)}
    out = set()
    for s in _sources(env):
        if not isinstance(s, str) or not s:
            continue
        a = os.path.abspath(s)
        for p in {os.path.normpath(a), os.path.realpath(a)}:
            if len(_parts(p)) < 2 or any(h == p or h.startswith(p.rstrip("/\\") + os.sep) for h in homes):
                continue
            out.add(p)
    return out


def _under(p, base):
    return p == base or p.startswith(base.rstrip("/\\") + os.sep)


def inside(pl, roots):
    """-> True when one of the places `pl` is under one of `roots` (the project, the cwd)."""
    return any(_under(p, r) for p in pl for r in roots if isinstance(r, str) and r)


def shell_target(cmd, pl, roots, home=None):
    """-> what in the Bash command `cmd` names this client's install (an absolute path, a path relative to the project or to ~,
    or, when the client lives inside the project, an install command), or None."""
    words = set(pl)
    for p in pl:
        for r in roots:
            if isinstance(r, str) and r and _under(p, r) and p != r:
                words.add(os.path.relpath(p, r))
        if home and _under(p, home) and p != home:
            words.add("~/" + os.path.relpath(p, home))
    for w in sorted(words, key=len):
        if re.search(r"(?<![\w.-])" + re.escape(w) + r"(?![\w.-])", cmd):
            return w
    if inside(pl, roots):
        m = INSTALL_WORDS.search(cmd)
        if m:
            return m.group(0)
    return None
