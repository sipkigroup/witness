"""Links the client prints for people (sign-up, Agents page, quickstart): always on the witness this client is set up for.

r0274 (open server trial 13.11): a self-hosted witness got https://witness.sipkigroup.com in every hint (quickstart, plugin install,
key help) - it sent the self-hoster to somebody else's service. The base is now the configured witness:
  the URL of the saved agent key (`deus-witness try`, agent-key.json), else DEUS_WITNESS_URL, else the default service -
the same order the hook uses to choose where it sends the key (main.Settings, 0.2.32 K1). The open server serves the same pages
(/signup.html, /dl/docs/quickstart.html), so every link works there.
A value that does not look like a plain http(s) URL is never printed (it may come from a project's settings): the default is used.
"""
from __future__ import annotations

import os
import re

DEFAULT_URL = "https://witness.sipkigroup.com"     # the same value as client.DEFAULT_URL / trial.DEFAULT_URL (tests check)
# r0288: the status page of the DEFAULT service, kept off its server (GitHub Actions + Pages of the open repository). Never shown for
# another witness: a self-hoster names their own with DEUS_WITNESS_STATUS_URL (https only), or none is shown.
DEFAULT_STATUS = "https://sipkigroup.github.io/witness-server/"
_PLAIN = re.compile(r"https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~\-/]*)?")


def site(url=None) -> str:
    """The witness base for a link: `url` if it is a plain http(s) URL (no trailing slash), else the default service."""
    if isinstance(url, str):
        u = url.strip().rstrip("/")
        if _PLAIN.fullmatch(u):
            return u
    return DEFAULT_URL


def configured_url(env=None) -> str:
    """The witness this machine is set up for: the saved agent key's URL, else DEUS_WITNESS_URL, else the default."""
    e = os.environ if env is None else env
    try:
        from .trial import load_key
        d = load_key(e)
    except Exception:  # noqa: BLE001  (a hint never fails the caller)
        d = None
    if d is not None and isinstance(d.get("url"), str) and site(d["url"]) == d["url"].strip().rstrip("/"):
        return site(d["url"])
    return site(e.get("DEUS_WITNESS_URL"))


def quickstart(url=None, anchor: str = "") -> str:
    return site(url) + "/dl/docs/quickstart.html" + anchor


def signup(url=None) -> str:
    return site(url) + "/signup.html"


def status(url=None, env=None):
    """r0288: the status page for the witness at `url` (None = none known). DEUS_WITNESS_STATUS_URL (a plain https URL) wins; the default
    service has DEFAULT_STATUS; any other witness has none (its operator did not tell us one, and ours would be about somebody else)."""
    e = os.environ if env is None else env
    v = (e.get("DEUS_WITNESS_STATUS_URL") or "").strip().rstrip("/")
    if v:
        return v + "/" if v.startswith("https://") and _PLAIN.fullmatch(v) else None
    return DEFAULT_STATUS if isinstance(url, str) and url.strip().rstrip("/") == DEFAULT_URL else None
