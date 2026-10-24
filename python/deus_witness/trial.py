"""deus-witness try: a trial account in one command, no sign-up form (server 0.2.38+, POST /v1/trial).

  deus-witness try [--url URL] [--project DIR] [--no-browser] [--force]

Run again, it REPLACES the previous trial account while that one has no passkey yet (the older page then says so), so the hook and the
page always talk about the same account. A trial account that already has your passkey is kept: `try` refuses to replace it (it is
yours; --force makes a new one anyway).

What it does, in this order:
  1. prints what the hook will send to the witness (and links to the privacy summary and the coverage table);
  2. asks the witness for a trial account: an agent key + the recommended mandate for THIS project as a draft (nothing is signed);
  3. saves the agent key to <DEUS_WITNESS_HOME or ~/.config/deus-witness>/agent-key.json (mode 600); the hook and the Claude Code plugin
     read it when DEUS_WITNESS_KEY is not set;
  4. opens the witness page in your browser. When Claude Code first needs you, that page asks for two passkey touches (Touch ID / Windows Hello /
     your phone): it becomes your account's key, you sign the drafted mandate with it, and from then on the agent cannot approve anything
     itself.

The link that claims the account is a one-time secret. It goes ONLY to the browser (in the part of the URL after #, which is not sent to any
server) and is never printed, logged or saved by this command - an agent that reads this command's output or your files must not get it.
No browser here (SSH, a container)? The link is written to your terminal (/dev/tty) only, never to stdout or stderr; with no terminal either,
run `deus-witness try` yourself in a terminal, not through the agent.
Unkept, the trial account and its journal are erased after 7 days (the page has a "Keep this account" button)."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time

import httpx

from . import __version__, _compat

DEFAULT_URL = "https://witness.sipkigroup.com"
KEY_FILE = "agent-key.json"
SENT = ("the tool name and the full input of every call the hook sees (shell commands, file paths, URLs, the text of a Write/Edit)",
        "the working directory and the project directory",
        "answers to the witness' questions about paths of that call and SHA-256 fingerprints of project files a command runs")


def home_dir(env=None) -> str:
    e = os.environ if env is None else env
    return e.get("DEUS_WITNESS_HOME") or os.path.join(_compat.home(), ".config", "deus-witness")


def key_path(env=None) -> str:
    e = os.environ if env is None else env
    return e.get("DEUS_WITNESS_KEY_FILE") or os.path.join(home_dir(e), KEY_FILE)


def load_key(env=None) -> dict | None:
    """-> {"key", "url", ...} saved by `deus-witness try`, or None (no file, unreadable, not ours)."""
    try:
        with open(key_path(env), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("key"), str) or not d["key"].startswith("dwk_"):
        return None
    return d


def _save(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp%d" % os.getpid()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _to_tty(text: str) -> bool:
    """Write to the controlling terminal only (never stdout/stderr, which an agent may capture). -> False when there is none."""
    try:
        with open("/dev/tty", "w") as t:
            t.write(text)
        return True
    except OSError:
        return False


def _open_browser(url: str, opener=None) -> bool:
    try:
        import webbrowser
        return bool((opener or webbrowser.open)(url, new=2))
    except Exception:      # noqa: BLE001  no browser here
        return False


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _mark_opened(env) -> None:
    try:
        mark = os.path.join(home_dir(env), "trial-opened")
        os.makedirs(os.path.dirname(mark), exist_ok=True)
        with open(mark, "w") as f:
            f.write(str(int(time.time())))
    except OSError:
        pass


def _retire(old, url, transport, force, path, out):
    """-> None to go on making the new trial, or the exit code. POST /v1/trial/retire with the previous trial key (server 0.2.39+)."""
    base = old.get("url") if isinstance(old.get("url"), str) and old.get("url") else url
    try:
        with httpx.Client(base_url=base.rstrip("/"), timeout=15.0, transport=transport) as h:
            r = h.post("/v1/trial/retire", json={}, headers={"Authorization": "Bearer " + old["key"]})
    except httpx.HTTPError:
        return None                            # cannot ask: the old one expires by itself
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code == 200:
        print("deus-witness try: the previous trial account (no passkey yet) is replaced by a new one; an older trial page in your "
              "browser will say so - use the new page.", file=out)
        return None
    if r.status_code == 409 and j.get("error") == "TRIAL_CLAIMED" and not force:
        print("deus-witness try: your trial account already has your passkey: it is yours, nothing changed (key: %s). Keep using it "
              "(the page: %s/trial.html). To make another trial account anyway: deus-witness try --force" % (path, base.rstrip("/")), file=out)
        return 2
    return None                                # expired, unknown key, an older server (404): make the new one


def run(argv=None, env=None, transport=None, opener=None, out=None) -> int:
    e = dict(os.environ if env is None else env)
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="deus-witness try", description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=e.get("DEUS_WITNESS_URL") or DEFAULT_URL)
    ap.add_argument("--project", default=e.get("CLAUDE_PROJECT_DIR") or os.getcwd(), help="project directory (default: current)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser; write the link to this terminal only")
    ap.add_argument("--force", action="store_true", help="replace the saved agent key even if it belongs to a full account or to a "
                    "trial account that already has your passkey (default: refuse and change nothing)")
    ap.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)       # our own test runs: never counted by the witness
    o = ap.parse_args(argv)
    from .hook.form import default_form
    path = key_path(e)
    old = load_key(e)
    if old is not None and not old.get("trial") and not o.force:
        print("deus-witness try: %s already holds an agent key of a full account; nothing changed (use --force to replace it)." % path, file=out)
        return 2
    url = o.url.rstrip("/")
    if old is not None and old.get("trial"):
        # 0.2.39: the same person runs `try` again: the previous trial account goes if it has no passkey yet (else an older page could
        # claim an account the hook no longer uses: the hook would wait for nobody)
        rc = _retire(old, url, transport, o.force, path, out)
        if rc is not None:
            return rc
    print("Deus Witness trial. The hook will send to %s:" % url, file=out)
    for s in SENT:
        print("  - " + s, file=out)
    print("  Privacy: %s/privacy.html   What is checked: %s/dl/docs/coverage.html" % (url, url), file=out)
    body = {"form": default_form(o.project), "client": {"name": "deus-witness", "version": __version__}}
    if o.internal or e.get("DEUS_WITNESS_INTERNAL") == "1":
        body["internal"] = True
    try:
        with httpx.Client(base_url=url, timeout=30.0, transport=transport) as h:
            r = h.post("/v1/trial", json=body)
    except httpx.HTTPError as x:
        print("deus-witness try: cannot reach %s (%s)" % (url, type(x).__name__), file=out)
        return 1
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code != 200 or not isinstance(j.get("api_key"), str) or not isinstance(j.get("claim_url"), str):
        print("deus-witness try: the witness refused: %s %s" % (j.get("error", r.status_code), j.get("detail", "")), file=out)
        if r.status_code == 429:
            ra = j.get("retry_after") if isinstance(j.get("retry_after"), int) else _int(r.headers.get("retry-after"))
            if ra:
                print("deus-witness try: you can make the next trial account in %d min (at %s). A trial page already open in your browser "
                      "keeps working: press its button again." % ((ra + 59) // 60, time.strftime("%H:%M", time.localtime(time.time() + ra))), file=out)
        return 1
    _save(path, {"key": j["api_key"], "url": url, "agent_id": j.get("agent_id"), "trial": True, "expires_at": j.get("expires_at"),
                 "project": os.path.realpath(o.project), "created_at": int(time.time())})
    link = j["claim_url"]
    shown = False if o.no_browser else _open_browser(link, opener)
    if shown:
        _mark_opened(e)                        # 0.2.39: the hook does not open a second tab for the same account right away
    if not shown:
        shown = _to_tty("\nOpen this link in YOUR browser (do not paste it into the agent; it is shown once):\n  %s\n\n" % link)
    del link
    j.pop("claim", None)                       # nothing below may print it
    print("Trial account ready (expires %s; %d calls a day)." % (time.strftime("%Y-%m-%d", time.gmtime(j.get("expires_at") or 0)), j.get("quota_per_day") or 0), file=out)
    print("Agent key saved to %s (mode 600). The Claude Code plugin and deus-witness-hook use it when DEUS_WITNESS_KEY is not set." % path, file=out)
    if shown:
        print("Next: use Claude Code as usual. The first call that needs you waits; the browser page that just opened asks for two passkey "
              "touches (Touch ID / Windows Hello / phone): one makes the passkey, one signs the rules - nothing is allowed before that, and the agent cannot do it for you.", file=out)
        return 0
    print("No browser and no terminal here: the link that claims the account could not be shown safely. Run `deus-witness try` yourself "
          "in a terminal on this computer (not through the agent).", file=out)
    return 3


def main(argv=None) -> None:
    sys.exit(run(argv))
