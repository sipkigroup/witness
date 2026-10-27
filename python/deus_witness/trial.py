"""deus-witness try: a trial account in one command, no sign-up form (server 0.2.38+, POST /v1/trial).

  deus-witness try [--url URL] [--project DIR] [--no-browser] [--force]

Run again, it REPLACES the previous trial account while that one has no passkey yet (the older page then says so), so the hook and the
page always talk about the same account. A trial account that already has your passkey is kept: `try` refuses to replace it (it is
yours; --force makes a new one anyway). The previous trial is erased only AFTER the new one exists (2710u, a witness with GET
/v1/trial/status): a refusal (the rate limit) leaves it working; with an older witness it is erased first, and a refusal says so.

What it does, in this order:
  1. asks the witness for a trial account: an agent key + the recommended mandate for THIS project as a draft (nothing is signed);
  2. prints what the hook will send to the witness (and links to the privacy summary and the coverage table) - only once it exists (N4);
  3. saves the agent key to <DEUS_WITNESS_HOME or ~/.config/deus-witness>/agent-key.json (mode 600); the hook and the Claude Code plugin
     read it when DEUS_WITNESS_KEY is not set;
  4. opens the witness page in your browser. When Claude Code first needs you, that page asks for two passkey touches (Touch ID / Windows Hello /
     your phone): it becomes your account's key, you sign the drafted mandate with it, and from then on the agent cannot approve anything
     itself.

The link that claims the account is a one-time secret. It goes ONLY to the browser (in the part of the URL after #, which is not sent to any
server) and is never printed, logged or saved by this command - an agent that reads this command's output or your files must not get it.
No browser here (SSH, a container)? The link is written to your terminal (/dev/tty) only, never to stdout or stderr; with no terminal either
(0.2.34), nothing is saved, the trial account is withdrawn (POST /v1/trial/retire) and the exit code is 3: run `deus-witness try` yourself in
a terminal (`uvx --from deus-witness deus-witness try`), not through the agent.
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
TRY_CMD = "uvx --from deus-witness deus-witness try"      # 0.2.40: what a person types; a uv user has no `deus-witness` on PATH
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


REPLACED_TEXT = ("deus-witness try: the previous trial account (no passkey yet) is replaced by a new one; an older trial page in your "
                 "browser will say so - use the new page.")


def _retire(old, url, transport, force, path, out, retired=None):
    """-> None to go on making the new trial, or the exit code. POST /v1/trial/retire with the previous trial key (server 0.2.39+).
    27.10 (polygon series 2, N3): the replacement is printed by run() only once the new account exists; `retired` (a list) gets True."""
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
        if retired is not None:
            retired.append(True)
        return None
    if r.status_code == 409 and j.get("error") == "TRIAL_CLAIMED" and not force:
        _say_claimed(path, base, out)
        return 2
    return None                                # expired, unknown key, an older server (404): make the new one


def _say_claimed(path, base, out):
    print("deus-witness try: your trial account already has your passkey: it is yours, nothing changed (key: %s). Keep using it "
          "(the page: %s/trial.html). To make another trial account anyway: %s --force" % (path, base.rstrip("/"), TRY_CMD), file=out)


def _status(old, url, transport):
    """2710u (polygon series 2, proposal 1): GET /v1/trial/status with the previous trial key, BEFORE anything is made or erased.
    -> "claimed" (it has a passkey, or was kept), "unclaimed", "gone" (401: expired or withdrawn already), or None: a witness without this
    endpoint (older than 2710u: 404) or no answer -> the old order (retire first)."""
    base = old.get("url") if isinstance(old.get("url"), str) and old.get("url") else url
    try:
        with httpx.Client(base_url=base.rstrip("/"), timeout=15.0, transport=transport) as h:
            r = h.get("/v1/trial/status", headers={"Authorization": "Bearer " + old["key"]})
    except httpx.HTTPError:
        return None
    if r.status_code == 401:
        return "gone"
    try:
        j = r.json()
    except ValueError:
        return None
    if r.status_code == 200 and isinstance(j, dict) and isinstance(j.get("claimed"), bool):
        return "claimed" if j["claimed"] else "unclaimed"
    return None


def _withdraw(key, url, transport) -> bool:
    """0.2.34: POST /v1/trial/retire for a trial account nobody can claim. -> True when the witness erased it."""
    try:
        with httpx.Client(base_url=url.rstrip("/"), timeout=15.0, transport=transport) as h:
            return h.post("/v1/trial/retire", json={}, headers={"Authorization": "Bearer " + key}).status_code == 200
    except httpx.HTTPError:
        return False                           # cannot ask: it expires by itself (7 days) and nothing holds its key


INSTALL_HOW = ("in Claude Code: /plugin marketplace add sipkigroup/witness, then /plugin install deus-witness@sipkigroup; or add the hook "
               "to settings.json - https://witness.sipkigroup.com/dl/docs/quickstart.html#hook")
HOOK_MISSING_TEXT = ("The hook is NOT installed yet, so nothing is checked: Claude Code runs every call as before. Install the plugin "
                     "(in Claude Code: /plugin marketplace add sipkigroup/witness, then /plugin install deus-witness@sipkigroup) or add "
                     "the hook to settings.json - https://witness.sipkigroup.com/dl/docs/quickstart.html#hook")


def hook_installed(project, env):
    """0.2.41: is a Witness hook installed for this project, found as the doctors find it: settings.json hooks (user, project, local,
    managed) and the Claude Code plugin as Claude Code registered it (installed_plugins.json + enabledPlugins; installed with the on/off
    state unknown counts as installed). -> True / False / None (could not tell). Read only; never raises."""
    try:
        from .hook import failsafe
        e = dict(env)
        e.pop("CLAUDE_PLUGIN_ROOT", None)
        prj = os.path.abspath(project)
        active, _, _ = failsafe.find_state(prj, e)
        if active:
            return True
        return any(p.get("enabled") is None for p in failsafe.plugin_state(prj, e))
    except Exception:      # noqa: BLE001
        return None


def hook_places(project, env) -> dict:
    """RT-0.2.41 F5: hook_installed() under each Claude Code configuration directory this shell can name: $CLAUDE_CONFIG_DIR (when set)
    and ~/.claude. -> {config dir: True / False / None}. Claude Code uses the CLAUDE_CONFIG_DIR of the shell that starts IT, which may not
    be this one."""
    from .hook import failsafe
    out = {}
    e = dict(env)
    out[failsafe.user_config_dir(e)] = hook_installed(project, e)
    if e.get("CLAUDE_CONFIG_DIR"):
        e.pop("CLAUDE_CONFIG_DIR")
        d = failsafe.user_config_dir(e)
        if d not in out:
            out[d] = hook_installed(project, e)
    return out


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
    retired = []
    later = False                              # 2710u: retire the previous trial only once the new one exists and its link was shown
    if old is not None and old.get("trial"):
        # 0.2.39: the same person runs `try` again: the previous trial account goes if it has no passkey yet (else an older page could
        # claim an account the hook no longer uses: the hook would wait for nobody). 2710u: a refusal must not cost the working one, so
        # with a witness that says the state first, nothing is erased before the new account exists.
        st = _status(old, url, transport)
        if st == "claimed" and not o.force:
            _say_claimed(path, old.get("url") or url, out)
            return 2
        if st in ("claimed", "unclaimed"):
            later = True
        elif st is None:                       # an older witness: the old order (retire first), with the honest text on a refusal
            rc = _retire(old, url, transport, o.force, path, out, retired)
            if rc is not None:
                return rc
    kept = later                               # the previous trial is still there (and its page works) until the retire below
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
        ra = (j.get("retry_after") if isinstance(j.get("retry_after"), int) else _int(r.headers.get("retry-after"))) if r.status_code == 429 else None
        # 27.10 (polygon O8): with retry_after the witness' own text (UTC) is not repeated: one line below, in local time
        print("deus-witness try: the witness refused: %s %s" % (j.get("error", r.status_code), "" if ra else j.get("detail", "")), file=out)
        if r.status_code == 429:
            if ra and retired:             # N3 (27.10): the previous trial is already erased: its page does not keep working
                print("deus-witness try: your previous trial account (no passkey yet) was erased before this refusal, so its page no longer "
                      "works. You can make the next trial account in %d min (at %s)." % ((ra + 59) // 60, time.strftime("%H:%M", time.localtime(time.time() + ra))), file=out)
            elif ra:
                # 2710z: the "page keeps working" sentence is said once: below when the old account is kept, here when it is not
                print("deus-witness try: you can make the next trial account in %d min (at %s)." % ((ra + 59) // 60, time.strftime("%H:%M", time.localtime(time.time() + ra))) +
                      ("" if kept else " A trial page already open in your browser keeps working: press its button again."), file=out)
        if retired and not (r.status_code == 429 and ra):
            print("deus-witness try: your previous trial account (no passkey yet) was erased before this refusal; run this again later.", file=out)
        if kept:                               # 2710u: nothing was erased
            print("deus-witness try: your previous trial account is kept as it was (key: %s); its page keeps working%s" % (path, ": press its button again." if ra and not retired else "."), file=out)
        return 1
    # N4 (27.10): what the hook sends is said once there is an account to send it to
    print("Deus Witness trial. The hook will send to %s:" % url, file=out)
    for s in SENT:
        print("  - " + s, file=out)
    print("  Privacy: %s/privacy.html   What is checked: %s/dl/docs/coverage.html" % (url, url), file=out)
    link = j["claim_url"]
    opened = shown = False if o.no_browser else _open_browser(link, opener)
    if not shown:
        shown = _to_tty("\nOpen this link in YOUR browser (do not paste it into the agent; it is shown once):\n  %s\n\n" % link)
    del link
    j.pop("claim", None)                       # nothing below may print it
    if not shown:
        # 0.2.34: nobody can see the link, so nobody can claim this account: do NOT keep its key (the hook would wait up to 600 s on every
        # call for a touch that cannot come), delete a key file that is already there, and withdraw the account (its claim link dies with it)
        _withdraw(j["api_key"], url, transport)
        if old is not None and old.get("trial") and not kept:
            try:
                os.remove(path)
            except OSError:
                pass
        print("No browser here, and no terminal to show the link in (the link claims the account: it is shown only to a person, never "
              "to this output). Nothing was saved and the trial account was withdrawn, so your calls are not held. Run `%s` "
              "yourself in a terminal (SSH is fine: the link is shown there, and you can open it on your phone or laptop)." % TRY_CMD, file=out)
        if kept:
            print("Your previous trial account is kept as it was (key: %s)." % path, file=out)
        return 3
    if later:
        rc = _retire(old, url, transport, o.force, path, out, retired)
        if rc is not None:                     # its passkey was made meanwhile (on the older page): that one is the person's
            _withdraw(j["api_key"], url, transport)
            print("The page that just opened belongs to a new trial account that was withdrawn again: close it.", file=out)
            return rc
    _save(path, {"key": j["api_key"], "url": url, "agent_id": j.get("agent_id"), "trial": True, "expires_at": j.get("expires_at"),
                 "project": os.path.realpath(o.project), "created_at": int(time.time())})
    if opened:
        _mark_opened(e)                        # 0.2.39: the hook does not open a second tab for the same account right away
    if retired:
        print(REPLACED_TEXT, file=out)         # N3 (27.10): said only now that the new account exists
    print("Trial account ready (expires %s; %d calls a day)." % (time.strftime("%Y-%m-%d", time.gmtime(j.get("expires_at") or 0)), j.get("quota_per_day") or 0), file=out)
    print("Agent key saved to %s (mode 600). The Claude Code plugin and deus-witness-hook use it when DEUS_WITNESS_KEY is not set." % path, file=out)
    page = "the browser page that just opened" if opened else "the page at the link above"     # 0.2.40: --no-browser shows a link
    touches = (page + " asks for two passkey touches (Touch ID / Windows Hello / phone): one makes the passkey, one signs the rules - "
               "nothing is allowed before that, and the agent cannot do it for you.")
    places = hook_places(o.project, e)
    vals = set(places.values())
    hooked = "mixed" if {True, False} <= vals else True if True in vals else False if False in vals else None
    if hooked == "mixed":                      # RT-0.2.41 F5: found under one config dir, not under another: never a flat "NOT installed"
        print("The hook may not be installed: it is there for Claude Code with config dir %s, but not with %s. Claude Code uses the "
              "CLAUDE_CONFIG_DIR of the shell you start it from: start it with the config dir that has the hook, or install it there too "
              "(%s)." % (", ".join(d for d, v in places.items() if v), ", ".join(d for d, v in places.items() if v is False), INSTALL_HOW),
              file=out)
        print("Once the hook is there, the first call that needs you waits; " + touches, file=out)
        return 0
    if hooked is False:                        # 0.2.41 (HN rehearsal 7): a key without a hook checks nothing - say it, never "as usual"
        print(HOOK_MISSING_TEXT, file=out)
        print("(Checked the Claude Code config dir(s) %s. If you start Claude Code with another CLAUDE_CONFIG_DIR, run this with that "
              "one set to check there.)" % ", ".join(places), file=out)
        print("Once the hook is there, the first call that needs you waits; " + touches, file=out)
        return 0
    if hooked is None:
        print("Could not tell whether the Witness hook is installed: run `uvx --from deus-witness deus-witness-hook --doctor` to check.", file=out)
    print("Next: use Claude Code as usual. The first call that needs you waits; " + touches, file=out)
    return 0


def main(argv=None) -> None:
    sys.exit(run(argv))
