"""Your own agent, no MCP: ask the witness before every risky action. DEUS_WITNESS_KEY = your agent key."""
import os
from deus_witness import Witness

w = Witness(os.environ.get("DEUS_WITNESS_URL", "https://witness.sipkigroup.com"), os.environ["DEUS_WITNESS_KEY"])


def guarded(tool, args, run):
    r = w.act(tool, args)                       # allow AARs are verified against the pinned witness key
    if r.verdict == "defer":                    # the owner must approve; wait up to 50 s, then ask again later
        r = w.wait(r.rid, timeout=50)
    if r.verdict == "pass":
        return run(args)
    if r.verdict != "allow":
        return "blocked: %s (receipt %s)" % (r.reason, r.rid)
    if w.present(r.rid)["result"] != "accept":  # consume the receipt BEFORE acting
        return "blocked: receipt not accepted"
    try:
        out = run(args)
        w.report(r.rid, True)
        return out
    except Exception:
        w.report(r.rid, False)
        raise


if __name__ == "__main__":
    print(guarded("send_email", {"to": "bob@acme.example", "subject": "hi", "body": "hello"}, lambda a: "sent to " + a["to"]))
