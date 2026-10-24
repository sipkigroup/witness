"""Checkpoints (Section 9.1): Merkle root over ledger heads + OpenTimestamps anchor INTERFACE ONLY.
No network, no OTS client is called here: this module only fixes the bytes that would be submitted."""
import cbor2
from .cose import sha256

# RFC 6962 style domain separation
def _leaf(b): return sha256(b"\x00" + b)
def _node(l, r): return sha256(b"\x01" + l + r)


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves):
    """leaves: list of bytes (e.g. ledger heads). Empty -> sha256(b'')."""
    if not leaves:
        return sha256(b"")
    def rec(ls):
        if len(ls) == 1:
            return _leaf(ls[0])
        k = _split(len(ls))
        return _node(rec(ls[:k]), rec(ls[k:]))
    return rec(list(leaves))


def inclusion_path(leaves, index):
    def rec(ls, i):
        if len(ls) == 1:
            return []
        k = _split(len(ls))
        if i < k:
            return rec(ls[:k], i) + [("R", merkle_root(ls[k:]))]
        return rec(ls[k:], i - k) + [("L", merkle_root(ls[:k]))]
    return rec(list(leaves), index)


def path_sides(index, size):
    """Sides (of the sibling) that RFC 9162 Section 2.1.3 derives for leaf `index` in a tree of `size` leaves, leaf to root."""
    if size == 1:
        return []
    k = _split(size)
    if index < k:
        return path_sides(index, k) + ["R"]
    return path_sides(index - k, size - k) + ["L"]


def verify_inclusion(leaf, path, root, index=None, size=None):
    """path = [(side, sibling_hash)]; with index and size given, the side labels MUST equal the derived ones (-01 Section 9.1)."""
    if index is not None and [x[0] for x in path] != path_sides(index, size):
        return False
    h = _leaf(leaf)
    for side, sib in path:
        h = _node(h, sib) if side == "R" else _node(sib, h)
    return h == root


def checkpoint_payload(ledger_id: bytes, seq: int, head: bytes, t: int, ts_tree_head: bytes = None) -> bytes:
    """Canonical CBOR of the Section 9.1 checkpoint map."""
    m = {"ledger": ledger_id, "seq": seq, "head": head, "t": t}
    if ts_tree_head is not None:
        m["ts_tree_head"] = ts_tree_head
    return cbor2.dumps(m, canonical=True)


def ots_digest(payload_or_root: bytes) -> bytes:
    """The 32-byte digest to submit to OpenTimestamps calendars: SHA-256 of the checkpoint (or the aggregated root)."""
    return sha256(payload_or_root)


class AnchorNotPerformed(Exception):
    pass


def ots_request(digest: bytes, calendars=("calendar-A", "calendar-B")) -> dict:
    """Describes the submission only. Needs >= 2 calendars operated by parties other than the witness (Section 9.2)."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    return {"format": "opentimestamps/v1", "digest_hex": digest.hex(), "calendars": list(calendars),
            "status": "not-submitted"}


def ots_submit(request: dict):
    """STUB. The real client (python-opentimestamps, network) is deliberately NOT called in Step 2."""
    raise AnchorNotPerformed("OTS submission is a Step-3 task (own calendar on VPS, owner's Manual mode)")
