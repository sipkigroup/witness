"""Incremental Merkle tree over the append-only ledger hashes (RFC 9162 Section 2.1: tree hash with the 0x00 / 0x01 prefixes and the
largest-power-of-two split, exactly as aar_ref.checkpoint) - same bytes out, O(log n) work per root once the tree is warm.

Why it works: ledger entries are only ever appended, so the root of a FULL subtree (2^k leaves) never changes. Roots of full subtrees with
at least MIN_CACHED leaves are kept in a bounded LRU; a root / path over a prefix of n leaves then touches O(log n) cached nodes plus at
most 2*MIN_CACHED fresh hashes at the right edge. Subtrees smaller than MIN_CACHED are not stored (they are the bulk of the nodes).

Cache key: (first leaf hash, last leaf hash, size). A ledger hash is sha256 of a signed entry that contains `prev`, i.e. a leaf hash commits
to the whole chain before it, so equal (first, last, size) means equal leaves for a valid chain. The verifier checks the chain
independently (verify_file), so a broken chain is reported there whatever this cache returns.

Memory: at most `cap` entries (default 100000, ~25 MB: tuple + 32-byte root + dict slot; the leaf bytes are shared with the ledger list),
env DW_MERKLE_CACHE. Eviction only costs recomputation of the evicted subtree.

The module is self-contained (needs only aar_ref.checkpoint) because it is shipped inside the evidence pack (verify/merklecache.py)
and used by verify_pack.py. `install()` replaces aar_ref.checkpoint.merkle_root / inclusion_path (and the names already imported by
aar_ref.state / aar_ref.verify) - the kernel files are not edited. `self_check()` compares with the reference implementation."""
import os
import random
import threading
from collections import OrderedDict

from aar_ref import checkpoint as C
from aar_ref.cose import sha256

MIN_CACHED = 8
DEFAULT_CAP = 100000

_ref_root, _ref_path = C.merkle_root, C.inclusion_path          # the reference implementation, kept for self_check and tests


class Cache:
    def __init__(self, cap=DEFAULT_CAP):
        self.cap = max(0, int(cap))
        self.d = OrderedDict()
        self.lock = threading.Lock()
        self.hits = self.misses = 0

    def get(self, key):
        with self.lock:
            r = self.d.get(key)
            if r is None:
                self.misses += 1
                return None
            self.d.move_to_end(key)
            self.hits += 1
            return r

    def put(self, key, val):
        if not self.cap:
            return
        with self.lock:
            self.d[key] = val
            self.d.move_to_end(key)
            while len(self.d) > self.cap:
                self.d.popitem(last=False)

    def __len__(self):
        return len(self.d)


_cache = Cache(int(os.environ.get("DW_MERKLE_CACHE") or DEFAULT_CAP))


def _root(ls, a, b, cache):
    n = b - a
    if n == 1:
        return C._leaf(ls[a])
    full = (n & (n - 1)) == 0 and n >= MIN_CACHED
    if full:
        key = (ls[a], ls[b - 1], n)
        r = cache.get(key)
        if r is not None:
            return r
    k = C._split(n)
    r = C._node(_root(ls, a, a + k, cache), _root(ls, a + k, b, cache))
    if full:
        cache.put(key, r)
    return r


def merkle_root(leaves, cache=None):
    """Same contract as aar_ref.checkpoint.merkle_root."""
    if not leaves:
        return sha256(b"")
    ls = leaves if isinstance(leaves, list) else list(leaves)
    return _root(ls, 0, len(ls), _cache if cache is None else cache)


def inclusion_path(leaves, index, cache=None):
    """Same contract as aar_ref.checkpoint.inclusion_path: [(side, sibling_hash)] from the leaf up to the root."""
    ls = leaves if isinstance(leaves, list) else list(leaves)
    c = _cache if cache is None else cache
    lo, hi, out = 0, len(ls), []
    while hi - lo > 1:
        m = lo + C._split(hi - lo)
        if index < m:
            out.append(("R", _root(ls, m, hi, c)))
            hi = m
        else:
            out.append(("L", _root(ls, lo, m, c)))
            lo = m
    return out[::-1]


def inclusion_paths(leaves, indices, cache=None):
    """{index: path} for several leaves of ONE tree (shares the cached subtree roots)."""
    ls = leaves if isinstance(leaves, list) else list(leaves)
    return {i: inclusion_path(ls, i, cache) for i in indices}


def self_check(rounds=40, seed=1):
    """Fast vs reference on random trees (sizes 1..200 plus prefixes of one growing list, cold and warm cache). True / False."""
    rnd = random.Random(seed)
    c = Cache(64)
    base = [sha256(b"selfcheck%d" % i) for i in range(200)]
    for _ in range(rounds):
        n = rnd.randint(1, 200)
        ls = base[:n]
        if merkle_root(ls, c) != _ref_root(ls):
            return False
        i = rnd.randrange(n)
        if inclusion_path(ls, i, c) != _ref_path(ls, i):
            return False
    return merkle_root([], c) == _ref_root([])


_installed = False


def install():
    """Route the kernel's Merkle functions through the cache. Idempotent. Returns True when installed."""
    global _installed
    if _installed:
        return True
    if (os.environ.get("DW_MERKLE_FAST") or "1").lower() in ("0", "off", "false", "no"):
        return False
    if not self_check():
        return False
    C.merkle_root, C.inclusion_path = merkle_root, inclusion_path
    for modname in ("aar_ref.state", "aar_ref.verify"):      # these did `from .checkpoint import merkle_root` at import time
        mod = __import__(modname, fromlist=["x"])
        if getattr(mod, "merkle_root", None) is _ref_root:
            mod.merkle_root = merkle_root
    _installed = True
    return True


def stats():
    return {"entries": len(_cache), "cap": _cache.cap, "hits": _cache.hits, "misses": _cache.misses, "installed": _installed}
