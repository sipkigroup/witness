"""Command line of the offline pack checker: `deus-witness-verify-pack <pack.zip | unpacked folder> [flags]`.
A .zip is unpacked into a temporary folder first (names that would leave it, links, oversized packs are refused). Then the checker runs
exactly as `python -I verify/verify_pack.py <folder>` does: it imports its modules only from its own folder, never from the pack.
The last line is `RESULT: VALID` or `RESULT: INVALID`; exit 0 / 1 (64: wrong usage)."""
import os
import stat
import sys
import tempfile
import zipfile

MAX_FILES = 200000
MAX_BYTES = 4 * 1024 ** 3


def _unzip(zpath, dest):
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_BYTES:
            raise ValueError("pack too large")
        base = os.path.realpath(dest)
        for i in infos:
            mode = i.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("link in pack: %s" % i.filename)
            target = os.path.realpath(os.path.join(base, i.filename))
            if target != base and not target.startswith(base + os.sep):
                raise ValueError("path leaves the folder: %s" % i.filename)
        z.extractall(base)


HELP = """usage: deus-witness-verify-pack <pack.zip | unpacked folder> [flags]
Offline check of a Deus Witness evidence pack. Flags (one per argument, value flags are --name=value):
  --offline  --use-pack-code  --require-anchors  --require-views  --witness-kid=<hex>  --owner-kid=<hex>  --tsa-ca=<dir>  (more: see the README)
  --pq-cutoff=YYYY-MM-DD  long-term (post-quantum) mode: only entries under a Bitcoin block before that day count; a calendar's
    pending promise does not (--pq-headers=<json {height: header hex}> gives block headers checked here; online, two explorers)
A folder with bundle.cbor + vector.json is a Mandate Receipt v0 conformance bundle: RESULT: VALID | UNPROVEN <codes> (exit 3) | INVALID <code>
example: deus-witness-verify-pack evidence-pack.zip --offline
exit: 0 pack VALID (also for -h / --help), 1 INVALID, 3 NOT PROVEN (--pq-cutoff), 64 wrong usage (a bad argument is an error, not help)
"""


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return 0
    from . import verify_pack as V
    pos = [i for i, a in enumerate(argv) if not a.startswith("--")]
    if len(pos) == 1:                # 0.2.52: a Mandate Receipt v0 conformance bundle (bundle.cbor + vector.json with the trust anchors)
        from . import mandate_check as MC
        if MC.is_bundle(argv[pos[0]]):
            bad = [a for a in argv if a.startswith("--") and a not in ("--require-views", "--offline")]
            if bad:
                print("verify_pack: a conformance bundle takes only --require-views (got %s)" % ", ".join(map(repr, bad)))
                return 64
            return MC.main_bundle(argv)
    if len(pos) == 1 and os.path.isfile(argv[pos[0]]):
        with tempfile.TemporaryDirectory(prefix="dw-verify-") as tmp:
            try:
                _unzip(argv[pos[0]], tmp)
            except (OSError, ValueError, zipfile.BadZipFile) as e:
                print("pack: cannot be unpacked (%s)" % e)
                print("RESULT: INVALID")
                return 1
            argv[pos[0]] = tmp
            return V.main(argv)
    return V.main(argv)
