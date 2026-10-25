# Verifying an evidence pack

The pack (`deus-witness-evidence-<account>-<time>.zip`) contains the ledger, signed checkpoints, receipts, the key registry log, anchor proofs, hashes of the page scripts, and a copy of the verifier.

**Short version.** `pip install deus-witness` (Python 3.10+), then `deus-witness-verify-pack deus-witness-evidence-*.zip --offline` (or `python -m deus_witness.verify_pack <pack.zip> --offline`); the last line must be `RESULT: VALID`. This checker comes from the package (PyPI and the open repository, `python/deus_witness/verify_pack/`), not from the pack, so it does not depend on the pack's author. It checks the signatures, the hash chain, the Merkle roots, the key registry and the anchors; it does not replay the witness's allow/deny decisions against the mandate (the line `trust: verdicts ... NOT replayed` says so). The copy that sits in the pack (`python -I verify/verify_pack.py . --offline` inside the unzipped folder) does replay them, but it is only as honest as the pack: see below. The entries about 0.2.4 to 0.2.6 further down are for readers of older packs; skip them the first time.

## 1. Python verifier (offline)
```
pip install deus-witness                  # the checker from the package, not from the pack; add "deus-witness[verify]" for RFC 3161 tokens and the online anchor check
deus-witness-verify-pack deus-witness-evidence-*.zip --offline      # a .zip or an unzipped folder; same flags as below

# the copy that sits in the pack (replays the decisions too; only as honest as the pack):
unzip deus-witness-evidence-*.zip -d pack
pip install cbor2 cryptography            # plus opentimestamps for the online anchor check
cd pack && python -I verify/verify_pack.py . --offline   # the checker and its modules sit in verify/ of the pack
```
The checker copy in the pack runs as it is: no flag is needed and no warning is printed. It imports its modules only from the folder it sits in (`verify/`); a `verify_pack.py` copied alone, without that folder, ends with `RESULT: INVALID` (ModuleNotFoundError). The flag `--use-pack-code` only adds the pack's own `verify/` folder to the front of the module search path and prints `WARNING: --use-pack-code ...`; with the copy that sits in the pack it changes nothing. Because a doctored pack can carry a doctored checker, a result from the pack's own copy is only as honest as the pack. To lower that trust: read the checker (its files are listed with SHA-256 in `manifest.json`), run it with `--witness-kid=<hex>` (the key id from `https://witness.sipkigroup.com/v1/witness` fetched by you). The JS and Swift verifiers in the repository check the spec vectors, not packs.
The line `complete as of <UTC time> (seq N)` says up to which ledger entry the pack is complete (the manifest is signed by the witness key and the ledger must end with that checkpoint). `manifest: NOT SIGNED` or `INCOMPLETE` makes the result INVALID.
Output lines: `ledger: valid (N entries)` or `ledger: invalid <CODE>@<seq>`; `receipts: K/K included`; `anchor <batch>: bitcoin block <h> (mempool.space=OK blockstream.info=OK)`, `pending` or `MISMATCH`; last line `RESULT: VALID` or `RESULT: INVALID` (exit code 0 / 1). Without `--offline` the anchor is checked against two block explorers.

### What the checker takes on trust (0.2.12, review 7)
The witness key and your own key(s) are read **from the pack itself**: a dishonest operator holds the witness key, so a pack can be consistent and still not be the
witness's. The checker now says so instead of staying silent:
- `witness: kid <hex> (taken from the pack: compare with https://<iss>/v1/witness ...)` and `owner key(s): <hex> (... compare with your devices -- Devices page ...)`.
  Compare them, or let the checker do it: `--witness-kid=<hex>` (at least 16 hex digits of the kid you got from `/v1/witness` earlier, or from a receipt you hold) and
  `--owner-kid=<hex>` (one of the keys your Devices page shows); a mismatch is `INVALID`.
- `anchors: K of N checkpoints under a stamped batch (newest anchored: seq S)`, or `anchors: NONE -- the history is vouched for by the witness alone`. Without an anchor the
  operator could have rewritten the history and re-signed the pack: ask for the anchors, compare with the receipts you hold, or run with `--require-anchors` (no anchored
  checkpoint = `INVALID`). Entries newer than the newest anchored checkpoint are always the witness's word alone.
- `registry: anchored through row S`: the registry heads of a stamped batch are rows of this `registry.json` (`ANCHOR MISMATCH` = the registry was rebuilt: `INVALID`).
- `registry: owner tags ok (...)` (R7-04): every registry row carries a tag of its account in a second hash chain; a row of YOUR account cut down to look like another
  account's (a key removal hidden that way) is `HIDDEN ROW ... INVALID`. Packs from before 0.2.12 say `owner tags: not in this pack`: there, a key removal is confirmed by the
  witness alone. The tags let a reader group the other accounts' rows by account (how many rows, at which positions), not see them.
- Lines `trust: ...` just before `RESULT` list what this run did not prove.

## 2. Independent verifier (Swift, `aarc-wa`)
```
aarc-wa verify-pack pack
```
(`aarc-wa` is built from the Swift sources of the repository; it is optional and not part of the pip packages.)
Prints `ledger: valid` and `RESULT: VALID`. It does not check the anchor. It shares a specification with the Python verifier but not code: two implementations, one author team.

## 3. What a VALID result means
The ledger chain and signatures are intact, every receipt is in it, the registry entry matches the key that signed your mandate and approvals. It does not prove that the agent had no other channels, nor that the page you signed on was honest (see concepts). Corrupt any byte and both verifiers must say `INVALID`; the e2e test of the project does exactly that.

## 4. The anchor
Hourly the server commits a Merkle root over new checkpoints to OpenTimestamps calendars. `pending` is normal for hours; once Bitcoin includes it the pack (downloaded again) shows the block height. A `MISMATCH` is an alarm: keep the pack and tell the operator.


## 0.2.4: promises and tool maps

`promises/<rid>.promise.cose` is the witness's signed inclusion promise for each decision (draft-deus-aar-05 section 9.5). The checker prints `promises: N kept, M pending`; `PROMISE_LATE` or `PROMISE_BROKEN` makes the pack INVALID (the witness broke what it signed); a promise that is not the witness's or not for this ledger is ignored (it is no evidence). `toolmaps/<sha256>.cbor` is the tool map document whose SHA-256 is the `toolmap_sha256` inside the mandate your passkey signed; the checker prints `toolmaps: ...` and rejects a file that does not hash to its name.


## 0.2.5: when a promise is given, and what an unmet one looks like

A promise (MMD 3600 s) is a signed commitment, so the server gives one **only when it can keep it**: `DW_ANCHOR=on`, the last anchor run succeeded and is recent. With `DW_ANCHOR=off` (a server without anchoring) there are **no promises**: the pack then has no `promises/` and nothing can be "late".

What if a promise was given and then the stamp failed (OpenTimestamps calendars down, server stopped for hours)? The checkpoint exists and the ledger is intact; the bound "anchored within an hour" is not met. A signed promise cannot be withdrawn, and an honest witness must not look like a broken one for ever, so:
- the pack exports the **failed batch record** (`anchors/<batch>.json`, `"status": "failed"`, no `.ots`) next to the others;
- the checker prints `promises: ... N PROMISE_UNMET_DISCLOSED` and a line saying which batches were not stamped; the result stays VALID, the time bound of those entries is **unproven**;
- a late promise with **no** such record (or `off` batch) in the pack is still `PROMISE_LATE` and INVALID: the witness cannot hide a failure by leaving the record out, because the missing record leaves the promise late;
- when the stamp is retried later and succeeds, the same checkpoint is anchored by a new batch; the old promise stays "unmet, disclosed" (late), the entry is still anchored.

Reading it: `kept` = anchored in time; `pending` = not yet due; `PROMISE_UNMET_DISCLOSED` = the witness itself shows it missed the bound. Seeing many of those means the operator's anchor job is unhealthy.

### Protected literals in `toolmaps/` (R4-02)
The `patterns` list in a tool map document is `HMAC-SHA256(k_account, class NUL literal)`. `k_account` is derived from the server secret and never leaves the server, so **a holder of the pack cannot recover or test a literal** (a bare sha256 of a phone number is brute-forced in seconds). Consequence for checking **without the secret**: the checker verifies only what needs no secret: that the document hashes to the name of its file and to the `toolmap_sha256` inside the mandate your passkey signed (the tags are opaque but bound). It cannot say which literals the tags stand for; the owner sees the real list on the Data page, and the server compares the sets (`DATA_PATTERNS_CHANGED`). Packs made by 0.2.4 and earlier still contain the bare sha256 form.


## 0.2.6: three readings fixed (interop pass, 19.10.2026)

1. **`now` for promises is the signed `created_t` of the manifest, never the clock of the machine that runs the checker.** A promise is "late" when `created_t` of the pack is past `entry_t + mmd` and no anchored checkpoint covers it: the same pack gives the same verdict today and in five years, and a verifier with a wrong clock cannot change it. (A pack made later than the promise's deadline that still lacks the stamp is exactly the case the disclosure below exists for.)
2. **"Anchored" means two things together: the batch record has status `pending` or `bitcoin`/`confirmed` AND the batch's `.ots` file is in the pack.** A status without the file is a claim, not a stamp, and counts as not anchored (`off` and `pending` without `.ots` both leave the promise to the lateness rule). Whether the `.ots` itself is valid is a further, separate check: the Python checker parses it (a stamp over another digest is `MISMATCH`, INVALID); the Swift checker does not parse `.ots` and only requires the file. A `kept` promise needs an anchored checkpoint whose entry `t` <= `entry_t + mmd` and that covers the entry.
3. **A disclosure must cover the promise.** `PROMISE_UNMET_DISCLOSED` applies to a late promise only when the pack holds a batch record with `"status": "failed"` whose checkpoint covers `seq >= P.seq` (`P.seq` = the POSITION of the promised entry in the presented ledger). A failed batch for an earlier checkpoint does not excuse a later promise (that stays `PROMISE_LATE`). Only `failed` discloses: a batch with status `off` does not (the server then gives no new promises, but one given before and not kept stays late).

The Python checker (`packtools/verify_pack.py`) was brought in line with 2 and 3 in this release (before, any `failed` or `off` record disclosed any late promise, and a bare `pending` status counted as anchored); the Swift checker already behaved so. Packs for each reading: `cloud/server/tests_pack/test_interop_pack.py` (`kept-ots-pending`, `kept-ots-bitcoin`, `pending-status-no-ots`, `failed-batch-covers`, `failed-batch-not-covering`).
