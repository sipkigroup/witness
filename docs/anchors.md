# Anchors: Bitcoin as an internal guarantee, RFC 3161 timestamps

The ledger of each organisation is append-only and signed by the witness; checkpoints are collected into an hourly **batch** and the
Merkle root of the batch is anchored outside. An anchor proves one thing: **this root (and so every checkpoint under it) existed no
later than time T.** It does not prove that the actions were good, that the witness was honest about what it was asked, or anything
about calls that never reached the witness.

## 1. Bitcoin through OpenTimestamps (since 0.1)
- What: the batch root is submitted to OpenTimestamps calendars; after the calendar's transaction is mined (hours), the `.ots` proof
  can be upgraded and checked against a Bitcoin block header.
- What it proves: the root existed before that block. **No trusted third party**: anyone with a Bitcoin node (or block headers) can
  check it; nobody, including us, can backdate it.
- Limits: `pending` for hours after the batch; precision is block time (minutes to hours); checking needs the `opentimestamps` tool and
  block headers; it says nothing about time *after* the root was made.
- In the interface (profile `smb`) it is shown under "Details -> internal guarantee": it is a free layer that protects the evidence
  against our own later edits, not a headline feature for a small business.

## 2. RFC 3161 timestamps (0.2, second anchor)
- What: the same batch root is sent as a timestamp request to each Time-Stamping Authority that is enabled (see section 3); the signed
  responses (`.tsr`) and the TSA certificate chains go into the evidence pack (`anchors/<batch>.tsr.<tsa>`, roots in `anchors/tsa-ca/`).
- What it proves: the TSA signed that it saw the root at `genTime`. `verify_pack.py` checks it offline: the TSA signature, that
  `messageImprint` equals the root, and `genTime` (`tsa <batch>: OK (<tsa>, ...)`).
- **A TSA is a trusted third party** (unlike Bitcoin): you trust its key, its clock and its certificate chain; the root of trust in the
  pack comes from the pack's author (the verifier prints its fingerprint; `--tsa-ca` lets you pin your own).
- **These are NOT qualified time stamps (eIDAS)** and not "legally binding" anywhere: call them "RFC 3161 time stamp from FreeTSA".
  Qualified stamps are separate paid services (a contract for the enterprise plan, not a free second anchor).
- Profile `enterprise` shows both anchors.

### 2.1 Switching it on: `DW_TSA_URL` (0.2.9)
Off by default: with neither `DW_TSA_URL` nor `DW_TSA=on` set, no timestamp request ever leaves the server.
- `DW_TSA_URL=https://tsa.example/tsr` - the RFC 3161 endpoint of ONE TSA you chose (your company's TSA, or a public one whose terms
  allow it: setting the URL is your statement that they do; see section 3 for the services excluded in code).
- `DW_TSA_CA=/path/root.pem` - **required**: the TSA's root certificate (PEM or DER). Without it no reply can be verified, so the server
  refuses to start rather than collect tokens nobody can check. Compare its fingerprint with the TSA's published one over a second channel.
- `DW_TSA_NAME=corp-tsa` - optional short name (`a-z 0-9 -`, default: from the URL host); the token is `anchors/<batch>.tsr.<name>`.
- Checked at start-up: an `http(s)` URL with a host, no `user:password` in it, not Sectigo / Apple / GlobalSign / Entrust, a readable root;
  otherwise the process does not start (`startup refused: DW_TSA_URL: ...`).
- Every batch (every 30 min, the same job as Bitcoin) asks this TSA once for a token over the batch root; the token is kept only if it
  verifies against `DW_TSA_CA` (signature, imprint = root, chain, timeStamping EKU), next to the batch's `.json`/`.ots` in the anchors
  folder, and goes into the evidence pack with the root (`anchors/tsa-ca/<name>.pem`). `verify_pack.py` checks it offline;
  `--tsa-ca=<dir>` pins your own copy of the root instead of trusting the one in the pack.
- With `DW_ANCHOR=off` and `DW_TSA_URL` set, batches are still made and stamped by the TSA only (a closed perimeter with an internal TSA):
  no Bitcoin, and no inclusion promises (those need `DW_ANCHOR=on`, 0.2.5).
- A TSA that is down or answers wrongly never fails the batch: the log says `tsa=0 ok failed=<name>`, the next batch asks again.
- `DW_TSA=on` + `lib/tsa/providers.json` (section 3) still works; both can be on, a name is never asked twice.
- The browser check of the pack (`packcheck.js`) does not verify RFC 3161 tokens; `verify_pack.py` does.

## 3. Status in 0.2.1 - read this before relying on the second anchor
- Which TSA may be asked (decision of 19.10.2026, `cloud/lib/tsa/USLOVIYA.md`; the terms are known from research only, not read
  first-hand): a provider in `cloud/lib/tsa/providers.json` is queried only if `take: true` AND `terms: "allowed"` AND its root
  certificate is on disk. **FreeTSA** is `take: true` (commercial use allowed per research, 1 request/s, no SLA, own root, not
  qualified); **DigiCert** is off (`terms: "unconfirmed"`) until it confirms in writing. **Sectigo, Apple, GlobalSign, Entrust** are
  excluded in code (`EXCLUDED` in `server/app/jobs.py`, by name and by host): their free endpoints are for code signing only.
- **In fact no live TSA is asked yet**: the FreeTSA root `ca/freetsa.pem` is not in the repository (the build sessions had no route to
  freetsa.org), so the anchor job writes `tsa=0` and a WARN line. A person with a browser has to add the root (fingerprint checked over
  two channels), quote the terms in `USLOVIYA.md` and make one live stamp.
- Even then there is ONE free TSA, not two: the requirement "two free independent TSAs" of ARHITEKTURA-0.2 section 7 is dropped. A
  second independent TSA = DigiCert after a written answer, or a paid TSA under contract.
- The whole path was exercised against **two local test TSAs** only. My run of `server/tests_pack/test_team_pack_server.py`
  (19.10.2026) printed `tsa 20261019T020441Z-b2995c14: OK (tsa-a, tsa-b)` and, for the Bitcoin anchor with `DW_ANCHOR=off`,
  `anchor 20261019T020441Z-b2995c14: pending (inclusion in batch root proven; not stamped)`.
- Texts must not promise "two independent timestamp authorities" (OTCHET-0.2.0 section 4 p.3, OTCHET-P0 section 4).

## 4. Which anchor answers which question
| question | ledger + witness signature | Bitcoin (OTS) | RFC 3161 (each enabled TSA) |
|---|---|---|---|
| was entry N changed or removed later? | yes (hash chain, checkpoints) | yes, against our own later edits too | yes, for the batch time |
| did the root exist by time T? | no (the witness's own clock) | yes, block time, trustless | yes, `genTime`, trusting the TSA |
| how soon is it checkable? | at once | hours (`pending` first) | at once |
| who must be trusted? | the witness | nobody (Bitcoin consensus) | each TSA |
| what the action was, whether it was good | receipt + mandate + approvals | no | no |
| calls that bypassed the witness | no | no | no |
