#!/usr/bin/env python3
"""Offline checker of a Deus Witness evidence pack.   usage: verify_pack.py <unpacked folder> [--offline] [--use-pack-code]
Needs: python 3.10+, cbor2, cryptography; `opentimestamps` only for the anchor check.
N-05: the checker imports its modules (aar_ref, wa_profile, registry_wa) ONLY from beside itself (or, in the source tree, from the
project layout). Code inside the PACK is never imported unless you pass --use-pack-code (then the pack is trusted as much as its author).
Get this script from a source you trust (wheel / published SHA-256), NOT from the pack you are checking; run it with `python -I`.
Output lines: ledger / receipts / checkpoints / registry / anchor ...; last line RESULT: VALID | RESULT: INVALID; exit 0 / 1.
0.2 (team packs, org/ present): `org policy: chain ok (v1..vN)` | `org policy: BROKEN <code>@v<N>`; second pass
`quorum: K/K entries meet policy-at-time` | `quorum: FAIL <code>@<seq>`; `batch approvals: E envelopes, I items`;
`tsa <batch>: OK (<names>)` | `tsa <batch>: MISMATCH (...)` for RFC 3161 tokens (anchors/<batch>.tsr.<tsa>, roots in anchors/tsa-ca/,
or --tsa-ca=<dir> with roots you trust). A single-owner 0.1 pack prints no org lines. --offline: no network at all.
0.2.2 (several passkeys, recovery): `keys: N keys (A added: P by passkey, R by recovery code (witness-attested); X removed), S/S
signatures by a key active at the time` | `keys: FAIL <code>@<seq|row>`; `org recovery: v<N> replaced key <old> -> <new> (...)`.
0.2.12 (R7-03): the checker says what it took on trust. `witness: kid <hex>` and `owner key(s): <hex>` are read FROM THE PACK: compare them
with https://<iss>/v1/witness and with your own devices, or pass --witness-kid=<hex> / --owner-kid=<hex> (a mismatch is INVALID). `anchors:`
counts the checkpoints under a stamped batch; `anchors: NONE` = the history is vouched for by the witness alone (with --require-anchors that
is INVALID). `registry: anchored through row S`. Lines `trust: ...` before RESULT list what was not proven.
0.2.12 (R7-04): `registry: owner tags ok` -- every row of this account in the second registry chain carries its text (a hidden own row,
e.g. a key removal cut down to seq/prev/hash, is INVALID); a pack from before 0.2.12 says `owner tags: not in this pack`.
0.2.27 (node 2, only when the pack has node2/): `node2: COVERED through seq S ...` | `node2: NOT COVERED (...)` | `node2: ALARM (...)` (INVALID).
Flags: --node2-genesis=<hex> (SHA-256 of the first co-signature), --node2-pin=<file> (default: node2-pin.json next to the pack folder; written
after a good chain), --no-node2-pin-write, --node2-expect=<json file> {policy_sha256, measurement} of the published node 2 build,
--node2-amd-ark=<hex> (an extra AMD root pin: tests only), --require-node2 (NOT COVERED is INVALID).
TEE (Intel TDX, only when the pack has tee/ or an anchor record with a `tee` member; cloud/tee/DIZAIN-TDX.md): `tee <batch>: OK ...` |
`tee <batch>: NO QUOTE (...)` (not credited) | `tee <batch>: <FAILURE> (TEE_QUOTE_MISSING | TEE_QUOTE_INVALID | TEE_BINDING_MISMATCH |
TEE_MEASUREMENT_UNKNOWN)` (INVALID) | `tee: KEY OUTLIVED CODE (TEE_KEY_OUTLIVED_CODE ...)` (INVALID) | `tee: N of M anchored checkpoints ...`.
Flags: --tee-expect=<expect.json>, --tee-intel-root=<pem>, --tee-collateral=<dir>, --tee-now=<unix t>, --require-tee."""
import glob
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


_FLAGS_BOOL = ["--offline", "--require-anchors", "--require-tee", "--require-node2", "--use-pack-code", "--no-node2-pin-write"]
_FLAGS_VAL = ["--witness-kid", "--owner-kid", "--tsa-ca", "--tee-expect", "--tee-intel-root", "--tee-collateral", "--tee-now",
              "--node2-amd-ark", "--node2-expect", "--node2-genesis", "--node2-pin"]


def main(argv):
    """Never raises on bad input: any failure to read or parse the pack ends with a reason line and `RESULT: INVALID`, exit 1."""
    try:
        return _main(argv)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        raise
    except BaseException as e:      # noqa: BLE001  (RecursionError, MemoryError, OSError, ValueError ... on hostile files)
        return _invalid("unreadable or malformed pack (%s)" % type(e).__name__)


def _invalid(why):
    """The reason goes on its own line; the LAST line is always exactly `RESULT: INVALID`."""
    print("pack: %s" % why)
    print("RESULT: INVALID")
    return 1


def _read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def _rb(path):
    with open(path, "rb") as f:
        return f.read()


def _main(argv):
    off = "--offline" in argv
    want_wk = next((a.split("=", 1)[1].lower() for a in argv if a.startswith("--witness-kid=")), None)
    want_ok = next((a.split("=", 1)[1].lower() for a in argv if a.startswith("--owner-kid=")), None)
    need_anchors = "--require-anchors" in argv
    trust = []                               # 0.2.12 (R7-03): what this run took on trust, printed before RESULT
    tsa_ca = next((a.split("=", 1)[1] for a in argv if a.startswith("--tsa-ca=")), None)
    args = [a for a in argv if not a.startswith("--")]
    for a in argv:       # a typo or two flags glued into one word must not pass silently (the check would run without them)
        name, eq, _v = a.partition("=")
        if a.startswith("--") and not (" " not in a and ((name in _FLAGS_BOOL and not eq) or (name in _FLAGS_VAL and eq))):
            print("verify_pack: unknown or malformed argument: %s (one flag per argument; value flags are --name=value)" % repr(a))
            return 2
    if "--require-tee" in argv:
        miss = [n for n in ("--tee-intel-root", "--tee-expect") if not any(a.startswith(n + "=") and len(a) > len(n) + 1 for a in argv)]
        if miss:
            return _invalid("--require-tee needs %s (without them the TEE quotes are not checked against Intel and the expected code)"
                            % " and ".join(m + "=" for m in miss))
    if len(args) != 1 or not os.path.isdir(args[0]):
        print(__doc__)
        return 64
    root = os.path.abspath(args[0])
    dirs = [HERE]
    if "--use-pack-code" in argv:
        print("WARNING: --use-pack-code: executing verifier modules from the pack itself; the result is only as honest as the pack's author")
        dirs.insert(0, os.path.join(root, "verify"))
    for i, d in enumerate(dirs):
        if os.path.isdir(d) and d not in sys.path:
            sys.path.insert(i, d)
    import cbor2  # noqa: F401
    try:        # verify/merklecache.py: same Merkle bytes as aar_ref.checkpoint, O(log n) per checkpoint instead of O(n); self-checks first
        import merklecache
        if not merklecache.install() and os.environ.get("DW_MERKLE_FAST", "1").lower() not in ("0", "off", "false", "no"):
            print("merkle: cache self-check FAILED, using the reference implementation (slow)")
    except ImportError:
        print("merkle: merklecache.py not found next to the pack's aar_ref, using the reference implementation (slow)")
    from aar_ref import cose
    from aar_ref.checkpoint import merkle_root, verify_inclusion
    from aar_ref.verify import load_entries, verify_file
    from registry_wa import WaRegistry
    import wa_profile  # noqa: F401  (imported BEFORE wq_profile: it puts its parent dir on sys.path, which in a pack is the pack root)
    saved = list(sys.path)
    try:
        import wq_profile as wq
    except ImportError:         # a 0.1.x pack checked with --use-pack-code carries no wq_profile.py: fine for a solo pack (org/ -> INVALID below)
        wq = None
    sys.path[:] = saved
    try:
        from registry_wa import QuorumRegistry          # 01's registry: for_account(principal, entry, chain, wa_with_policy)
        q_args = (True,)
    except ImportError:
        try:
            from registry_wq import QuorumRegistry      # 06's checker copy (packtools/registry_wq.py): for_account(principal, entry, chain, rp)
            q_args = None
        except ImportError:
            QuorumRegistry = None

    ok = True
    mp = os.path.join(root, "manifest.json")
    if not os.path.isfile(mp):
        print("manifest: MISSING manifest.json")
        return _invalid("no manifest.json")
    man = _read_json(mp)
    if not isinstance(man, dict) or not isinstance(man.get("files"), dict) or not isinstance(man.get("witness"), dict):
        print("manifest: malformed (need an object with files{} and witness{})")
        return _invalid("manifest malformed")
    # 0. manifest: every file hash
    bad = 0
    for p, h in man["files"].items():
        fp = os.path.abspath(os.path.join(root, p)) if isinstance(p, str) else None
        if fp is None or not fp.startswith(root + os.sep):
            print("manifest: PATH OUTSIDE PACK %r" % (p,)); bad += 1
        elif not os.path.isfile(fp):
            print("manifest: MISSING %s" % p); bad += 1
        elif hashlib.sha256(_rb(fp)).hexdigest() != h:
            print("manifest: MISMATCH %s" % p); bad += 1
    print("manifest: %s (%d files)" % ("ok" if not bad else "%d problems" % bad, len(man["files"])))
    ok &= not bad

    wk = cose.Key.public(cose.ALG_EDDSA, bytes.fromhex(man["witness"]["pub_hex"]))
    if wk.kid.hex() != man["witness"]["kid_hex"]:
        print("witness: kid does not match pub"); ok = False
    iss = man["witness"].get("iss") if isinstance(man["witness"].get("iss"), str) else "<witness>"
    if want_wk is not None:                  # 0.2.12 (R7-03): the witness key the person trusts, not the one the pack names
        good_wk = len(want_wk) >= 16 and wk.kid.hex().startswith(want_wk)
        print("witness: kid %s %s --witness-kid" % (wk.kid.hex()[:16], "matches" if good_wk else "DOES NOT MATCH"))
        ok &= good_wk
    else:
        print("witness: kid %s (taken from the pack: compare with %s/v1/witness, or pass --witness-kid=)" % (wk.kid.hex()[:16], iss.rstrip("/")))
        trust.append("the witness key %s is the witness's (from the pack itself)" % wk.kid.hex()[:16])
    # N-04: the signed manifest (witness key) fixes the file hashes and the checkpoint the ledger must end with
    signed = None
    sp = os.path.join(root, "manifest.cose")
    if not os.path.isfile(sp):
        print("manifest: NOT SIGNED (manifest.cose missing: nothing says up to which entry the pack is complete)")
        ok = False
    else:
        try:
            signed = cose.loads(cose.verify1(_rb(sp), [wk], "application/deus-witness-pack-manifest+cbor")[0])
            if signed.get("files") != man["files"]:
                raise ValueError("files differ")
            print("manifest: signed by the witness key")
        except Exception:   # noqa: BLE001
            print("manifest: SIGNATURE INVALID (manifest.cose is not a witness signature over manifest.json)")
            signed = None
            ok = False
    rp = os.path.join(root, "registry.json")
    if not os.path.isfile(rp):
        print("registry: MISSING registry.json")
        return _invalid("no registry.json")
    reg_doc = _read_json(rp)
    if not isinstance(reg_doc, dict) or not isinstance(reg_doc.get("log"), list) or "principal" not in reg_doc or "entry" not in reg_doc:
        print("registry: malformed")
        return _invalid("registry malformed")
    principal, entry = reg_doc["principal"], reg_doc["entry"]
    org = _load_org(root, man) if os.path.isdir(os.path.join(root, "org")) else None
    if org is not None and (wq is None or QuorumRegistry is None):
        print("org policy: cannot be checked (no wq_profile.py / QuorumRegistry next to the checker)")
        return _invalid("team pack without the team checker")
    keyring = _keyring(wq, reg_doc, principal, entry)            # 0.2.2: None = one pinned key (as 0.2.1)
    if keyring is not None and (wq is None or not hasattr(wq, "key_intervals")):
        print("keys: cannot be checked (no 0.2.2 wq_profile.py next to the checker)")
        return _invalid("pack with key changes without the 0.2.2 checker")
    kw = {} if keyring is None or keyring["error"] else {"keys": keyring["records"]}
    if org is None:
        registry = WaRegistry.for_account(principal, entry, **kw)
        if keyring is not None and QuorumRegistry is not None and q_args:      # a batch revocation (wb) of a solo account
            registry = QuorumRegistry.for_account(principal, entry, (), True, **kw)
    else:
        registry = QuorumRegistry.for_account(principal, entry, org["chain"], *(q_args or (_rp(entry),)), **kw)

    # 1. registry log chain
    prev = b""
    chain_ok = True
    try:
        for r in reg_doc["log"]:
            if bytes.fromhex(r["prev"]) != prev:
                chain_ok = False
            if "entry_json" in r and hashlib.sha256(bytes.fromhex(r["prev"]) + r["entry_json"].encode()).hexdigest() != r["hash"]:
                chain_ok = False
            if "row_json" in r and hashlib.sha256(bytes.fromhex(r["prev"]) + r["row_json"].encode()).hexdigest() != r["hash"]:
                chain_ok = False
            prev = bytes.fromhex(r["hash"])
        own = [r for r in reg_doc["log"] if "entry_json" in r]
        if not own or json.loads(own[-1]["entry_json"]) != entry:
            chain_ok = False
    except Exception:       # malformed log row: the chain cannot be confirmed
        chain_ok = False
    print("registry: %s (%d rows, head %s)" % ("chain ok" if chain_ok else "CHAIN BROKEN", len(reg_doc["log"]), (reg_doc.get("head") or "-")[:16]))
    ok &= chain_ok
    tags_line, tags_bad = _owner_tags(reg_doc["log"])
    print(tags_line)
    ok &= not tags_bad
    if not tags_bad and "not in this pack" in tags_line:
        trust.append("no own registry row (a key removal, a policy change) was cut down to look like another account's (pack before 0.2.12)")
    if keyring is not None:
        if keyring["error"]:
            print("keys: FAIL %s@row %s" % keyring["error"])
            ok = False
    ok &= _owner_key_lines(wq, keyring, entry, want_ok, trust)
    # 0.2.14 (R8-08): a device class (phone / laptop) is the witness's record of what the owner declared (key_device rows), not signed by the owner
    trust.append("the device classes of the keys (key_device rows: the witness alone vouches; no owner signature) and so which "
                 "approvals were made on a phone")
    for line, bad in _device_lines(reg_doc, principal):
        print(line)
        ok &= not bad
    org_ok = False
    if org is not None:
        why = org["error"] or _check_org(wq, org, principal, entry, reg_doc, keyring)
        if why:
            print("org policy: BROKEN %s@v%s" % why)
            ok = False
        else:
            print("org policy: chain ok (v1..v%d)" % len(org["chain"]))
            org_ok = True
            for line in _recoveries(wq, org, _rp(entry)):
                print(line)

    # 2. the ledger (A: aar_ref verifier with the WebAuthn registry), against the newest checkpoint
    ledger_path = os.path.join(root, "ledger", "ledger.cose")
    cps = {}
    for p in glob.glob(os.path.join(root, "checkpoints", "*.cose")):
        stem = os.path.basename(p)[:-5]
        try:
            if not (stem.isascii() and stem.isdigit()):
                raise ValueError(stem)
            cps[int(stem)] = _rb(p)
        except (ValueError, OSError):
            print("checkpoint %s: INVALID (unreadable or not named <seq>.cose)" % os.path.basename(p))
            ok = False
    newest = cps[max(cps)] if cps else None
    if not os.path.isfile(ledger_path):
        print("ledger: MISSING ledger/ledger.cose")
        return _invalid("no ledger")
    try:
        r = verify_file(ledger_path, [wk], set(), registry, principal, checkpoint=newest, require_cose=True)
        entries = load_entries(ledger_path, [wk]) or []
    except Exception as e:  # noqa: BLE001  (garbage in the ledger file: hex, CBOR, encoding)
        r, entries = {"result": "invalid", "reason": "UNREADABLE_%s" % type(e).__name__}, []
    if signed is not None:
        last = entries[-1] if entries else None
        want = signed.get("cp_seq")
        if want is None:
            fine = not entries
        else:
            fine = last is not None and last["type"] == "CHECKPOINT" and last["body"].get("seq") == want and last["body"].get("head") == signed.get("cp_head")
        if fine:
            import datetime
            print("complete as of %s UTC (seq %s)" % (datetime.datetime.fromtimestamp(signed["created_t"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), want))
        else:
            print("pack: INCOMPLETE (the ledger does not end with the checkpoint the signed manifest names)")
            ok = False
    if r["result"] == "valid":
        print("ledger: valid (%d entries)" % len(entries))
        trust.append("verdicts: the witness's allow/deny/defer decisions are NOT replayed here (the decision rules are not in this package); the signatures, hash chain, Merkle roots, key registry and anchors are checked")
    else:
        print("ledger: invalid %s@%s" % (r.get("reason"), r.get("at", "-")))
        ok = False
    # other checkpoints: signature, head and root must fit the entries
    for s, cp in sorted(cps.items()):
        try:
            c = cose.loads(cose.verify1(cp, [wk], cose.TYP_CHECKPOINT)[0])
            fine = c["seq"] < len(entries) and c["head"] == entries[c["seq"]]["hash"] and \
                c["root"] == merkle_root([e["hash"] for e in entries[:c["seq"] + 1]])
        except Exception:
            fine = False
        if not fine:
            print("checkpoint %d: INVALID" % s)
            ok = False
    print("checkpoints: %d" % len(cps))

    # 3. receipts: AAR signed by the witness and equal to the RECEIPT entry at chain.seq
    rc = sorted(glob.glob(os.path.join(root, "receipts", "*.aar.cose")))
    inc = 0
    receipt_seqs = []                        # TEE step: the ledger seq of each included receipt
    for p in rc:
        rid = os.path.basename(p)[:-len(".aar.cose")]
        try:
            raw = _rb(p)
            aar = cose.loads(cose.verify1(raw, [wk], cose.TYP_AAR)[0])
            sub = cose.parse1(raw)[0][cose.H_CWT][cose.CWT_SUB]
            ch = aar["chain"]
            e = entries[ch["seq"]]
            if sub == rid and e["type"] == "RECEIPT" and e["body"]["id"] == rid and e["hash"] == ch["entry"] and e["witness_sig_valid"]:
                inc += 1
                receipt_seqs.append(ch["seq"])
                continue
        except Exception:
            pass
        print("receipt %s: NOT INCLUDED" % rid)
    print("receipts: %d/%d included" % (inc, len(rc)))
    ok &= inc == len(rc)

    # 3a. 0.2.2: every wa-sig / wb in the ledger is by a key that was active at the entry's witnessed time
    if keyring is not None and not keyring["error"]:
        n_sig, fail = _keys_pass(wq, keyring, entries, org["chain"] if org else ())
        if fail:
            print("keys: FAIL %s@%s" % fail)
            ok = False
        else:
            print("keys: %s, %d/%d signatures by a key active at the time" % (keyring["summary"], n_sig, n_sig))

    # 3b. second pass (0.2): every principal-signed entry after the genesis meets the policy in force at its witnessed time
    if org is not None:
        if not org_ok:
            print("quorum: not checked (policy chain broken)")
        else:
            good, total, fail, nb, items = _second_pass(wq, org, entries, principal, entry)
            if fail:
                print("quorum: FAIL %s@%s" % fail)
                ok = False
            else:
                print("quorum: %d/%d entries meet policy-at-time" % (good, total))
            print("batch approvals: %d envelopes, %d items" % (nb, items))
            dg = org.get("deleg") or {}
            if dg.get("n"):
                # 0.2.15: proven from the signed policy in force at each approval's witnessed time (rules.delegation)
                print("org delegation: %d approvals of %d delegated agent(s), 0 by the agent's operator, every signer an approver named "
                      "at that time" % (dg["n"], len(dg["agents"])))
            if dg.get("other"):
                trust.append("%d approval(s) of %d agent(s) the signed policy names in no delegation (rules.delegation): if the server "
                             "applied a delegation to them (set before 0.2.15, before it was moved into the policy), that their operator "
                             "did not confirm them is the witness's word" % (dg["other"], len(dg["other_agents"])))
    if org is not None and not org_ok:
        trust.append("who runs which agent and who may confirm for it (delegation): not checked, the policy chain is broken")
    for line, bad in _declared(root, wq, org, principal, entry):
        print(line)
        ok &= not bad

    # 4. anchors
    leaves_of_cps = {hashlib.sha256(c).hexdigest() for c in cps.values()}
    unmet = []                               # 0.2.5 (R4-01): anchor records that disclose a batch that was NOT stamped ("failed", or "off": anchoring was switched off)
    good_anchors = {}
    anchored_leaves = set()                  # 0.2.4: leaves of checkpoints under a batch that was stamped (OpenTimestamps `pending` or confirmed): the anchored CHECKPOINT entries of promises
    for jp in sorted(glob.glob(os.path.join(root, "anchors", "*.json"))):
        b = os.path.basename(jp)[:-5]
        try:
            a = _read_json(jp)
            b = a["batch"]
            if not isinstance(b, str) or os.path.basename(b) != b:
                raise ValueError("batch")
            path = [(s, bytes.fromhex(h)) for s, h in a["path"]]
            bytes.fromhex(a["root"])
            good = a["leaf"] in leaves_of_cps and verify_inclusion(bytes.fromhex(a["leaf"]), path, bytes.fromhex(a["root"]), a["leaf_index"], a["size"])
        except Exception:   # anchor file with wrong types / missing keys
            print("anchor %s: MISMATCH (malformed anchor file)" % os.path.basename(jp))
            ok = False
            continue
        if not good:
            print("anchor %s: MISMATCH (checkpoint is not under the batch root)" % b)
            ok = False
            continue
        good_anchors[b] = a                  # TEE step: the checkpoint is under this root (the quote is checked against it)
        try:
            print("anchor %s: " % b + _ots(os.path.join(root, "anchors", b + ".ots"), a["root"], off))
        except Exception as e:  # noqa: BLE001  (corrupt .ots)
            print("anchor %s: MISMATCH (unreadable .ots: %s)" % (b, type(e).__name__))
            ok = False
            continue
        if "MISMATCH" in _last:
            ok = False
        elif a.get("status") in ("pending", "bitcoin", "confirmed") and os.path.exists(os.path.join(root, "anchors", b + ".ots")):
            anchored_leaves.add(a["leaf"])      # verify.md 0.2.6: "anchored" = a stamped status AND the .ots file in the pack (a bare status is a claim, not a stamp)
        elif a.get("status") == "failed":
            unmet.append((b, [s_ for s_, raw in cps.items() if hashlib.sha256(raw).hexdigest() == a["leaf"]][0]))      # 0.2.6: only a FAILED batch discloses (`off` does not); kept with the seq its checkpoint covers
    # 4'. 0.2.12 (R7-03): say what the anchors cover -- and that there are none, when there are none
    n_anchor_files = len(glob.glob(os.path.join(root, "anchors", "*.json")))
    anchored_seqs = sorted(s_ for s_, raw in cps.items() if hashlib.sha256(raw).hexdigest() in anchored_leaves)
    if anchored_seqs:
        print("anchors: %d of %d checkpoints under a stamped batch (newest anchored: seq %d)" % (len(anchored_seqs), len(cps), anchored_seqs[-1]))
        if cps and max(cps) > anchored_seqs[-1]:
            trust.append("the entries after seq %d (newer than the newest anchored checkpoint) are vouched for by the witness alone" % anchored_seqs[-1])
    else:
        print("anchors: NONE%s -- the history is vouched for by the witness alone; ask for the anchors or compare with receipts you hold"
              % (" stamped (%d anchor file(s), none stamped)" % n_anchor_files if n_anchor_files else ""))
        trust.append("the whole history (no anchored checkpoint: the witness could have rewritten it)")
        if need_anchors:
            print("anchors: --require-anchors and no anchored checkpoint")
            ok = False
    reg_line, reg_bad = _registry_anchored(root, reg_doc["log"], verify_inclusion)
    if reg_line:
        print(reg_line)
        ok &= not reg_bad
    # 4a. 0.2.4: inclusion promises (draft-deus-aar-05 9.5, 10 step 11), promises/<rid>.promise.cose
    for line, bad in _promises(root, wk, entries, cps, anchored_leaves, signed, unmet):
        print(line)
        ok &= not bad
    for line, bad in _toolmaps(root, entries):
        print(line)
        ok &= not bad
    # 5. RFC 3161 tokens over the batch roots (offline: signature, imprint, chain to the TSA root)
    for line, bad in _tsa_lines(root, tsa_ca):
        print(line)
        ok &= not bad
    # 6. 0.2.27: node 2 (independent co-signer of the journal heads, AMD SEV-SNP); only when the pack has node2/
    for line, bad in _node2_lines(root, cps, argv, trust):
        print(line)
        ok &= not bad
    # 7. TEE (Intel TDX, cloud/tee/DIZAIN-TDX.md): only when the pack carries quotes (or a --tee-*/--require-tee flag asks for them)
    for line, bad in _tee_lines(root, wk, cps, good_anchors, receipt_seqs, argv, trust):
        print(line)
        ok &= not bad
    for t_ in trust:
        print("trust: " + t_)
    print("RESULT: VALID" if ok else "RESULT: INVALID")
    return 0 if ok else 1



TEE_CODE_FIELDS = ("mr_td", "rtmr0", "rtmr1", "rtmr2")      # the OS image + VM config; the app's code is app_events compose-hash (RTMR3)
TEE_QUOTE_CHECKS = ("structure", "quote_sig", "qe_binding", "qe_report_sig", "pck_chain", "intel_root", "debug", "event_log", "tcb_status")


def _tee_att(path):
    """tee/<x>.tdx.json -> (raw quote bytes, event log | None, the document)."""
    import base64
    att = _read_json(path)
    q = base64.b64decode(att["quote_b64"], validate=True)
    ev = att.get("event_log")
    if isinstance(ev, str):
        ev = json.loads(ev) if ev else None
    return q, ev, att


def _tee_check(TQ, wk, q, ev, rd, opts):
    """One quote against the report_data the witness key and the context give. -> (failure line part | None, detail, fingerprint, result)."""
    r = TQ.verify(q, rd, opts["expect"], opts["intel"], ev, opts["col"], opts["now"])
    st = {n: x for n, x, _ in r["checks"]}
    body = r.get("body") or {}
    if st.get("structure") == TQ.FAIL:
        return "INVALID (TEE_QUOTE_INVALID: not a TDX quote)", "", None, r
    if st.get("report_data") == TQ.FAIL:
        if body.get("report_data", "")[:64] != TQ.key_hash(wk.pub).hex():
            return ("FOREIGN KEY (TEE_BINDING_MISMATCH: the quote binds key hash %s.., not the witness key %s that signed the receipts)"
                    % (body.get("report_data", "")[:16], wk.kid.hex()[:16])), "", None, r
        return "BINDING MISMATCH (TEE_BINDING_MISMATCH: report_data is the witness key's but not for this context)", "", None, r
    bad = [n for n in TEE_QUOTE_CHECKS if st.get(n) == TQ.FAIL]
    if bad:
        return "INVALID (TEE_QUOTE_INVALID: %s)" % ", ".join(bad), "", None, r
    fp = (tuple(body.get(f) for f in TEE_CODE_FIELDS), r.get("app_events", {}).get("compose-hash"))
    if st.get("measurements") == TQ.FAIL:
        det = [d for n, x, d in r["checks"] if n == "measurements"][0]
        return "MEASUREMENT UNKNOWN (TEE_MEASUREMENT_UNKNOWN: %s)" % det, "", fp, r
    return None, r["verdict"], fp, r


def _tee_lines(root, wk, cps, good_anchors, receipt_seqs, argv, trust):
    """Receipt -> ledger entry (seq) -> checkpoint -> batch root (step 4) -> anchor record `tee` member -> tee/<bid>.tdx.json (by
    SHA-256) -> report_data = key_hash(witness key) || ctx_batch(bid, root) -> the same witness key that signed the receipts. Plus the
    boot quote of the instance that made the pack, and one key = one code version across all quotes (TEE_KEY_OUTLIVED_CODE)."""
    out = []
    flag = lambda n: next((a.split("=", 1)[1] for a in argv if a.startswith(n + "=")), None)  # noqa: E731
    req = "--require-tee" in argv
    exp_p, root_p, col, now = flag("--tee-expect"), flag("--tee-intel-root"), flag("--tee-collateral"), flag("--tee-now")
    tdir = os.path.join(root, "tee")
    claimed = os.path.isdir(tdir) or any("tee" in a for a in good_anchors.values())
    if not claimed:
        if req or exp_p or root_p:
            out.append(("tee: NONE (the pack carries no TDX quote: nothing says the witness key lives in a TEE)", req))
        return out
    try:
        import tdx_quote as TQ
    except ImportError:
        out.append(("tee: cannot be checked (no tdx_quote.py next to the checker)", True))
        return out
    opts = {"expect": _read_json(exp_p) if exp_p else None, "intel": _rb(root_p) if root_p else None, "col": col,
            "now": float(now) if now else None}
    seq_of = {hashlib.sha256(raw).hexdigest(): s for s, raw in cps.items()}
    codes = []                               # (fingerprint, where) of every quote that checked
    seen_nv, tcb_notes = set(), set()
    attested, unquoted = [], []              # (bid, checkpoint seq)

    def note(r):
        for n, x, _ in r["checks"]:
            if x == TQ.NV:
                seen_nv.add(n)
        if r["verdict"].startswith("TCB_"):
            tcb_notes.add(r["verdict"][4:])

    for b in sorted(good_anchors):
        a = good_anchors[b]
        seq = seq_of.get(a.get("leaf"))
        tm = a.get("tee")
        if not isinstance(tm, dict) or not tm.get("quote_sha256"):
            why = tm.get("error") if isinstance(tm, dict) and isinstance(tm.get("error"), str) else "the anchor record names no quote"
            out.append(("tee %s: NO QUOTE (%s): checkpoint seq %s is not credited with the TEE claim" % (b, why[:120], seq), False))
            unquoted.append((b, seq))
            continue
        want = "tee/%s.tdx.json" % b
        qp = os.path.join(root, "tee", b + ".tdx.json")
        if tm.get("quote") != want or not os.path.isfile(qp):
            out.append(("tee %s: MISSING QUOTE (TEE_QUOTE_MISSING: the anchor record names quote %s.., the pack has no %s)"
                        % (b, str(tm.get("quote_sha256"))[:16], want), True))
            continue
        try:
            q, ev, att = _tee_att(qp)
        except Exception as e:   # noqa: BLE001
            out.append(("tee %s: INVALID (TEE_QUOTE_INVALID: unreadable %s: %s)" % (b, want, type(e).__name__), True))
            continue
        if hashlib.sha256(q).hexdigest() != str(tm["quote_sha256"]).lower():
            out.append(("tee %s: MISMATCH (TEE_QUOTE_MISSING: %s is not the quote the anchor record names)" % (b, want), True))
            continue
        rd = TQ.report_data(wk.pub, TQ.ctx_batch(b, bytes.fromhex(a["root"])))
        fail, verdict, fp, r = _tee_check(TQ, wk, q, ev, rd, opts)
        if fail:
            out.append(("tee %s: %s" % (b, fail), True))
            continue
        note(r)
        codes.append((fp, "batch " + b))
        attested.append((b, seq))
        out.append(("tee %s: OK (quote over batch root + witness key %s; %s)" % (b, wk.kid.hex()[:16], verdict), False))
    bp = os.path.join(tdir, "boot.tdx.json")
    if os.path.isfile(bp):
        try:
            q, ev, att = _tee_att(bp)
            rd = TQ.report_data(wk.pub, TQ.ctx_boot(att["iss"], int(att["t"])))
            fail, verdict, fp, r = _tee_check(TQ, wk, q, ev, rd, opts)
        except Exception as e:   # noqa: BLE001
            fail = "INVALID (TEE_QUOTE_INVALID: unreadable tee/boot.tdx.json: %s)" % type(e).__name__
        if fail:
            out.append(("tee boot: %s" % fail, True))
        else:
            note(r)
            codes.append((fp, "boot t=%s" % att["t"]))
            out.append(("tee boot: OK (the instance that made this pack holds witness key %s; %s)" % (wk.kid.hex()[:16], verdict), False))
    # one witness key, one code version: different OS/VM measurements or a different compose-hash under the same key = the key outlived its code
    bases = {}
    for fp, where in codes:
        bases.setdefault(fp[0], where)
    composes = {}
    for fp, where in codes:
        if fp[1] is not None:
            composes.setdefault(fp[1], where)
    if len(bases) > 1 or len(composes) > 1:
        vs = ["%s from %s" % ("compose-hash " + h[:16], w) for h, w in composes.items()] if len(composes) > 1 else \
             ["mr_td %s.. from %s" % ((k[0] or "")[:16], w) for k, w in bases.items()]
        out.append(("tee: KEY OUTLIVED CODE (TEE_KEY_OUTLIVED_CODE: witness key %s is bound by quotes of %d code versions: %s)"
                    % (wk.kid.hex()[:16], max(len(bases), len(composes)), "; ".join(vs)), True))
    # what the quotes cover
    att_seqs = sorted(s for _, s in attested if s is not None)
    if att_seqs:
        newest = att_seqs[-1]
        cov = sum(1 for s in receipt_seqs if s <= newest)
        out.append(("tee: %d of %d anchored checkpoints under a batch with a valid quote (newest: seq %d); receipts %d/%d covered "
                    "(receipt -> entry -> checkpoint -> batch root -> quote -> witness key %s)"
                    % (len(att_seqs), len(good_anchors), newest, cov, len(receipt_seqs), wk.kid.hex()[:16]), False))
        if cov < len(receipt_seqs):
            trust.append("TEE: the receipts after seq %d (newer than the newest batch with a quote) are not yet covered by a TDX quote" % newest)
        late = [b for b, s in unquoted if s is not None and s > att_seqs[0]]
        if late:
            out.append(("tee: GAP (%d batch(es) without a quote after a quoted one, first %s: the key went on signing without a TDX quote)"
                        % (len(late), late[0]), req))
    else:
        out.append(("tee: NOT ATTESTED (no anchored checkpoint is under a batch with a valid quote)", req))
    if req and unquoted:
        out.append(("tee: --require-tee and %d anchored batch(es) without a quote" % len(unquoted), True))
    if "measurements" in seen_nv:
        trust.append("TEE: which code holds the key -- measurements not compared (pass --tee-expect=<expect.json> rebuilt from the published image)")
    if "intel_root" in seen_nv:
        trust.append("TEE: that the quotes come from Intel hardware -- chain not checked against a pinned Intel SGX Root CA (pass --tee-intel-root=)")
    if "tcb_status" in seen_nv:
        trust.append("TEE: the TCB status of the TDX platform (pass --tee-collateral=<dir> fetched by tdx_quote.py --fetch-collateral)")
    for t_ in sorted(tcb_notes):
        trust.append("TEE: the platform TCB is %s (not UpToDate): a known, unpatched weakness of that platform level" % t_)
    if attested:
        trust.append("TEE: that the code is honest and never exports the key (TDX proves which code runs, not that it is correct: audit the source)")
    return out

def _owner_tags(log):
    """0.2.12 (R7-04): the second registry chain (server/app/reglog.py). -> (line, bad). Every row carries tag + hash2; own rows (with their
    text) give the account's tag; a row with that tag but without its text is an own row cut down to look foreign."""
    if not any("hash2" in r for r in log):
        return "registry: owner tags: not in this pack (made before 0.2.12)", False
    prev2, own_tag, hidden = b"", None, []
    try:
        for r in log:
            if "hash2" not in r or "tag" not in r:
                return "registry: owner tags BROKEN (row %s without tag / hash2)" % r.get("seq"), True
            tg = bytes.fromhex(r["tag"])
            text = r.get("entry_json", r.get("row_json"))
            if text is not None:
                body = hashlib.sha256(text.encode()).digest()
                if own_tag is None:
                    own_tag = tg
                elif tg != own_tag:
                    return "registry: owner tags BROKEN (row %s of this account carries another tag)" % r.get("seq"), True
            else:
                body = bytes.fromhex(r["body"])
            if hashlib.sha256(b"dw-registry-v2\0" + prev2 + tg + body).digest() != bytes.fromhex(r["hash2"]):
                return "registry: owner tags BROKEN (second chain at row %s)" % r.get("seq"), True
            prev2 = bytes.fromhex(r["hash2"])
        hidden = [r.get("seq") for r in log if "entry_json" not in r and "row_json" not in r and bytes.fromhex(r["tag"]) == own_tag]
    except (KeyError, TypeError, ValueError, AttributeError):
        return "registry: owner tags BROKEN (malformed row)", True
    if own_tag is None:
        return "registry: owner tags BROKEN (no row of this account)", True
    if hidden:
        return "registry: HIDDEN ROW of this account at seq %s (its text is missing: a key or policy change cut out of the pack)" % \
            ", ".join(map(str, hidden[:8])), True
    n_own = sum(1 for r in log if "entry_json" in r or "row_json" in r)
    return "registry: owner tags ok (%d rows of this account, all with their text; second chain head %s)" % (n_own, log[-1]["hash2"][:16]), False


def _registry_anchored(root, log, verify_inclusion):
    """0.2.12: anchors/<batch>.json `registry_leaves` -- the registry heads under a batch root. -> (line or "", bad). A head under a root that
    is not a row of registry.json means the registry in the pack is not the one that was anchored."""
    by_hash = {r.get("hash"): r.get("seq") for r in log}
    by_hash2 = {r.get("hash2"): r.get("seq") for r in log if "hash2" in r}
    through, bad = None, []
    for jp in sorted(glob.glob(os.path.join(root, "anchors", "*.json"))):
        try:
            a = _read_json(jp)
            if a.get("status") not in ("pending", "bitcoin", "confirmed") or not os.path.exists(os.path.join(root, "anchors", a["batch"] + ".ots")):
                continue
            for l in a.get("registry_leaves") or []:
                if not verify_inclusion(bytes.fromhex(l["leaf"]), [(s, bytes.fromhex(h)) for s, h in l["path"]], bytes.fromhex(a["root"]),
                                        l["leaf_index"], a["size"]):
                    bad.append(a["batch"])
                    continue
                seq = (by_hash if l["kind"] == "registry" else by_hash2).get(l["leaf"])
                if seq is None:
                    bad.append(a["batch"])
                else:
                    through = max(through or 0, seq)
        except (KeyError, TypeError, ValueError, AttributeError, OSError):
            bad.append(os.path.basename(jp))
    if bad:
        return "registry: ANCHOR MISMATCH (batch %s: the anchored registry head is not in this registry.json)" % ", ".join(bad[:4]), True
    if through is None:
        return "", False
    return "registry: anchored through row %d" % through, False


def _owner_key_lines(wq, keyring, entry, want, trust):
    """0.2.12 (R7-03): the owner keys this check trusted (from registry.json), to compare with the person's own devices. -> ok"""
    try:
        import wa_profile as wa
        base = wa.thumbprint(bytes.fromhex(entry["pub"])).hex()
    except Exception:   # noqa: BLE001
        return True
    if keyring is None or keyring.get("error") or not keyring.get("intervals"):
        active = [base]
    else:
        active = [k.hex() for k, iv in keyring["intervals"].items() if iv and iv[-1][1] is None]
        active = sorted(active, key=lambda k: k != base)
    names = ", ".join(k[:16] for k in active)
    if want is not None:
        good = len(want) >= 8 and any(k.startswith(want) for k in active)
        print("owner key: %s --owner-kid %s among the active keys (%s)" % (want[:16], "is" if good else "is NOT", names))
        return good
    print("owner key%s: %s (active at the end of the pack, taken from it: compare with your devices -- Devices page -- or pass --owner-kid=)"
          % ("s" if len(active) > 1 else "", names))
    trust.append("the owner key(s) %s are yours (from the pack itself)" % names)
    return True


def _toolmaps(root, entries):
    """-> [(line, bad)]. 0.2.4 (draft-deus-aar-05 8.6): a mandate in the ledger that carries `toolmap_sha256` binds a tool map document. toolmaps/<sha256>.cbor
    must hash to its name (else INVALID); a bound hash without its document is reported (the evidence package SHOULD carry the bytes), not invalid."""
    bound = {e["body"]["mandate"]["toolmap_sha256"].hex() for e in entries
             if e["type"] == "MANDATE" and isinstance(e.get("body"), dict) and isinstance(e["body"].get("mandate"), dict)
             and isinstance(e["body"]["mandate"].get("toolmap_sha256"), (bytes, bytearray))}
    files = sorted(glob.glob(os.path.join(root, "toolmaps", "*.cbor")))
    if not bound and not files:
        return []
    out, have, bad = [], set(), False
    for p in files:
        name = os.path.basename(p)[:-5]
        if hashlib.sha256(_rb(p)).hexdigest() != name:
            out.append(("toolmaps: MISMATCH %s (the bytes do not hash to the name)" % os.path.basename(p), True))
            bad = True
        else:
            have.add(name)
    missing = bound - have
    out.append(("toolmaps: %d mandate(s) bind a tool map, %d document(s) present%s" % (len(bound), len(have & bound), (", %d MISSING" % len(missing)) if missing else ""), False))
    return out


def _promises(root, wk, entries, cps, anchored_leaves, signed, unmet=()):
    """-> [(line, bad)]. A promise that is not the witness's or does not fit the audited ledger is NOT EVIDENCE and does not make the pack invalid
    (a forged promise cannot make an honest ledger look bad); a valid promise that is LATE or BROKEN does (the witness broke what it signed)."""
    paths = sorted(glob.glob(os.path.join(root, "promises", "*.promise.cose")))
    if not paths:
        return []
    try:
        from aar_ref import cose
        from aar_ref.verify import check_promise_cose
    except ImportError:             # --use-pack-code with a core older than 0.2.4
        return [("promises: cannot be checked (the core in use predates draft-deus-aar-05)", False)]
    anchored = sorted({c_seq + 1 for c_seq, raw in cps.items() if hashlib.sha256(raw).hexdigest() in anchored_leaves})      # the CHECKPOINT entry follows the entry it covers
    now = int((signed or {}).get("created_t") or 0)
    lid = entries[0]["ledger"] if entries else None
    out, tally, disclosed = [], {}, set()
    for p in paths:
        rid = os.path.basename(p)[:-len(".promise.cose")]
        try:
            o = check_promise_cose(_rb(p), entries, [wk], anchored, now, lid)
        except Exception:  # noqa: BLE001
            o = "PROMISE_MALFORMED"
        if o == "PROMISE_LATE" and unmet:
            try:
                ps = cose.loads(cose.verify1(_rb(p), [wk], cose.TYP_PROMISE)[0])["seq"]
            except Exception:  # noqa: BLE001
                ps = None
            cov = [b for b, cs in unmet if ps is not None and cs >= ps]       # 0.2.6: the failed batch must cover seq >= P.seq (the position of the promised entry)
            if cov:
                o = "PROMISE_UNMET_DISCLOSED"       # 0.2.5: the witness itself records that the stamp of the batch failed: a disclosed failure, not a hidden one
                disclosed.update(cov)
        tally[o] = tally.get(o, 0) + 1
        if o in ("PROMISE_BROKEN", "PROMISE_LATE"):
            out.append(("promise %s: %s" % (rid, o), True))
    out.append(("promises: " + ", ".join("%d %s" % (n, k) for k, n in sorted(tally.items())), False))
    if tally.get("PROMISE_UNMET_DISCLOSED"):
        out.append(("promises: %d promise(s) were not kept in time; the pack discloses anchor batch(es) %s that were not stamped. The ledger itself is unaffected; "
                    "treat the time bound of those entries as unproven" % (tally["PROMISE_UNMET_DISCLOSED"], ", ".join(sorted(disclosed))), False))
    return out


# ---------------------------------------------------------------- 0.2: organisation policy, second pass, declared data, TSA
ENVELOPE_TYPES = ("MANDATE", "CEILING", "APPROVAL", "REVOCATION", "ALLOWANCE")     # 0.2.10: ALLOWANCE (extension) is signed by the owner too


def _rp(entry):
    w = entry.get("webauthn") or {}
    return {"rp_id": w.get("rp_id"), "origins": list(w.get("origins") or [])}


def _inside(root, rel):
    fp = os.path.abspath(os.path.join(root, rel)) if isinstance(rel, str) else None
    return fp if fp is not None and fp.startswith(root + os.sep) and os.path.isfile(fp) else None


def _load_org(root, man):
    """org/chain.json {principal, versions:[{ver, t, registry_seq, hash, policy, envelope}]} -> {chain:[(policy, envelope, t)], versions, error}."""
    out = {"chain": [], "versions": [], "error": None}
    try:
        doc = _read_json(os.path.join(root, "org", "chain.json"))
        vs = doc["versions"]
        if not isinstance(vs, list) or not vs:
            raise ValueError("versions")
        for i, v in enumerate(vs):
            pf, ef = _inside(root, v.get("policy")), _inside(root, v.get("envelope"))
            if v.get("ver") != i + 1 or pf is None or ef is None:
                out["error"] = ("POLICY_CHAIN", i + 1)
                return out
            t = v.get("t")
            out["chain"].append((_rb(pf), _rb(ef), t if isinstance(t, int) and not isinstance(t, bool) else None))
        out["versions"] = vs
    except Exception:   # noqa: BLE001
        out["error"] = ("POLICY_MALFORMED", len(out["chain"]) + 1)
    return out


def _check_org(wq, org, principal, entry, reg_doc, keyring=None):
    """None or (code, ver): the chain itself (00 reference), then what binds it to THIS pack: genesis = the pinned key of the account,
    same principal, increasing witnessed times, hashes of chain.json, the registry_log rows that made each version effective."""
    import cbor2
    ch = org["chain"]
    r = wq.verify_policy_chain(ch, rp=_rp(entry))
    if r:
        return r
    g = cbor2.loads(ch[0][0])
    if g["principal"] != principal:
        return ("POLICY_CHAIN", 1)
    if keyring is None:
        if g["members"][0]["pub"].hex() != str(entry.get("pub", "")).lower():
            return ("KEY_MISMATCH", 1)              # genesis must be signed by the key pinned in registry.json (0.1), not any key
    elif keyring["error"] or ch[0][2] is None or not wq.key_active_at(keyring["intervals"], g["members"][0]["kid"], ch[0][2]):
        return ("KEY_MISMATCH", 1)                  # 0.2.2: by a key of the account that was active when the genesis took effect
    seqs = {}
    for row in reg_doc["log"]:
        seqs[row.get("seq")] = row
    last_t = None
    for i, ((pb, _, t), v) in enumerate(zip(ch, org["versions"])):
        ver = i + 1
        if t is None or (last_t is not None and t <= last_t):
            return ("POLICY_TIME", ver)
        last_t = t
        if v.get("hash") != hashlib.sha256(pb).hexdigest():
            return ("POLICY_CHAIN", ver)
        rs = v.get("registry_seq")
        if rs is not None:
            row = seqs.get(rs)
            if row is None:
                return ("POLICY_REGISTRY", ver)
            try:
                ej = json.loads(row["entry_json"]) if "entry_json" in row else None
                rj = json.loads(row["row_json"]) if "row_json" in row else None
            except ValueError:
                ej = rj = None
            if isinstance(ej, dict) and "policy_hash" in ej and ej["policy_hash"] != v["hash"]:
                return ("POLICY_REGISTRY", ver)
            if rj is not None:          # 0.2.2: the row's own text names this version (and a key swap exactly as the policy does)
                op = rj.get("org_policy") if isinstance(rj, dict) else None
                if not isinstance(op, dict) or op.get("hash") != v["hash"] or op.get("ver") != ver or op.get("principal") != principal:
                    return ("POLICY_REGISTRY", ver)
                sw = wq.key_swap(cbor2.loads(ch[i - 1][0]), cbor2.loads(pb)) if i and hasattr(wq, "key_swap") else None
                want = {"old_kid": sw[0].hex(), "new_kid": sw[1].hex()} if sw else None
                if op.get("key_swap") != want:
                    return ("POLICY_REGISTRY", ver)
    return None


def _second_pass(wq, org, entries, principal, entry):
    """-> (good, total, (code, seq) | None, wb envelopes, wb items). Replays mandates/receipts to rebuild every expected payload,
    takes the approval's action from its RECEIPT, and checks each envelope against the policy in force at the entry's witnessed t.
    A plain wa-sig / COSE_Sign1 of the owner after the genesis counts as a one-signer quorum (it cannot bypass the rules)."""
    import cbor2
    import wa_profile as wa
    from aar_ref.state import approval_payload, ceiling_payload, revocation_payload
    ch, rp = org["chain"], _rp(entry)
    pols = [cbor2.loads(pb) for pb, _, _ in ch]
    pinned = wa.thumbprint(bytes.fromhex(entry["pub"]))
    mandates, receipts, wbs = {}, {}, {}
    good = total = 0
    dstat = org.setdefault("deleg", {"n": 0, "agents": set(), "other": 0, "other_agents": set()})
    for e in entries:
        b = e["body"] if isinstance(e["body"], dict) else {}
        if e["type"] == "RECEIPT":
            receipts[b.get("id")] = b
        if e["type"] not in ENVELOPE_TYPES or "cose" not in b:
            if e["type"] == "MANDATE" and isinstance(b.get("mandate"), dict):
                mandates[b["mandate"].get("id")] = b["mandate"]
            continue
        c, t, seq = b["cose"], e["t"], e["seq"]
        action = pm = agent = None
        try:
            if e["type"] == "MANDATE":
                pm = b["mandate"]
                mandates[pm.get("id")] = pm
                typ, pay = wa.TYP_MANDATE, cbor2.dumps(pm, canonical=True)
            elif e["type"] == "CEILING":
                typ, pay = wa.TYP_CEILING, ceiling_payload(principal, b["id"], b["amount"], b["currency"], b["window_s"])
            elif e["type"] == "REVOCATION":
                typ, pay = wa.TYP_REVOCATION, revocation_payload(mandates[b["mandate"]])
            elif e["type"] == "ALLOWANCE":
                if wq.policy_at(ch, t) is not None:          # 0.2.10: a team's mandate is never widened by one allowance signature
                    return good, total + 1, ("ALLOWANCE_UNDER_POLICY", seq), len(wbs), sum(wbs.values())
                continue                                     # before the genesis: the first pass checked the owner's signature
            else:
                rc = receipts[b["receipt"]]
                action = rc["action"]
                agent = mandates[rc["mandate"]].get("agent")
                typ, pay = wa.TYP_APPROVAL, approval_payload(mandates[rc["mandate"]], action, b["receipt"], b.get("approved", True))
        except (KeyError, TypeError):
            return good, total, ("WQ_MALFORMED", seq), len(wbs), sum(wbs.values())
        ver = wq.policy_at(ch, t)
        kind = wq.envelope_kind(c)
        if ver is None:
            if kind in ("wq", "wb"):
                return good, total + 1, ("WQ_POLICY_STALE", seq), len(wbs), sum(wbs.values())
            continue                                 # before the genesis: solo mode of 0.1, nothing to check here
        total += 1
        pol = pols[ver - 1]
        members = {m["kid"]: m for m in pol["members"]}
        approved = e["type"] == "APPROVAL" and b.get("approved", True) is not False
        dl = hasattr(wq, "delegation_code") and approved and wq.delegation_of(pol, agent) is not None
        if approved:
            if dl:
                dstat["n"] += 1
                dstat["agents"].add(agent)
            else:
                dstat["other"] += 1
                dstat["other_agents"].add(agent)
        try:
            refusal = e["type"] == "APPROVAL" and b.get("approved", True) is False
            if kind == "wq" and refusal:
                # 0.2.0 (ZAMECHANIYA 06 p.5, 01 p.4): stopping is easy -- a refusal needs ONE signer holding a role the approval rule names
                code = wq.verify_wq(c, typ, pay, ch, action=None, rp=rp, at=t)
                reqs = wq.requirements(pol, typ, None, action)
                if code is None and reqs:
                    signers = [members.get(w["kid"]) for w in cbor2.loads(c)["sigs"]]
                    if not any(sm and (r == "any" or r in sm["roles"]) for sm in signers for r, _ in reqs):
                        code = "WQ_QUORUM"
            elif kind == "wq":
                code = wq.verify_wq(c, typ, pay, ch, action=action, rp=rp, at=t, **({"agent": agent} if dl else {}))
            elif kind == "wb":
                m = cbor2.loads(c)
                wbs[hashlib.sha256(c).digest()] = len(m["items"])
                mem = members.get(m["kid"])
                code = "WQ_NOT_MEMBER" if mem is None else (wq.verify_wb(c, typ, pay, mem, rp=rp) or wq.wb_requirements_met(pol, m["kid"], action)
                                                            or (wq.delegation_code(pol, agent, [m["kid"]], t) if dl else None))
            else:                                        # wa-sig or COSE_Sign1 by the pinned key (first pass proved the signature)
                mem = members.get(_wa_kid(c) or pinned)  # 0.2.2: a wa-sig by another key of the account names its own kid
                code = "WQ_NOT_MEMBER" if mem is None else None
                if code is None and dl:
                    code = wq.delegation_code(pol, agent, [_wa_kid(c) or pinned], t)
                if code is None:
                    for role, k in wq.requirements(pol, typ, pm, action):
                        if (1 if refusal else k) > (1 if role == "any" or role in mem["roles"] else 0):
                            code = "WQ_QUORUM"
                            break
        except Exception:   # noqa: BLE001  (hostile envelope that the first pass already rejected)
            code = "WQ_MALFORMED"
        if code:
            return good, total, (code, seq), len(wbs), sum(wbs.values())
        good += 1
    return good, total, None, len(wbs), sum(wbs.values())


def _wa_kid(c):
    try:
        import cbor2
        m = cbor2.loads(c)
        return m.get("kid") if isinstance(m, dict) and isinstance(m.get("kid"), bytes) else None
    except Exception:   # noqa: BLE001
        return None


# ---------------------------------------------------------------- 0.2.2: several passkeys, recovery
def _keyring(wq, reg_doc, principal, entry):
    """Key changes of THIS account from the registry log rows (`row_json` {"key_event": ...}). None when there are none (0.2.1 pack).
    -> {records: {kid: record} of every key ever added, intervals, summary, error: (code, seq) | None}. A key added by a passkey must
    carry a wa-sig (typ dw-key-event) over the exact new key by a key active at that row's time; by "recovery-code" carries none."""
    evs = []
    for r in reg_doc["log"]:
        if "row_json" not in r:
            continue
        try:
            ev = json.loads(r["row_json"]).get("key_event")
        except (ValueError, AttributeError):
            ev = None
        if isinstance(ev, dict):
            evs.append((r.get("seq"), ev))
    if not evs:
        return None
    out = {"records": {}, "intervals": {}, "summary": "", "error": None}
    if wq is None or not hasattr(wq, "key_intervals"):
        out["error"] = ("CHECKER_TOO_OLD", "-")
        return out
    import wa_profile as wa
    base_kid = wa.thumbprint(bytes.fromhex(entry["pub"]))
    out["records"][base_kid] = entry
    done, n_pk, n_rc, n_rm = [], 0, 0, 0
    for seq, ev in evs:
        try:
            kid, op, t, by = bytes.fromhex(ev["kid"]), ev["op"], ev["t"], ev["by"]
            if ev.get("principal") != principal or op not in ("add", "remove") or not isinstance(t, int) or isinstance(t, bool):
                raise ValueError("event")
            if done and t < done[-1][0]:
                raise ValueError("time")
            iv = wq.key_intervals(base_kid, 0, done)
            if op == "add":
                rec = ev["entry"]
                if rec.get("alg") != "ES256" or wa.thumbprint(bytes.fromhex(rec["pub"])) != kid or wq.key_active_at(iv, kid, t):
                    raise ValueError("entry")
                if (rec.get("webauthn") or {}).get("rp_id") != (entry.get("webauthn") or {}).get("rp_id"):
                    raise ValueError("rp")
            elif not wq.key_active_at(iv, kid, t):
                raise ValueError("not active")
            if by == "passkey":
                pay, env = bytes.fromhex(ev["payload_hex"]), bytes.fromhex(ev["envelope_hex"])
                pm = wq.parse_key_event(pay)
                if pm is None or pm["principal"] != principal or pm["op"] != op or pm["kid"] != kid:
                    raise ValueError("payload")
                if op == "add" and pm["pub"].hex() != ev["entry"]["pub"]:
                    raise ValueError("payload")
                signer = _wa_kid(env)
                if signer is None or (op == "add" and signer == kid) or not wq.key_active_at(iv, signer, t):
                    out["error"] = ("KEY_EVENT_SIGNER", seq)
                    return out
                code = wa.verify_envelope(env, wq.TYP_KEY_EVENT, pay, out["records"][signer])
                if code:
                    out["error"] = (code, seq)
                    return out
                n_pk += op == "add"
            elif by == "recovery-code" and op == "add":
                n_rc += 1
            else:
                raise ValueError("by")
            if op == "add":
                out["records"][kid] = ev["entry"]
            else:
                n_rm += 1
            done.append((t, op, kid))
        except (KeyError, TypeError, ValueError, AttributeError):
            out["error"] = ("KEY_EVENT_MALFORMED", seq)
            return out
    out["intervals"] = wq.key_intervals(base_kid, 0, done)
    out["summary"] = "%d keys (%d added: %d by passkey, %d by recovery code (witness-attested); %d removed)" % (
        len(out["records"]), n_pk + n_rc, n_pk, n_rc, n_rm)
    return out


def _keys_pass(wq, keyring, entries, chain=()):
    """-> (signatures checked, (code, seq) | None): each wa-sig / wb of the account in the ledger by a key active at the entry's t.
    Once a team policy is in force (chain), every envelope is the team's: members of the policy at that time (second pass), not this
    account's own passkeys -- a member's batch approval (wb) is judged there."""
    n = 0
    for e in entries:
        b = e["body"] if isinstance(e["body"], dict) else {}
        if e["type"] not in ENVELOPE_TYPES or "cose" not in b:
            continue
        if chain and wq.policy_at(chain, e["t"]) is not None:
            continue
        kind = wq.envelope_kind(b["cose"])
        if kind not in ("wa", "wb"):
            continue
        kid = _wa_kid(b["cose"])
        n += 1
        if kid is None or not wq.key_active_at(keyring["intervals"], kid, e["t"]):
            return n, ("KEY_NOT_ACTIVE", e["seq"])
    return n, None


def _device_lines(reg_doc, principal):
    """0.2.15: the phones declared with a recovery code, read from the key_device rows of THIS account: when each one counts as a phone
    (not_before: at least 24 h after the declaration), and whether it was cancelled or its wait ended early by a team quorum.
    -> [(line, bad)]. A row of 0.2.14 has no not_before: the claim took effect at once (said so, not a failure)."""
    out, seen = [], {}
    for r in reg_doc.get("log") or ():
        try:
            kd = json.loads(r["row_json"]).get("key_device") if "row_json" in r else None
        except (ValueError, AttributeError, TypeError):
            kd = None
        if not isinstance(kd, dict) or kd.get("principal") != principal:
            continue
        kid = str(kd.get("kid", ""))[:8]
        if kd.get("by") == "recovery-code" and kd.get("device") == "phone":
            nb, t = kd.get("not_before"), kd.get("t")
            if nb is None:
                out.append(("keys: %s declared the new phone with a recovery code at %s and counted as phone at once (before 0.2.15)" % (kid, t), False))
            elif not isinstance(nb, int) or not isinstance(t, int) or nb - t < 24 * 3600 or nb - t > 72 * 3600:
                out.append(("keys: FAIL RECOVERY_DELAY %s (declared at %s, phone from %s: the wait must be 24-72 h)" % (kid, t, nb), True))
            else:
                seen[kid] = len(out)
                out.append(("keys: %s declared the new phone with a recovery code at %d; counts as phone from %d (%d h later)" % (kid, t, nb, (nb - t) // 3600), False))
        elif kd.get("cancelled") and kid in seen:
            out[seen[kid]] = (out[seen[kid]][0] + "; CANCELLED at %s by key %s (never counted as phone%s)" % (
                kd.get("t"), str(kd.get("by"))[:8], "; stopped by the witness: it signs nothing after that" if kd.get("stopped") else ""), False)
        elif kd.get("stopped"):         # 0.2.17 (R9-03): a key a cancelled (or removed) waiting phone had vouched for
            out.append(("keys: %s stopped by the witness at %s: it was vouched for by %s, a new phone declared with a recovery code that was "
                        "cancelled or removed (the witness's record; it signs nothing after that)" % (kid, kd.get("t"), str(kd.get("vouched_by"))[:8]), False))
        elif kd.get("lifted") and kid in seen:
            out[seen[kid]] = (out[seen[kid]][0] + "; wait ended at %s by a team quorum (%s, request %s; the witness's record)" % (
                kd.get("t"), kd.get("org"), kd.get("req_id")), False)
    return out


def _recoveries(wq, org, rp):
    """Lines for the versions that only replace one member's key (0.2.2), with the rule that signed them."""
    import cbor2
    out = []
    if not hasattr(wq, "key_swap"):
        return out
    ch = org["chain"]
    for i in range(1, len(ch)):
        prev, cur = cbor2.loads(ch[i - 1][0]), cbor2.loads(ch[i][0])
        sw = wq.key_swap(prev, cur)
        if sw is None:
            continue
        signers = [w["kid"] for w in cbor2.loads(ch[i][1])["sigs"]]
        rc = prev["rules"].get("recovery")
        by_policy = wq.verify_wq(ch[i][1], wq.TYP_POLICY, ch[i][0], ch[:i], rp=rp) is None
        how = "rule policy %s k=%d" % (prev["rules"]["policy"]["role"], prev["rules"]["policy"]["k"]) if by_policy or rc is None \
            else "rule recovery %s k=%d" % (rc["role"], rc["k"])
        out.append("org recovery: v%d replaced key %s -> %s (%s, %d signers, the replaced key not among them: %s)" % (
            i + 1, sw[0][:4].hex(), sw[1][:4].hex(), how, len(signers), "yes" if sw[0] not in signers else "no"))
    return out


def _declared(root, wq, org, principal, entry):
    """coverage/<agent>.json (operator statement, never fails the pack) and advisory/<rid>.json (release signatures, checked)."""
    out = []
    for p in sorted(glob.glob(os.path.join(root, "coverage", "*.json"))):
        try:
            c = _read_json(p)
            out.append(("coverage %s: %s (operator-declared, not verified)" % (os.path.basename(p)[:-5], c.get("level", "?")), False))
        except Exception:   # noqa: BLE001
            out.append(("coverage %s: unreadable (operator-declared, not verified)" % os.path.basename(p)[:-5], False))
    adv = sorted(glob.glob(os.path.join(root, "advisory", "*.json")))
    if not adv:
        return out
    import cbor2
    import wa_profile as wa
    keys = {wa.thumbprint(bytes.fromhex(entry["pub"])): entry}
    for pb, _, _ in (org or {}).get("chain", []):
        for m in cbor2.loads(pb)["members"]:
            keys.setdefault(m["kid"], wq._reg_of(m, _rp(entry)))
    n = 0
    for p in adv:
        rid = os.path.basename(p)[:-5]
        try:
            a = _read_json(p)
            env = bytes.fromhex(a["envelope_hex"])
            pay = wq.release_payload(a["rid"], a["args_sha256"], a["release"])
            reg = keys.get(cbor2.loads(env)["kid"])
            code = "KEY_MISMATCH" if reg is None or a["rid"] != rid else wa.verify_envelope(env, wq.TYP_RELEASE, pay, reg)
        except Exception:   # noqa: BLE001
            code = "MALFORMED"
        if code:
            out.append(("advisory %s: %s" % (rid, code), True))
        else:
            n += 1
    out.append(("advisory: %d/%d releases signed (the L3 advice itself is not evidence)" % (n, len(adv)), n != len(adv)))
    return out


def _tsa_lines(root, tsa_ca):
    out, groups = [], {}
    for p in sorted(glob.glob(os.path.join(root, "anchors", "*.tsr.*"))):
        b, _, name = os.path.basename(p).partition(".tsr.")
        groups.setdefault(b, []).append((name, p))
    if not groups:
        return out
    cadir = os.path.abspath(tsa_ca) if tsa_ca else os.path.join(root, "anchors", "tsa-ca")
    try:
        import tsa
    except ImportError:
        return [("tsa %s: not checked (tsa.py / asn1crypto not installed)" % b, False) for b in sorted(groups)]
    seen = set()
    for b in sorted(groups):
        try:
            digest = bytes.fromhex(_read_json(os.path.join(root, "anchors", b + ".json"))["root"])
        except Exception:   # noqa: BLE001
            out.append(("tsa %s: MISMATCH (no readable anchors/%s.json with the batch root)" % (b, b), True))
            continue
        names, errs = [], []
        for name, p in sorted(groups[b]):
            ca = os.path.join(cadir, name + ".pem")
            if not os.path.isfile(ca):
                errs.append("%s: no root certificate" % name)
                continue
            if not tsa_ca and name not in seen:
                seen.add(name)
                out.append(("tsa-ca %s: sha256 %s (root taken from the pack: compare with the TSA's published root, or pass --tsa-ca=<dir>)"
                            % (name, hashlib.sha256(_rb(ca)).hexdigest()[:16]), False))
            r = tsa.verify(_rb(p), digest, ca)
            if r["ok"]:
                names.append(name)
            else:
                errs.append("%s: %s" % (name, r["reason"]))
        if errs:
            out.append(("tsa %s: MISMATCH (%s)" % (b, "; ".join(errs)), True))
        else:
            out.append(("tsa %s: OK (%s)" % (b, ", ".join(names)), False))
    return out


_last = ""


def _ots(path, root_hex, off):
    global _last
    if not os.path.exists(path):
        _last = "pending (inclusion in batch root proven; not stamped)"
        return _last
    try:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except ImportError:
        _last = "pending (opentimestamps not installed: proof file present, not checked)"
        return _last
    with open(path, "rb") as f:
        d = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    if d.file_digest != bytes.fromhex(root_hex):
        _last = "MISMATCH (.ots commits to another digest)"
        return _last
    atts = []

    def walk(ts):
        for att in ts.attestations:
            atts.append((ts.msg, att))
        for _, sub in ts.ops.items():
            walk(sub)
    walk(d.timestamp)
    btc = [(m, a.height) for m, a in atts if isinstance(a, BitcoinBlockHeaderAttestation)]
    if not btc:
        _last = "pending"
        return _last
    msg, h = btc[0]
    if off:
        _last = "bitcoin block %d (offline: block header not cross-checked)" % h
        return _last
    res = {}
    for name, base in (("mempool.space", "https://mempool.space/api"), ("blockstream.info", "https://blockstream.info/api")):
        try:
            bh = urllib.request.urlopen("%s/block-height/%d" % (base, h), timeout=30).read().decode().strip()
            blk = json.load(urllib.request.urlopen("%s/block/%s" % (base, bh), timeout=30))
            res[name] = "OK" if bytes.fromhex(blk["merkle_root"])[::-1] == msg else "MISMATCH"
        except Exception:
            res[name] = "UNREACHABLE"
    _last = "bitcoin block %d (%s)" % (h, " ".join("%s=%s" % kv for kv in res.items()))
    if "MISMATCH" in res.values():
        _last = "MISMATCH " + _last
    return _last



# ---------------------------------------------------------------- 0.2.27: node 2
NODE2_GENESIS = None    # SHA-256 (hex) of the first co-signature of the production node 2: pinned here once published (OTS-stamped). None = not yet
NODE2_EXPECT = None     # {"policy_sha256": hex, "measurement": hex} of the published node 2 build. None = no real policy yet (probe: allow-all)


def _node2_lines(root, cps, argv, trust):
    """-> [(line, bad)]. COVERED: the newest anchored checkpoint of this journal is among the checkpoints node 2 inspected, its cosig is in
    an unbroken chain from the genesis (and agrees with the pin of an earlier check), every K2 of the chain is bound to an AMD-signed SEV-SNP
    report of a non-debug guest whose policy has no known allow-all form. ALARM (bad): a valid alarm about this journal, a chain that differs
    from the pin, or fewer alarms in the pack than node 2 counted. Everything else: NOT COVERED (bad only with --require-node2)."""
    d = os.path.join(root, "node2")
    if not os.path.isdir(d):
        return []
    need = "--require-node2" in argv
    try:
        from node2 import amd as N2AMD, attest as N2A, cosign as N2C
    except ImportError:
        trust.append("node 2: not checked (the node2 modules are not next to the checker)")
        return [("node2: cannot be checked (node2/cosign.py, attest.py, amd.py not next to the checker)", need)]
    import cbor2

    def opt(name):
        return next((a.split("=", 1)[1] for a in argv if a.startswith(name + "=")), None)

    def nc(why):
        return [("node2: NOT COVERED (%s)" % why, need)]
    try:
        cdoc = _read_json(os.path.join(d, "chain.json"))
        chain = [(bytes.fromhex(x["cose_hex"]), bytes.fromhex(x["pub_hex"])) for x in sorted(cdoc["chain"], key=lambda x: x["n"])]
        keys = {bytes.fromhex(k["pub_hex"]): k.get("attestation") for k in _read_json(os.path.join(d, "keys.json"))}
        alarms = [(bytes.fromhex(a["cose_hex"]), bytes.fromhex(a["pub_hex"])) for a in _read_json(os.path.join(d, "alarms.json"))]
    except Exception as e:  # noqa: BLE001
        return nc("node2/ files malformed: %s" % type(e).__name__)
    if not chain:
        return nc("no co-signature in the pack")
    from aar_ref import cose
    witness = _read_json(os.path.join(root, "manifest.json"))["witness"]
    k1 = bytes.fromhex(witness["pub_hex"])
    mine = {}                                  # leaf hex -> (seq, raw) of this journal's checkpoints
    lids = set()
    for s_, raw in cps.items():
        mine[hashlib.sha256(raw).hexdigest()] = (s_, raw)
        try:
            lids.add(bytes(cbor2.loads(cose.verify1(raw, [cose.Key.public(cose.ALG_EDDSA, k1)], cose.TYP_CHECKPOINT)[0])["ledger"]))
        except Exception:  # noqa: BLE001
            pass
    out = []
    # alarms (each one is offline evidence: two checkpoints signed by node 1 that are not an append-only pair)
    good_alarms, my_alarms = set(), []
    for al, pub in alarms:
        try:
            why = N2C.verify_alarm(al, pub, k1)
            m = N2C.cose_verify(al, pub, N2C.TYP_ALARM)
        except N2C.Reject:
            out.append(("node2: an alarm in the pack is not valid evidence (ignored)", False))
            continue
        if pub not in [p for _, p in chain]:
            out.append(("node2: an alarm signed by a key outside the co-signature chain (ignored)", False))
            continue
        good_alarms.add(hashlib.sha256(al).digest())
        if bytes(m["ledger"]) in lids:
            my_alarms.append((why, m["bid"]))
    # pin of an earlier check, genesis
    pin_path = opt("--node2-pin") or os.path.join(os.path.dirname(root), "node2-pin.json")
    pin = None
    if os.path.isfile(pin_path):
        try:
            pin = _read_json(pin_path)
            pin = {"genesis": bytes.fromhex(pin["genesis_hex"]), "n": int(pin["n"]), "hash": bytes.fromhex(pin["hash_hex"]), "alarms": int(pin.get("alarms", 0))}
        except Exception:  # noqa: BLE001
            return [("node2: ALARM (the pin file %s is unreadable: refusing to check without it; move it away only if you know why)" % pin_path, True)]
    g = opt("--node2-genesis") or NODE2_GENESIS
    if g:
        genesis, gsrc = bytes.fromhex(g), "pinned"
    elif pin:
        genesis, gsrc = pin["genesis"], "from your pin"
    else:
        genesis, gsrc = hashlib.sha256(chain[0][0]).digest(), "taken from this pack"
        trust.append("node 2: the genesis of the co-signature chain was taken from the pack (first check; keep %s or pass --node2-genesis)" % os.path.basename(pin_path))
    try:
        head = N2C.verify_chain(chain, genesis, (pin["n"], pin["hash"]) if pin else None)
    except N2C.Reject as e:
        if str(e) == "CHAIN_PIN":
            return out + [("node2: ALARM (the co-signature chain differs from the one you saw before: pin n=%d; node 2 restarted from an old state, "
                           "or another chain is shown)" % pin["n"], True)]
        if str(e) == "CHAIN_GENESIS" and gsrc != "taken from this pack":
            return out + [("node2: ALARM (the co-signature chain does not start at the genesis %s: node 2 was replaced, or restarted without "
                           "its state)" % gsrc, True)]
        return out + nc("co-signature chain: %s (genesis %s)" % (e, gsrc))
    # alarms node 2 counted must all be in the pack
    if head.get("alarms", 0) > len(good_alarms) or (head.get("alarms", 0) and bytes(head["alarm_head"]) not in good_alarms):
        return out + [("node2: ALARM (node 2 counted %d alarm(s), this pack shows %d valid one(s): node 1 hides alarms)" % (head.get("alarms", 0), len(good_alarms)), True)]
    if my_alarms:
        return out + [("node2: ALARM %s on YOUR journal (batch %s): node 2 refused to co-sign; both checkpoints are in node2/alarms.json, signed by "
                       "node 1 -- %s" % (my_alarms[0][0], my_alarms[0][1], "definitive proof of a rewritten history" if my_alarms[0][0] in ("FORK", "ROLLBACK")
                                         else "node 1 could not prove that the new journal extends the old one"), True)]
    if good_alarms:
        out.append(("node2: %d alarm(s) on other journals (not yours): see node2/alarms.json" % len(good_alarms), False))
    # attestation of every K2 in the chain
    expect = None
    ef = opt("--node2-expect")
    if ef:
        e_ = _read_json(ef)
        expect = {"policy_sha256": bytes.fromhex(e_["policy_sha256"]), "measurement": bytes.fromhex(e_["measurement"])}
    elif NODE2_EXPECT:
        expect = {"policy_sha256": bytes.fromhex(NODE2_EXPECT["policy_sha256"]), "measurement": bytes.fromhex(NODE2_EXPECT["measurement"])}
    pins = dict(N2AMD.ARK_PINS)
    if opt("--node2-amd-ark"):
        pins["--node2-amd-ark"] = opt("--node2-amd-ark").lower()
    att_bad = []
    for pub in dict.fromkeys(p for _, p in chain):
        try:
            doc = N2A.doc_from_json(keys.get(pub))
            if doc["pub"] != pub or doc["node1_pub"] != k1:
                raise N2A.AttestError("KEY_MISMATCH")
            r = N2A.check_full(doc, expect, pins)
        except (N2A.AttestError, TypeError, AttributeError) as e:
            att_bad.append("%s...: %s" % (pub.hex()[:12], e))
            continue
        if not r["ok"]:
            att_bad.append("%s...: %s" % (pub.hex()[:12], "; ".join(r["problems"])))
        for t_ in r["trust"]:
            if ("node 2: " + t_) not in trust:
                trust.append("node 2: " + t_)
    # coverage of the newest anchored checkpoint of this journal
    by_hash = {hashlib.sha256(cs).digest(): (cs, pub) for cs, pub in chain}
    anchored = []
    for jp in glob.glob(os.path.join(root, "anchors", "*.json")):
        try:
            a = _read_json(jp)
            if a["leaf"] in mine:
                anchored.append((mine[a["leaf"]][0], a["batch"], mine[a["leaf"]][1]))
        except Exception:  # noqa: BLE001
            continue
    if not anchored:
        return out + nc("no anchored checkpoint of your journal in the pack")
    covered_seq, newest = None, max(anchored)
    for s_, bid, raw in sorted(anchored, reverse=True):
        p = os.path.join(d, os.path.basename(bid) + ".cosig.cose")
        lp = os.path.join(d, os.path.basename(bid) + ".leaves.json")
        if not (os.path.isfile(p) and os.path.isfile(lp)):
            continue
        cs = _rb(p)
        hit = by_hash.get(hashlib.sha256(cs).digest())
        try:
            if hit and N2C.covered(cs, hit[1], [bytes.fromhex(x) for x in _read_json(lp)], raw):
                covered_seq = (s_, bid, N2C.verify_cosig(cs, hit[1])["n"], hit[1])
                break
        except (N2C.Reject, ValueError, TypeError):
            continue
    if att_bad:
        return out + nc("attestation of K2 %s" % " | ".join(att_bad))
    if covered_seq is None or covered_seq[0] < newest[0]:
        return out + nc("your newest anchored checkpoint (seq %d, batch %s) is not among the checkpoints node 2 co-signed%s" % (
            newest[0], newest[1], "; covered through seq %d" % covered_seq[0] if covered_seq else ""))
    pin_new = {"genesis_hex": genesis.hex(), "n": head["n"], "hash_hex": hashlib.sha256(chain[-1][0]).hexdigest(), "alarms": head.get("alarms", 0)}
    if "--no-node2-pin-write" not in argv:
        try:
            with open(pin_path, "w") as f:
                json.dump(pin_new, f, indent=1)
        except OSError:
            trust.append("node 2: the pin could not be written to %s (keep n=%d hash %s yourself)" % (pin_path, head["n"], pin_new["hash_hex"][:16]))
    s_, bid, n, pub = covered_seq
    line = "node2: COVERED through seq %d (batch %s, co-signature n=%d of %d, K2 %s..., genesis %s)" % (s_, bid, n, head["n"], pub.hex()[:12], gsrc)
    if cps and max(cps) > s_:
        trust.append("node 2: the entries after seq %d are not co-signed by node 2 yet (next batch)" % s_)
    return out + [(line, False)]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
