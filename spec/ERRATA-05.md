# Errata to draft-deus-aar-05 (19.10.2026)

The text of `draft-deus-aar-05.md` is NOT changed. This file closes the seven ambiguities AMBIGUITY-05-1...7 that the clean-room pass of
implementation C reported (`verifier_swift/OTCHET-INTEROP-C-05-2026-10-19.md`) and is folded into the next revision. Where a rule below is
applied, "MUST" is normative for implementations of -05. The reading chosen is the one implementations A (Python) and C (Swift) already share;
no vector of -05 changes its bytes or its expectation. Example vectors: `spec/vectors/errata05/` (decision and requirements, checked by
`python -m aar_ref.make_errata05`) and byte vectors `spec/vectors/cose/C83-C97` (generator `aar_ref/make_cose_vectors_v46.py`).

## E5-1 (AMBIGUITY-05-1). `publish` and the counters

Problem. Section 6.4 step 12 says "every action class except `publish` and `pass` (which never reach it)", and step 12a applies to "`A.class`".
A reader may take the parenthesis to mean that `publish` also skips 12a and 13, which makes the tier `publish` of `count-class` dead.

Rule. `publish` and `pass` skip step 12 ONLY. Both reach step 12a and step 13 like every other class. Order for `publish`: step 10 returns R (a
protected class in `A.data` is `deny DATA_FORBIDDEN`, a channel outside the list is `deny RESOURCE`, no `channels` is `defer ESCALATE_PUBLISH`);
a `deny` of R is final (step 11). Otherwise D is empty and K (step 12a) is computed with n = count(M, `publish`, t); step 13 combines
R and K. Consequences: `{publish: {max: 1}}` makes the second publish of the window `deny COUNT_LIMIT`; `{publish: {ask_over: 1}}` makes it
`defer ESCALATE_COUNT` when R is `allow`; when R is itself a `defer` (`ESCALATE_PUBLISH`) it keeps its reason (step 13, last sentence of -05).
The same holds for `pass`. The parenthesis of step 12 is to be read "which never reach step 12".

Vectors. `errata05/E5-1a..f` (decision). Byte level: `cose/C88` (counters on `pass` and `publish`, honest ledger) and `C89` (a RECEIPT that records the
second `publish` as `allow` under `{publish: {max: 1}}`: `VERDICT_NOT_REPRODUCIBLE`).

## E5-2 (AMBIGUITY-05-2). Abstract mode: symbolic hashes and an optional `ledger`

Problem. The CDDL of Sections 6.1 and 9.5 types `toolmap_sha256` as `bstr .size 32` and the `ledger` of a promise as `bstr`, while the abstract
vectors S39-S41, V52, V53, D106-D117 use the string `"tm-A"` and V55-V62 carry no `ledger` and have the harness member `signed_by`.

Rule (new convention 14 of Appendix A, beside convention 9). In an ABSTRACT vector (not in a byte-level vector):
(a) every field the CDDL types `bstr` or `bstr .size N` is a character string (symbolic hash), and a reader MUST accept a string and MUST NOT
report `MALFORMED`, `MANDATE_MALFORMED` or `PROMISE_MALFORMED` for the type or the size; this covers `toolmap_sha256` of a mandate and of an
action, and `entry` and `ledger` of a promise;
(b) the `ledger` of a promise MAY be absent; when present it is compared with the symbolic ledger identifier and a mismatch is `PROMISE_MALFORMED`
as in Section 9.5 step 1;
(c) `signed_by` is a member of the promise map in the abstract form only; it names the symbolic signer and replaces the signature check of
step 1 (not equal to the pinned witness key: `PROMISE_SIG`); a verifier of byte-level vectors MUST reject it as an extra member
(`PROMISE_MALFORMED`);
(d) a `null` or absent `toolmap_sha256` is equal to another `null` or absent one and to nothing else; string comparison is exact.
In a byte-level vector and in a real deployment none of this applies: the sizes of the CDDL are enforced (`C90`: 31 bytes, `MANDATE_MALFORMED`).

New convention 15 of Appendix A (byte-level promises). A `cose-ledger` vector may carry `promises_hex` (list of COSE_Sign1 promises, typ
`application/aar-inclusion-promise+cbor`), `anchored` (list of the INDEXES in the presented ledger of the CHECKPOINT entries whose anchor
verified) and `now`. The expected result then has `promises` (list of outcomes, in order) when the ledger is valid, and `promise` (index of the
first failing promise) when it is invalid by Section 10 step 11 - as in convention 13, the list is NOT given for an invalid result. A verifier MUST compare the `ledger` of a byte-level promise with the
identifier of the AUDITED ledger (not with the one the promise names): `C97` (a promise for another ledger: `PROMISE_MALFORMED`, ledger valid).
Implementation A did not (it took the identifier from the promise) and is corrected in this pass.

Vectors. Existing: V52, V53, V55-V62, S39-S41, D106-D117; new: `cose/C90`, `C97`.

## E5-3 (AMBIGUITY-05-3). `money_over` for a class without numeric limits

Problem. PROFILE-webauthn-01 Section 6 reads "`money_over X`: the largest of `budget`, `max_per_action`, `min_price` over the granted money classes is
greater than X; a class granted as plain `true` is unbounded". It does not say what a class granted as `{}` or `{budget: null}` contributes, nor why
`min_price` (a floor) counts as a size.

Rule. Let level(c) of a granted money class c (value neither `false`, `null` nor absent) be: unbounded (greater than every X) for the plain boolean `true`
(`refund: true` is such a class; `ask_over.amount` does not enter the function, Section 6.9); otherwise the largest of the members `budget`,
`max_per_action`, `min_price` that are present and not null, and 0 when none is. The mandate level is the largest level over the granted money classes.
`money_over X` fires when the mandate level is greater than X. Hence `purchase: {}` and `purchase: {budget: null, max_per_action: null}` fire `money` and not
`money_over`: such a purchase is always deferred by the witness (Section 6.4 step 10, "any of permission, `max_per_action`, `budget` unspecified ->
`defer ESCALATE_MONEY`") so each action carries its own approval, and the approval requirement of Section 6 (action amount) applies to it. `min_price` counts
as a size by convention: it is a number the principal signed for a money class, and treating it as a bound is the conservative reading for a sale
(raising the floor to 60000 needs the larger quorum). Reading "no limits = unbounded" for `{}` was rejected: it would demand the larger quorum for a
grant that the witness itself never lets through without a human.

Vectors. `errata05/E5-3a..h` (requirements function).

## E5-4 (AMBIGUITY-05-4). `t` of a checkpoint in Section 9.5 step 5

Rule. In Section 9.5 steps 2 and 5, "checkpoint of C has `t` <= D" means the `t` of the CHECKPOINT ENTRY (Section 7.1: the witness time of the entry),
not a member of the checkpoint body (which has `seq`, `head`, `root` and no `t`) and not the `t` of a separately signed checkpoint object
(Section 9.1) unless it is the same moment. `C92` (kept: entry `t` 1500 <= D 1600), `C93` (late: 1700 > 1600).

## E5-5 (AMBIGUITY-05-5). `ver` in the policy chain

Rule (PROFILE-webauthn-01 Section 3). `ver` of the policy at position k (counting from 1) MUST be k: "no gaps" is checked against the position, and a
policy whose `ver` differs from its position is `POLICY_CHAIN`. The `ver` returned in `(code, ver)` is the position (1-based). Vector `policy/p05-version-skipped`.

## E5-6 (AMBIGUITY-05-6). `wb` in a ledger: which policy

Rule (PROFILE-webauthn-01 Section 7). A `wb` has no policy name. In a ledger entry the key set that must contain the signer is the membership of the
policy version in force at the `t` of the entry (`policy_at(chain, t)`), including the case that the member was removed later (`WQ_NOT_MEMBER` only if
it was not a member then). Without a policy chain (single-owner mode) the pinned key of the principal. A chain without times fails the second
pass, as for `wq`.

## E5-7 (AMBIGUITY-05-7). Which `typ` error of a `wb` is which code

Rule (PROFILE-webauthn-01 Section 5). Two different faults: (a) the `typ` member of the envelope is not a text string or is not one of the typs the
profile registers for `wb` (`application/aar-approval+cbor`, `application/aar-revocation+cbor`): `WB_MALFORMED`; (b) the envelope is well formed but its
`typ` differs from the `typ` EXPECTED by the context (for an APPROVAL entry, anything other than `application/aar-approval+cbor`): `APPROVAL_SIG`
(or `REVOCATION_SIG` in a revocation context). Vector `wb/b11-wrong-typ-expected` is (b).

## Not changed

Implementation notes (not normative): the cloud service 0.2.4 stores `toolmap_sha256`, the hashes of the protected-data literals and of the advisor
settings INSIDE the signed mandate (Section 8.6 "the signing page MUST compute it"), writes `pass` decisions to the ledger with a receipt (Section 8.6) and
issues the inclusion promise of Section 9.5 with every AAR. Those members are extra members of the mandate only where the CDDL names them
(`toolmap_sha256`); the other hashes ride in the extension member described in `cloud/CHANGELOG.md` 0.2.4 and are not part of this profile.


## Addendum 19.10.2026: PROFILE-webauthn-02

The profile text referred to by E5-3, E5-5, E5-6 and E5-7 above is now `cloud/contract/v02/PROFILE-webauthn-02.md` (replaces -01; -01 is not changed). It adds
what the interop pass of verify-pack found (`verifier_swift/OTCHET-INTEROP-PACK-2026-10-19.md`, PACK-1...10): the rule for a refusal (`approved=false`) under a
`money_over` tier (one signer holding a role the approval rule names), a plain `wa-sig` after the genesis = a quorum of one pinned key, the code `POLICY_TIME`
(strict increase), the two passes, `P.seq` as a position in the presented ledger, `account`/`principal` of the manifest, and trust in the witness key of a pack.
The pack side (`now` of a promise, what "anchored" means, what a disclosure must cover) is in `cloud/docs/verify.md` 0.2.6. Section numbers cited in E5-5...E5-7 are
the same in -02. Test packs for these rules: `cloud/server/tests_pack/test_interop_pack.py`.
