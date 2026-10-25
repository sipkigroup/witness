# Team Profile for WebAuthn-Signed Mandates: Quorum, Batch and Organisation Policy

Document: PROFILE-webauthn-02 (appendix to draft-deus-aar-05; replaces PROFILE-webauthn-01, which is not changed; does not touch PROFILE-webauthn-00)
Status: draft, 2026-10-19. Reference implementation is not public.

## 1. Introduction

PROFILE-webauthn-00 lets one passkey sign a mandate, approval, revocation or ceiling object of draft-deus-aar-04 as an envelope `wa-sig`.
This profile adds what a team needs and leaves draft-deus-aar-04 and the witness ledger format untouched: a signed **organisation policy**, a **quorum envelope** `wq` (several members sign one object), a **batch envelope** `wb` (one member approves many deferred actions with one gesture), and the **requirements function** that maps an object to the signatures it needs. A verifier sees the same interface as before: `check(principal, signed_by, envelope, expect_payload, typ)` returns nothing or a reason code.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. All CBOR is Core Deterministic Encoding (draft-deus-aar-04 5.1); a verifier MUST re-encode a parsed map and reject it if the bytes differ.

## 2. Envelopes and discrimination

Three envelopes are CBOR maps and are told apart by the member `v`, never by the first byte:

| `v` | envelope |
|---|---|
| `deus-aar-wa-0.1` | `wa-sig` (PROFILE-webauthn-00 3.2) |
| `deus-aar-wq-0.1` | `wq` (Section 4) |
| `deus-aar-wb-0.1` | `wb` (Section 5) |

COSE_Sign1 (tag 18) is none of them. `envelope_kind(bytes)` returns `wa`, `wq`, `wb` or nothing.

## 3. Organisation policy

An organisation is an account: its principal `dw:<account_id>` and its single ledger do not change. The policy is a CDE map with `typ = application/dw-org-policy+cbor`:

```
org-policy = { "v": "dw-org-policy-0.1", "principal": tstr, "ver": uint (1, 2, ... no gaps),
               "prev": bstr .size 32 / null, ; SHA-256 of the previous policy CDE; null only for ver = 1
               "members": [+ member],         ; 1..16, strictly ascending by kid
               "rules": rules }
member = { "kid": bstr .size 32, "pub": bstr .size 65, "cred": bstr,
           "roles": [+ ("owner" / "budget" / "access")], "label": tstr }  ; label <= 32 characters, no "@"
rules  = { "policy": req, "mandate": [* tier], "approval": [* tier], "revocation": req, "ceiling": req }
tier   = { "if": "money" / "money_over" / "access", ? "amount": uint, "role": "budget" / "access" / "owner", "k": uint }
req    = { "role": "owner" / "budget" / "access" / "any", "k": uint }
```

Well-formedness (`validate_policy`) additionally requires: `kid` equals the RFC 9679 thumbprint of `pub`; roles are unique within a member; `amount` is present exactly for `money_over`; `1 <= k <= 16`; and every requirement can be met by the member list (k is not larger than the number of holders of the role). The last rule prevents an organisation from locking itself. The observer role exists in the service but never appears in a policy.

**Chain.** Version 1 (genesis) has exactly one member holding all three roles, every k equal to 1, and is signed by an ordinary `wa-sig` of that member's pinned key over `typ = application/dw-org-policy+cbor`. The `ver` of the policy at position k (counting from 1) MUST be k (ERRATA-05 E5-5), and the `t` of the versions MUST strictly increase: `t[k] > t[k-1]`, an equal or smaller time is `POLICY_TIME` (A.3). Version n >= 2 is signed by a `wq` collected under the rule `policy` of version n-1; the `wq` MUST name version n-1 in its `policy` member. `verify_policy_chain` returns nothing or `(code, ver)`: `POLICY_MALFORMED`, `POLICY_CHAIN` (`ver` differs from the position, wrong `prev`, changed principal, quorum names another version), `POLICY_TIME` (times do not strictly increase), or the code of the failing signature (`WQ_*`, `WA_*`, `KEY_MISMATCH`). An account without a policy, and an entry written before the `t` of version 1, works as in PROFILE-webauthn-00 (single-owner mode). From the `t` of version 1 on, a plain `wa-sig` is a quorum of one (Section 7, A.2).

## 4. Quorum envelope `wq`

```
wq   = { "v": "deus-aar-wq-0.1", "typ": tstr, "payload": bstr, "policy": bstr .size 32, "sigs": [+ wsig] }  ; sigs: 1..16, strictly ascending by kid
wsig = { "kid": bstr .size 32, "authData": bstr, "clientDataJSON": bstr, "sig": bstr .size 64 }
```

`policy` is the SHA-256 of the policy CDE under which the quorum was collected (for a policy change: the previous version). The challenge of every `wsig` is exactly the challenge of PROFILE-webauthn-00 3.3 (`deus-aar-wa-0.1`, `typ`, `payload`), so each member's browser signs an ordinary `wa-sig` and the service only assembles the pieces: no new client code. A `wsig` plus the shared `typ` and `payload` is a `wa-sig`, and the reference verifies it with the unchanged `wa-sig` procedure.

`verify_wq(env, expect_typ, expect_payload, chain, action, rp, at)` applies, in this order:
1. Structure and CDE (`WQ_MALFORMED`); `sigs` not ascending by kid (`WQ_MALFORMED`); a repeated kid in an ascending list (`WQ_DUP_SIGNER`).
2. `typ` and `payload` equal the expected ones (`MANDATE_SIG`, `APPROVAL_SIG`, `REVOCATION_SIG`, `CEILING_SIG`, `POLICY_SIG`).
3. `policy` names a version present in the chain (`WQ_POLICY_UNKNOWN`).
4. Only when the verifier supplies `at` (the witnessed time of the ledger entry; Section 7): that version was in force at `at` (`WQ_POLICY_STALE`).
5. Every signer is a member of that version (`WQ_NOT_MEMBER`).
6. Each signature, in kid order, passes steps 3 to 6 of PROFILE-webauthn-00 3.5 against the member's pinned key (first failure: its `WA_*` or `KEY_MISMATCH`). The relying-party id and origins are not part of the policy; the verifier takes them from the pinning record (`rp`).
7. Requirements (Section 6) are met (`WQ_QUORUM`).

The chain argument is not re-verified inside `verify_wq`; callers verify it once with `verify_policy_chain`.

## 5. Batch envelope `wb`

```
wb = { "v": "deus-aar-wb-0.1", "typ": "application/aar-approval+cbor", "items": [+ bstr .size 32],  ; 1..20
       "kid": bstr .size 32, "authData": bstr, "clientDataJSON": bstr, "sig": bstr .size 64 }
challenge = SHA-256( "deus-aar-wb-0.1" || 0x00 || typ || 0x00 || CDE(items) )
```

Each item is the SHA-256 of one approval payload. One `wb` is placed in every APPROVAL entry of the batch. `verify_wb` runs steps 3 to 6 of PROFILE-webauthn-00 3.5 over the batch challenge and requires `SHA-256(expect_payload)` to be among `items`. Codes: `WB_MALFORMED` (shape, more than 20 items, an item not 32 bytes, not CDE, or a `typ` that is not a text string or not one of `application/aar-approval+cbor`, `application/aar-revocation+cbor`), `APPROVAL_SIG` (a registered `typ` that differs from the one the context expects; `REVOCATION_SIG` in a revocation context; ERRATA-05 E5-7), `WB_ITEM` (payload not listed), then `KEY_MISMATCH`, `WA_CLIENTDATA`, `WA_AUTHDATA`, `WA_SIG`. A `wb` carries one signature; therefore an item is batchable only when its requirement is k = 1 for a role the signer holds (`wb_requirements_met`). A signer who is not in the policy yields `WQ_NOT_MEMBER`. A group is homogeneous (one agent, one class, one recipient or channel); that is a rule of the service, not of the verifier.

## 6. Requirements

`requirements(policy, typ, payload_map, action)` returns the list of `(role, k)` the signatures must meet, one entry per role. It is a pure function shared by the service and the verifier.

- Mandate. `money`: the mandate grants any of purchase, sale or refund (value neither false nor null). `money_over X`: the largest of `budget`, `max_per_action`, `min_price` over the granted money classes is greater than X; a class granted as plain `true` is unbounded and exceeds every X; a class granted as `{}` or with null limits contributes 0 and does not fire `money_over` (ERRATA-05 E5-3; such an action is always deferred and carries its own approval). `access`: any non-money class is granted. The requirement of a role is the maximum k of the tiers that fire. A mixed mandate therefore needs both roles.
- Approval. The payload carries only a hash, so the ACTION is needed: a money class selects `money`/`money_over` by `action.amount`, any other class selects `access`. Without an action the function returns an empty list (the stateless part of the check); the service checks the action before the approval is accepted and the verifier takes it from the RECEIPT entry.
- Refusal. An APPROVAL with `approved = false` is a stop, and stopping is easy (A.1): it needs ONE signer who holds a role named by the requirements of the approval rule for that action (`any` names every member); when the requirements are empty (no tier fires, or no action) any member of the policy version in force suffices. It is not `k` of the tier and not the `revocation` rule.
- Revocation, ceiling, policy: the single request of the matching rule. The default revocation rule is any role, k = 1: stopping is easy, widening is hard.
- A requirement `(role, k)` is met when at least k distinct signers hold the role in the policy version used (`any` matches every member). One person holding two roles counts for both.

## 7. Two passes: policy at time

A verifier reads a ledger in two passes (A.4). Pass 1 (the ledger): chain, signatures and the structure of every envelope; `wq` without `at`, so no requirement is checked and no policy time is applied; a `wb` is accepted when its signature and its item are valid under ANY version of the chain. Pass 2 (policy at time): for every entry with an envelope the policy version in force at the `t` of the entry is taken, and then the `wq` is checked with `at`, a `wb` against the membership of that version, and a plain `wa-sig` or COSE_Sign1 of the pinned key as a quorum of one (A.2). A fault found by pass 1 is reported on the ledger line, one found by pass 2 on the `quorum` line; the verdict is the same. The paragraph below describes pass 2.

A ledger entry that contains a `wq` is acceptable only if the policy named in it was the current version at the time of the entry: `policy[v].t <= entry.t < policy[v+1].t`. The service checks this when it accepts the entry (its current policy). A verifier performs a second pass over the ledger, supplying `at = entry.t` and a chain whose items carry `t` (the time of the registry record that made the version effective). A signer removed in version 3 can therefore not authorise an entry written after version 3 by signing under version 2 (`WQ_POLICY_STALE`). A chain without times cannot prove this and fails the second pass. `policy_at(chain, t)` returns the version in force at t.

## 8. Release signature

A human releases or rejects an action held by the local advisor with a `wa-sig` of `typ = application/dw-release+cbor` over the CDE map `{ "rid": tstr, "args_sha256": bstr .size 32, "release": bool }` (`release_payload`). A hexadecimal digest is converted to 32 bytes before encoding. Code on failure: `RELEASE_SIG`.

## 9. Security Considerations

- **Policy time rests on the witness.** The times `t` are the witness's clock (draft-deus-aar-04 12.6) and, like the pinning of keys (PROFILE-webauthn-00 3.7), the policy chain is only as honest as the witness that records it. The hourly anchor of the registry log bounds back-dating; it does not prove the order of events within an hour.
- **A batch is a rubber-stamp risk.** One gesture covers up to 20 items. The page MUST show every item, the group MUST be homogeneous, items needing k >= 2 are excluded, and an operator SHOULD watch the refusal rate inside batches against the item-by-item rate; a batch that never refuses is a signal of stamping.
- **Observers are outside the policy.** They never sign and are not in `members`; their existence is not visible to a third party, and neither are names or mail addresses (a `label` and a `kid` only).
- **What the human sees.** As in PROFILE-webauthn-00 3.7, the authenticator does not display the object; each browser computes the CDE and the challenge from the fields it shows. A compromised service can serve a different page; the quorum raises the cost (several independent devices must be fooled) but does not remove the assumption.
- **Dishonest requirement lists.** A requirement larger than the holders of the role is rejected at policy validation, so a policy cannot silently disable a class of objects.
- **Replay across versions.** A `wq` binds its policy hash, and a mandate or approval carries its own unique id or receipt, so a quorum collected under one version cannot be replayed as another object; the second pass restricts it to the time its version was in force.
- **Failure ordering.** Membership is checked for all signers before any signature is verified; when several things are wrong the code reported is the first in the order of Section 4.

## Appendix A. Changes from -01

Numbers 1-10 are the interoperability ambiguities PACK-1 ... PACK-10 found when more than one implementation (Python, Swift) was run on the same test packs. The implementations and the interoperability report are not part of this repository.

**A.1 (PACK-1) Refusal under `money_over`.** Section 6 gains the "Refusal" rule: an APPROVAL with `approved = false` needs one signer who holds a role named by the approval requirements for the action (`any`: every member); with no requirement, any member. Why this and not the `revocation` rule: the refusal concerns one action of the class the approval rule governs, so the signer must be someone the policy trusts for that class (a member with only `access` cannot refuse a refund); stopping stays easy (k = 1, never the k of the tier). A refusal signed with a `wq` and with a `wa-sig` is treated alike; in a `wb` a refusal is not batched (the batch envelope is an approval, Section 5). Implementation A already behaves so; implementation C applied the `revocation` rule (any member) and differs only for a signer without a named role (packs `refusal-member-without-named-role`: A INVALID `WQ_QUORUM@2`).

**A.2 (PACK-2) `wa-sig` after the genesis.** From the `t` of version 1 (`policy_at(chain, t)` is not empty) a plain `wa-sig` (or the COSE_Sign1 of the 0.1 single-owner form) of a pinned key counts as ONE signature of a member of the version in force: the member is found by `kid` (the pinned key's thumbprint, or the `kid` the `wa-sig` names, PROFILE-webauthn-00), and every requirement `(role, k)` of the object is met only if k <= 1 and the member holds the role (`any` matches every member). An unknown signer is `WQ_NOT_MEMBER`, an unmet requirement `WQ_QUORUM`. Before the `t` of version 1 the single-owner rule of PROFILE-webauthn-00 applies unchanged. A plain `wa-sig` therefore cannot bypass a team rule: an owner alone cannot sign a mandate that needs budget k = 2.

**A.3 (PACK-3) `POLICY_TIME`.** New code, in `verify_policy_chain` after the checks of the signature and `prev` of each version, as `(POLICY_TIME, ver)`: the `t` of version k MUST be strictly greater than the `t` of version k-1 (equal is a fault: `policy_at` would have two versions in force). The code joins the list of Section 3 and of Appendix I of draft-deus-aar-05 (to be folded in the next edition of the draft). Pack: `policy-times-must-increase` (`test_policy_times_must_increase`).

**A.4 (PACK-4) Two passes.** Defined in Section 7: which checks belong to which pass and which line reports a fault. The code of the first fault in ledger order is the verdict, so verdict and code of the line may differ in place (ledger line vs `quorum` line) between conforming implementations; the RESULT must not.

**A.5 (PACK-5) `P.seq` is a position.** In Section 9.5 of draft-deus-aar-05 steps 3-4 ("the entry at P.seq") the entry is the one at POSITION `P.seq` in the presented ledger (counting from 0), not the entry that declares that `seq`. On an intact ledger the two coincide; on one with a removed line the entry at the position is another one and the promise is BROKEN. Both implementations now read it so.

**A.6 (PACK-6) `account` and `principal` in the manifest.** The signed `manifest.cose` names an `account` (the witness's tenant identifier) and `manifest.json` a `principal` (`dw:<hex>` of the owner key). The profile defines no derivation between them and a verifier MUST NOT fail a pack for a mismatch of their spelling. The binding that counts is the `principal`: it SHOULD equal the principal of the registry entry and of the mandates in the ledger; `account` is only a label for the human. A verifier MAY print a note when it cannot relate them.

**A.7 (PACK-10) Trust in the witness key of a pack.** The witness key is taken from `manifest.json` of the pack, like everything else the pack carries. A third party who wants more than "the pack is self-consistent" MUST pin the key himself: he compares the key of the pack with the one he got from the operator or from an earlier pack. A checker SHOULD offer an option to pin the key (`--witness-key <hex>`, not yet in the reference checker: the comparison is by hand until it exists) and SHOULD print the key it used. The signed manifest and the checkpoint then bind the ledger to that key; what the profile does not give is a way to find out that a key is the right one, only that it did not change.

Not changed from -01: Sections 1, 2, 4, 8, and everything in Section 9 except that "Policy time rests on the witness" now also covers the `POLICY_TIME` check.
