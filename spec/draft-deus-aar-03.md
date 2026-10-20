---
title: "Agent Action Receipts with Human Mandate and Cumulative Ledger"
abbrev: "Deus AAR"
docname: draft-deus-aar-03
category: info
ipr: trust200902
submissiontype: independent
date: 2026-10-18
status: "PRIVATE WORKING DRAFT - not submitted, not published"
author:
  - name: Deus Witness project
    org: Sipki LLC
---

# Agent Action Receipts with Human Mandate and Cumulative Ledger (deus-aar-0.1)

## Abstract

This document specifies the Agent Action Receipt (AAR) profile, version
`deus-aar-0.1`. An AAR is a SCITT Signed Statement [RFC9943], encoded as
COSE_Sign1 [RFC9052], that records the decision taken on a single action
of an AI agent *before* the action reaches a tool. The profile does not
define a new envelope, a new log, or a new policy language for payments.
It reuses SCITT for the envelope and the transparency log, and it is
designed to sit next to the SCITT Permit profile
[I-D.munoz-scitt-permit-profile] and the Mastercard Verifiable Intent
credential [VI]. It adds exactly three things (unchanged in -01, -02 and -03):

1. a **human-key mandate**: the authority for non-payment actions
   (messages, files, disclosure of personal data, meetings, and later
   deletion and publication) is a statement signed by the principal's
   own device key, not by the operator's policy engine;
2. a **cumulative mandate ledger**: an append-only, hash-chained ledger
   of reservations and consumptions that enforces budgets across all
   actions, sessions, process restarts, witness instances and mandates
   of one principal, and that a third party can replay and check
   without trusting the operator;
3. an **independent witness signer**: the AAR is signed by a witness
   whose key the agent operator does not control, and tools execute
   only against a valid witness receipt.

The ledger head is periodically anchored with OpenTimestamps; a second
anchor is optional. No token is defined or required.

## Status of This Memo

This is a private working draft of the Deus Witness project
(Sipki LLC). It has not been submitted to the IETF or published
anywhere. Section numbers, field names and labels will change.

Revision -03 (reference implementation revision 4.4) closes the 12
ambiguities and the one editorial defect that C found in -02 (report
OTCHET-INTEROP-C-02-2026-10-18, numbering `AMBIGUITY-C2-n`). One of
them, C2-11, is a security defect and not only an ambiguity: -02 did not
require that the RECEIPT entry behind an AAR records the decision the
AAR carries, so a witness in collusion could give a tool an `allow` AAR
over a logged refusal and every check passed. -03 closes it in Section
8.4 check 8 and Section 10 step 9 and adds Section 12.12. Appendix F
lists each C2-n and where it is resolved. The profile identifier
`deus-aar-0.1` is NOT changed. The text below is the full -03 text;
Appendix D (changes -00 to -01) and Appendix E (-01 to -02) are kept
for history.

Revision -02 (reference implementation revision 4.3) closed the 24
ambiguities that a third, clean-room implementation (C, Swift, written
from -01 and its vectors only; report OTCHET-INTEROP-C-2026-10-18,
numbering `AMBIGUITY-C-n`) found in -01. Appendix E lists each one and
where it is resolved. The profile identifier `deus-aar-0.1` is NOT
changed. Three implementations now exist (A: aar_ref, B: verifier_js,
C: verifier_swift); all were written inside one project, so the evidence is
still a consistency check, not independent multi-organisation interop.

Revision -01 (reference implementation revision 4.2) closed the 32
ambiguities that an independent second implementation found in -00
(verifier_js, report OTCHET-INTEROP-2026-10-18). The "Changes from -00"
appendix (Appendix D) lists each ambiguity and where it is resolved.
The profile identifier `deus-aar-0.1` in the `v` and `spec` members is
NOT changed by this revision: it names the profile, not the draft. The
byte-level and abstract test vectors of Appendix A are the conformance
material; two implementations (A: aar_ref, B: verifier_js) were run
against them. Both were written inside one project, so this is a
consistency check, not independent multi-organisation interop.

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Architecture
4. Keys and Roles
5. Common Data Model
6. Human-Key Mandate
7. Cumulative Mandate Ledger
8. Agent Action Receipt (SCITT Profile)
9. Anchoring
10. Third-Party Verification
11. Transport Binding (Informative)
12. Security Considerations
13. Privacy Considerations
14. IANA Considerations
15. Open Questions
16. References
Appendix A. Test Vectors and Conformance
Appendix B. Mapping to the Reference Implementation
Appendix C. Comparison with Neighbouring Work
Appendix D. Changes from -00
Appendix E. Changes from -01
Appendix F. Changes from -02

---

## 1. Introduction

### 1.1 Problem

An AI agent acting for a person sends e-mail, shares files, discloses
the person's address or phone number, books meetings and spends money.
When something goes wrong, three parties disagree about what was
authorised: the person (the principal), the company that runs the agent
(the operator), and whoever suffered the loss. Logs written by the
operator are the operator's testimony about itself. A receipt signed by
the operator's policy engine proves what the operator decided, not what
the principal allowed.

Two properties are missing from the evidence today:

- **Whose authority.** The constraint that an action was checked
  against must itself be signed by the principal, with a key the
  operator does not hold. Otherwise the operator can widen the authority
  before the check and the receipt still verifies.
- **Cumulative state.** Many harms are not one large action but many
  small ones (budget splitting). A per-action receipt cannot show that
  the sum stayed within the mandate. The cumulative state must be
  reconstructible by a third party from signed records, across
  sessions, restarts and instances.

### 1.2 What already exists and what this profile adds

The field moved quickly in 2026 and this profile deliberately does not
compete with existing layers:

- **Envelope and log**: SCITT [RFC9943] with COSE_Sign1 and COSE
  Receipts [I-D.ietf-cose-merkle-tree-proofs]. AAR is a SCITT profile.
  Several agent-receipt profiles already exist
  ([I-D.noa-scitt-ai-agent-receipt], [I-D.mih-scitt-agent-action-capsule],
  [I-D.emirdag-scitt-ai-agent-execution], [I-D.sharif-agent-audit-trail]);
  AAR aligns its `action` and `chain` fields with them where possible.
- **Pre-execution authorization bound to request bytes**: the Permit
  profile [I-D.munoz-scitt-permit-profile] and its open implementation
  [KEEL-PERMIT] with an independent verifier [KEEL-VERIFIER]. AAR adopts
  the same idea of binding the decision to the canonical request
  (`binding_request_hash`) and MAY carry a Permit reference. Keel's
  work-chain specification also maintains a root-wide value ledger for
  monetary lanes.
- **Human-key mandates for payments**: Mastercard Verifiable Intent [VI]
  (layer L2 signed by the user's device key bound in L1) and AP2 [AP2],
  now under FIDO Alliance working groups. AAR consumes these for
  payments and does not redefine them.

As of 2026-10-17, none of the documents above (as read by the authors;
see Appendix C for the exact checks and their limits) combines:
(a) authority signed by the principal's key, (b) a cumulative ledger
that a third party verifies without trusting the operator or a payment
network, and (c) coverage of non-payment actions. In particular the
Keel verifier documentation states: "Pre-signing manipulation by a
privileged Keel operator at the moment evidence is created is NOT
detected by this verifier", and the Keel README states that "Keel's
issuer does not currently accept co-signatures". In Verifiable Intent
the cumulative budget (`mandate.payment.budget`) is tracked by the
payment network, not in a ledger a third party can replay.

AAR therefore adds exactly the three elements listed in the Abstract.
Everything else is taken from existing work.

### 1.3 Non-goals

This profile does not specify: a general policy language; agent
identity or attestation of agent software; payment authorization (use
[VI]/[AP2]); content inspection or data-loss prevention; a token,
blockchain or consensus protocol; legal effect of receipts.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

- **Principal**: the human (or organisation acting through a named
  human) on whose behalf the agent acts. Holds the principal key.
- **Agent**: software that proposes actions. Untrusted. Has no key in
  this profile; `agent` is a label bound into the mandate.
- **Operator**: the party that runs the agent and usually the
  infrastructure around it. Untrusted for the purposes of this profile.
- **Witness**: the enforcement point and signer of AARs. Sits on the
  only path from the agent to the tools, holds the tool credentials, and
  signs with a witness key the operator does not control (Section 4.3).
- **Tool**: the system that performs the effect (mail server, file
  share, marketplace, calendar, payment rail). Executes only against a
  valid AAR addressed to it.
- **Mandate**: a principal-signed statement of what the agent may do
  (Section 6).
- **Ceiling**: a principal-signed cumulative limit across all mandates
  of the principal (Section 6.3).
- **Ledger**: the append-only, hash-chained sequence of witness-signed
  entries for one principal (Section 7).
- **Reservation**: an amount held against a mandate budget and the
  ceiling from the moment of authorization until it is consumed or
  released (Section 7.4).
- **Verifier**: any third party holding only public keys and the
  ledger (auditor, insurer, court, counterparty).
- **Transparency Service (TS)**: a SCITT Transparency Service [RFC9943].
- **Verdict**: one of `allow`, `defer`, `deny`.

---

## 3. Architecture

```
 principal device                         independent witness
 (device key)                             (witness key != operator)
   |  signed Mandate / Ceiling /                |
   |  Approval / Revocation                     |
   +------------------------------------------->|
                                                |  evaluate (Sec. 6.4)
 agent --(proposed action)--> [operator] ------>|  reserve  (Sec. 7.4)
                                                |  sign AAR (Sec. 8)
                                                |----(AAR)----> tool
                                                |<--(consume / tool-signed
                                                |    non-execution)
                                                v
                                   principal ledger (hash chain)
                                                |
                         +----------------------+-------------------+
                         v                                          v
              SCITT Transparency Service                  checkpoint -> OpenTimestamps
              (COSE Receipt of inclusion)                 (+ optional 2nd anchor)
                                                |
                                                v
                                    verifier (public keys only)
```

Flow for one action:

1. The principal signs a mandate on a device and delivers it to the
   witness. The witness appends a MANDATE entry.
2. The agent proposes an action. The operator forwards it to the
   witness (the operator cannot reach the tool directly because the
   tool credentials are held by the witness and the tool requires an
   AAR).
3. The witness evaluates the action against the mandate and the ledger
   state (Section 6.4), creates a reservation if the action is
   a purchase, appends a RECEIPT entry and signs the AAR.
4. On `allow`, the tool checks the AAR (Section 8.4) and executes; the
   consumption is appended to the ledger. On `defer`, the principal
   decides with a signed approval (Section 6.6). On `deny`, nothing is
   executed.
5. The witness registers AARs with a TS and periodically anchors a
   checkpoint of the ledger head (Section 9).
6. A verifier replays the ledger and re-derives every verdict from
   principal-signed inputs (Section 10).

---

## 4. Keys and Roles

### 4.1 Principal key

The principal key signs mandates, ceilings, approvals and revocations.

- It MUST be an asymmetric key generated on a device controlled by the
  principal. ES256 (ECDSA P-256 with SHA-256) MUST be supported;
  EdDSA (Ed25519) SHOULD be supported.
- The mandate carries a `key_attestation` value: `secure-element`
  (non-exportable key with hardware attestation evidence, e.g. Secure
  Enclave, TPM, Android StrongBox), `passkey` (WebAuthn credential
  [WebAuthn]), or `software`. Attestation evidence, if present, SHOULD
  follow RATS conventions [RFC9334]. Verifiers MAY require a minimum
  level by policy; the profile itself accepts all three.
- The operator MUST NOT possess the principal key or any key able to
  produce signatures that verify under it.

### 4.2 Key pinning (no trust on first use)

A witness MUST NOT accept the first key that presents itself under a
principal name. The principal key MUST be pinned from a source outside
the operator's and the witness's control before the first MANDATE entry
is accepted. Acceptable sources include: a key bound in a Verifiable
Intent L1 credential (`cnf.jwk`) [VI], a key registered by the
principal with the tool provider (account settings, passkey
registration), or an out-of-band registry agreed between the principal
and the verifier. The ledger MUST record the pinning source in the
first entry. Records signed by any other key under the same principal
identifier MUST be rejected (`KEY_MISMATCH`) and MUST NOT modify ledger
state.

### 4.3 Witness independence

The value of an AAR rests on its signer not being the party whose
behaviour it describes. Therefore:

- The witness key MUST NOT be held by, derivable by, or usable at will
  by the operator. A witness key that appears in the operator's
  published key set MUST cause verification failure
  (`WITNESS_NOT_INDEPENDENT`).
- The witness MUST publish its key set and an **independence
  statement** naming the legal entity that controls the key and the
  deployment model. Defined deployment models are: `separate-party`
  (operated by an entity other than the operator), `tee` (key sealed in
  a trusted execution environment whose attestation is published and
  whose code measurement is reproducible), and `principal-hosted`
  (operated by or for the principal).
- A deployment in which the witness is operated by the operator on
  ordinary infrastructure is NOT conforming to this profile, even if
  the code is identical. It MAY still emit AAR-formatted statements but
  MUST set `independence` to `none`, and verifiers MUST NOT treat them
  as witness receipts.
- Tools MUST hold credentials only for the witness, so that the witness
  is on the only path to the effect. Where a tool cannot be put behind
  the witness, actions on that tool are outside the guarantees of this
  profile (Section 12.9).
- Multiple witnesses MAY co-sign (k-of-n); see Section 12.6.

### 4.4 Operator

The operator is not trusted. It can drop, delay, reorder or invent
proposed actions and can lie about outcomes. The profile is designed so
that these behaviours either fail closed (nothing executes) or become
visible to a verifier.

---

## 5. Common Data Model

### 5.1 Encoding

All signed payloads are CBOR maps [RFC8949] encoded with Core
Deterministic Encoding (CDE, Section 4.2.1 of [RFC8949]). In -01 map
keys are text strings for readability; integer labels are an Open
Question (Section 15). Hashes are SHA-256 over the deterministic
encoding.

Encoding is a property that verifiers CHECK, not only one that signers
produce. A verifier or tool MUST reject, with `MALFORMED`, any
COSE_Sign1 whose payload or protected header (a) is not well-formed
CBOR, (b) is not in Core Deterministic Encoding, (c) contains a
duplicate map key, or (d) is not tagged with CBOR tag 18. The tag is
mandatory in this profile: one object has one byte string, and entry
hashes (Section 7.1) are taken over those bytes. The protected header
MUST contain `alg`, `kid` and `typ`; `alg` or `kid` found only in the
unprotected header is `MALFORMED`. A detached (nil) payload is
`MALFORMED`.

### 5.2 Amounts

Amounts are non-negative integers in minor units (e.g. cents) together
with an ISO 4217 currency code. Floating-point values, negative values,
values above 10^15 (the value 10^15 itself is allowed) and any currency
other than the mandate's currency MUST be rejected with `BAD_AMOUNT`.
`currency` is REQUIRED in the mandate and in every monetary action
(`purchase`, `sale`, `refund`); an absent `currency` in either is
`BAD_AMOUNT`. `amount` is REQUIRED in a monetary action: an absent
`amount` is `BAD_AMOUNT`. A non-monetary action carries `amount` 0 or no
`amount`; any other value (for example `amount: 5` on a `message`) is
`BAD_AMOUNT`. Non-monetary actions are not subject to the currency rule.
Witnesses MUST NOT round or convert. A ledger
carries one currency (Section 15, item 14): the `currency` of its first
MANDATE entry. A later MANDATE or CEILING in another currency is
rejected by the witness (`MANDATE_MALFORMED`, `CEILING_MALFORMED`) and is
the same error at the entry in a verifier (Section 10 step 4).

In JSON test vectors a number written with a fraction or an exponent
(for example `100.0` or `1e2`) denotes a floating-point value and is
rejected; a vector reader that cannot tell `100.0` from `100` is not
usable for the vectors.

### 5.3 Time

All validity checks use the witness clock, never a time asserted by the
agent or operator. The witness clock MUST be monotonic: a backwards
step of the host clock MUST NOT move witness time backwards (it is
clamped). Times are integer seconds since the Unix epoch
everywhere in this document (ledger `t`, `expires`, `window_s`, `ttl`).
See Section 12.7 for the limits of this.

The decision function of Section 6.4 takes witness time as an argument.
A member `t` inside an action map is requester-asserted, is part of the
request bytes (Section 5.7) and is NEVER used for any validity check.
The abstract test vectors use `action.t` as a shorthand for the witness
clock (Appendix A); that is a property of the vector harness, not of
the protocol.

### 5.4 Recipients

A recipient of a `message`, `file` or `disclosure` action is
canonicalised before comparison, in this order:

1. If the string contains `<` or `>`, it MUST contain exactly one `<`
   followed by exactly one `>` with at least one character between them
   and no other `<` or `>`; the canonical input is the text between
   them. Any other use of `<` or `>` (two pairs, an unclosed pair)
   makes the recipient **invalid**: it matches nothing and is denied
   (`RECIPIENT`). This holds in every permission state: an invalid
   recipient is not matched by `to: "*"` and is not `OK_UNSPECIFIED`
   or `ESCALATE_FILE` (Section 6.4 step 10).
2. Apply the Unicode `toNFKC_Casefold` mapping once (Unicode Standard
   Section 3.13, property `NFKC_CF`: NFKC, full case folding, removal
   of default-ignorable code points). Full case folding maps U+00DF to
   `ss`.
3. Remove every code point with the Unicode `White_Space` property.

Comparison is exact on the canonical form. Entries of `to` and
`domains` in the mandate are canonicalised the same way (without step
1). Domain grants match the canonical domain (the part after the last
`@`) exactly; a subdomain does NOT match its parent. Homoglyphs are not
mapped and therefore do not match (fail closed). Resource and channel
identifiers of `delete` and `publish` are NOT canonicalised (Section
5.6.1).

### 5.5 Data classes

Each action declares the data classes it carries (`data`). This profile
registers `city` as non-protected and `address`, `phone`, `passport` as
protected. Every unregistered data class MUST be treated as protected.
Data class labels are compared byte-exact (`City` is not `city`, so it
is an unregistered, hence protected, class); registered labels are
lower-case ASCII. The declaration is made by the party proposing the
action; see Section 12.8 for why this is a limitation.

### 5.6 Action classes and risk levels

| class        | meaning                                   | risk level |
|--------------|-------------------------------------------|------------|
| `message`    | send a message                            | `low`, or `disclosure` if protected data |
| `file`       | share a file (content opaque to witness)  | `disclosure` |
| `disclosure` | reveal personal data to a recipient       | `low` if only non-protected data, else `disclosure` |
| `purchase`   | spend the principal's money               | `monetary` |
| `sale`       | sell on the principal's behalf            | `monetary` |
| `refund`     | request or issue a refund                 | `monetary` |
| `meeting`    | arrange a physical meeting                | `low` if `principal_present` is the boolean `true` (absent, `false` or any other value, e.g. `"yes"` or `1`, = not present), else `irreversible` |
| `delete`     | delete a resource (`recipient` = resource id; `reversible` flag, boolean, default false) | `low` if `reversible` is the boolean `true`, else `irreversible` |
| `publish`    | publish to an open channel (`recipient` = channel id) | `disclosure`; any protected data is denied |

The risk level is computed from the action content, not from the tool
name. Any class not in this table MUST be evaluated as `irreversible`
and denied (`CLASS_UNKNOWN`). The classes `delete` and `publish` are
registered (they were "fail-closed until registered" in -00) and have
their own rules in Section 5.6.1 and Section 6.4 step 10; the rules
there are normative and the single source: the `low` row of Section 6.2
("unspecified is allowed") does NOT apply to them.

### 5.6.1 Resource and channel identifiers (`delete`, `publish`)

`delete` targets and `publish` channels are opaque strings (for
example `repo:tmp/cache`, `blog:main`). They are compared byte-exact
and are NOT canonicalised. A mandate entry (in `targets` or `channels`)
matches an action identifier `r` as follows:

- an entry equal to `r` matches;
- an entry of length two or more that ends in `*` is a prefix pattern:
  it matches every `r` that begins with the entry without its final
  `*`; `*` has no meaning anywhere else in an entry and there is no
  other wildcard;
- an entry that is just `*` is a pattern with an empty prefix and is
  NOT allowed to match anything (a principal who wants "everything"
  must say so with an explicit permission model in a later revision);
- a pattern never matches an `r` that contains a `.` or `..` path
  segment (segments are separated by `/`); such an `r` can only match
  by an exact entry.

Matching a pattern says nothing about what the tool does with the
identifier; a tool that resolves paths MUST resolve them before
building the request it presents (Section 8.4).

### 5.7 Canonical request and hashes

- **Request map.** The request is the `action` map exactly as the
  operator submitted it to the witness, with every member it contains
  (`class`, `agent`, `recipient`, `data`, `amount`, `currency`, and
  where present `t`, `reversible`, `principal_present`). The witness
  adds and removes nothing. `binding_request_hash` is SHA-256 over the
  Core Deterministic Encoding of this map; the tool hashes the request
  it is about to execute in the same way. Two requests that differ in
  any member, including `t`, have different hashes.
- **Mandate hash.** SHA-256 of the CDE payload of the mandate (the
  signed map itself, not the COSE_Sign1 bytes: an ES256 signature is
  not unique, the payload is). The same value is `mandate.ref.digest`
  in the AAR.
- **Action hash.** The `binding_request_hash` of the deferred request.
- **Entry hash.** SHA-256 over the COSE_Sign1 bytes of a ledger entry.
  Because signatures are canonical (Section 8.1), the entry bytes are
  unique.

---

## 6. Human-Key Mandate

### 6.1 Structure

A mandate is a COSE_Sign1 signed with the principal key. Protected
header: `alg`, `kid`, `typ` = `application/aar-mandate+cbor` [RFC9596].

**Key identifiers.** Every `kid` in this profile (principal key,
witness key, checkpoint key) is the COSE Key Thumbprint of the public
key per [RFC9679] with SHA-256: 32 bytes, computed over the
deterministically encoded COSE_Key that holds only the required
members (OKP/Ed25519: `kty` 1, `crv` 6, `x`; EC2/P-256: `kty` 2,
`crv` 1, `x`, `y`). A verifier recomputes the thumbprint of each key
in the set it has pinned and selects a key only when the header `kid`
equals it; a header `kid` that equals no pinned thumbprint is
`KID_UNKNOWN`. A shortened hash of the key (for example the first 16
bytes of SHA-256) is NOT a `kid` in this profile.

A witness MUST reject a mandate that does not match the CDDL below
(`MANDATE_MALFORMED`); a verifier treats a MANDATE entry that does not
match as `MANDATE_MALFORMED`. Members not named here are not allowed.

```cddl
mandate = {
  "v": "deus-aar-0.1",
  "id": tstr,                        ; unique within the ledger (a random 128-bit value is RECOMMENDED)
  "principal": tstr,                 ; principal identifier
  "agent": tstr,                     ; agent label this mandate binds
  "nbf": uint, "exp": uint,          ; validity, witness clock
  "currency": tstr,                  ; ISO 4217, REQUIRED
  "budget_window_s": uint,           ; sliding window for budgets, REQUIRED
  "permissions": permissions,
  "forbidden_data": [* tstr],        ; never, overrides all grants
  ? "named_circle": bool / null,     ; Section 6.5; absent or null = false
  "key_attestation": "secure-element" / "passkey" / "software",
  ? "pin_source": tstr / null,       ; Section 4.2
  ? "payment_mandate_ref": hash-ref / null, ; VI L2 / AP2 for payments
  ? "permit_ref": hash-ref / null,   ; Permit [I-D.munoz-...]
}
permissions = {
  ? "message":    recipients / false / null,
  ? "file":       recipients / false / null,
  ? "disclosure": disclosure / false / null,
  ? "purchase":   { ? "max_per_action": uint / null, ? "budget": uint / null } / false / null,
  ? "sale":       { ? "min_price": uint / null } / false / null,
  ? "meeting":    true / false / null,
  ? "refund":     true / false / null,
  ? "delete":     { "targets": [* tstr], ? "allow_irreversible": bool / null } / false / null,
  ? "publish":    { "channels": [* tstr] } / false / null,
}
; every `?` member also accepts null, and null means the same as an absent
; member (unspecified, Section 6.2); a CDDL validator and the prose agree
recipients = { ? "to": "*" / [* tstr] / null, ? "domains": [* tstr] / null }
disclosure = { ? "to": "*" / [* tstr] / null, ? "domains": [* tstr] / null,
               ? "data": [* tstr] / null }
hash-ref   = { "alg": "sha-256", "digest": bstr, ? "uri": tstr }
```

**Optional members.** Every member marked `?` may be absent or `null`
(the CDDL says `/ null` where the type is not otherwise nullable), and
an absent optional member has the value `null` (for `named_circle`:
`false`). Absent and `null` mean the same everywhere in this document
(Sections 6.2 and 6.4); the mandate hash (Section 5.7) is taken over the
bytes as signed, so absent and `null` give different hashes but the
same meaning. Members not named in the CDDL are not allowed, in the
mandate and in the permission maps; the witness answers
`MANDATE_MALFORMED` for them and for a missing REQUIRED member (every
member without `?`).

**Consistency with the ledger.** The `principal` of every MANDATE (and
the `principal` of every ceiling map, which a verifier recomputes from
the ledger) MUST be the principal identifier the ledger identifier was
derived from (Section 7.1; in an abstract vector, the pinned principal
key). The `currency` of every MANDATE and CEILING MUST equal the
currency of the first MANDATE of the ledger (Section 5.2). A witness
rejects a mandate that breaks either rule with `MANDATE_MALFORMED` and a
ceiling that breaks the currency rule with `CEILING_MALFORMED`; a
verifier reports the same code at that entry (Section 10 step 4).

### 6.2 Tri-state permissions

Each permission is in one of three states. **Absent** (or `null`)
means the principal did not say (unspecified). **false** means
explicitly denied.
A **specification** names whom or how much. An explicit list or number
is stronger than the default: a recipient outside an explicit list, or
an amount above an explicit limit, is denied, not deferred.

The meaning of "unspecified" depends on the risk level:

| risk level     | unspecified permission means              |
|----------------|-------------------------------------------|
| `low`          | allow, with reason `OK_UNSPECIFIED` in the receipt |
| `monetary`     | defer to the principal (`ESCALATE_MONEY`); a `purchase` holds a reservation, a `sale` or `refund` does not |
| `disclosure` (file) | defer (`ESCALATE_FILE`)              |
| `disclosure` (protected data) | deny unless the data class is explicitly granted (`DATA_NOT_PERMITTED`) |
| `irreversible` | deny                                      |
| `delete`, reversible | defer to the principal (`ESCALATE_DELETE`); NEVER `OK_UNSPECIFIED` |
| `delete`, irreversible | deny (`IRREVERSIBLE_DELETE`)            |
| `publish`      | defer (`ESCALATE_PUBLISH`); with protected data deny (`DATA_FORBIDDEN`) |

For `message`/`file`/`disclosure` recipients, "unspecified" is exactly:
`to` is null or absent AND `domains` is null or absent. An empty
list (`to: []` or `domains: []`) is an explicit specification that
matches no recipient: it is denied, not deferred. `to: null` with a
`domains` list is a specification (only the listed domains match).

Rationale for denying, rather than deferring, protected data: disclosure
cannot be undone, and approval of deferrals is often blind. In the
project's L1 simulation (approvals modelled as blind with probability
0.97, an assumption, not a measurement of people) deferring protected
data produced 11 disclosures and 0 honest ones; denying produced 0. This is a contested choice (Section 15).

### 6.3 Ceiling

A ceiling is a principal-signed COSE_Sign1 (`typ`
`application/aar-ceiling+cbor`) whose payload is the map

```cddl
ceiling = { "v": "deus-aar-0.1", "id": tstr, "principal": tstr,
            "amount": uint, "currency": tstr, "window_s": uint }
```

All six members are REQUIRED; there is no default window (`window_s`
is an integer of at least 1). A CEILING that does not match this CDDL
(a member missing, of the wrong type or not named here, `window_s` 0)
is rejected by the witness with `CEILING_MALFORMED` and changes
nothing; a verifier treats a CEILING entry that does not match as
`CEILING_MALFORMED` (Section 10 step 4). The `currency` of a ceiling
MUST be the currency of the ledger (Section 6.1, consistency; a ceiling in
another currency is `CEILING_MALFORMED`). It bounds the sum of
committed amounts across **all** mandates of the principal. The CEILING
ledger entry carries these members as plain body fields beside the
`cose` object (Section 7.1). A witness MUST enforce the most recent valid ceiling. A
principal who issues several mandates without a ceiling has granted the
sum of their budgets; witnesses SHOULD warn the principal at signing
time when a second monetary mandate is issued without a ceiling.

### 6.4 Evaluation algorithm (normative)

Given mandate M, action A and ledger state S (committed amount for M,
committed amount for the principal, current ceiling), the witness MUST
compute the verdict as follows. The first matching step returns.

1. No mandate: `deny NO_MANDATE`.
2. Mandate signature does not verify under the pinned key:
   `deny MANDATE_SIG`.
3. `A.agent != M.agent`: `deny AGENT_MISMATCH`.
4. Witness time outside `[M.nbf, M.exp]` or mandate revoked (Section
   6.7): `deny EXPIRED`. (Witness time is the argument of the function,
   Section 5.3.)
5. `A.class` not registered: `deny CLASS_UNKNOWN`.
6. Amount invalid, a monetary action without `amount`, a non-monetary
   action whose `amount` is present and not 0, or a monetary action
   whose `currency` is absent or differs from `M.currency` (Section
   5.2): `deny BAD_AMOUNT`.
7. `A.data` intersects `M.forbidden_data`: `deny DATA_FORBIDDEN`.
8. The permission of the class is `false`: `deny CLASS_DENIED`. A
   `disclosure` that carries no protected data is evaluated under the
   `message` permission (step 10), so `message` = `false` is
   `CLASS_DENIED` for it too; `disclosure` = `false` stays
   `CLASS_DENIED` for it (an explicit denial of the class). A `message`
   that carries protected data is checked against `disclosure` in step
   12 (`disclosure` = `false` gives `DATA_FORBIDDEN` there).
9. Risk level `irreversible`: `deny UNATTENDED_MEETING` (meeting); the
   class `delete` is NOT handled here (it has its own rule in step 10:
   `deny IRREVERSIBLE_DELETE`); every other class evaluated as
   irreversible (that is, an unknown class) is `deny CLASS_UNKNOWN`.
10. Class rule (result R). For `message`, `file` and `disclosure` the
    recipient is examined first: an invalid recipient (Section 5.4)
    returns `deny RECIPIENT`, whatever the permission (unspecified,
    `to: "*"`, a list).
    - `meeting`: `allow OK` if granted, else `allow OK_UNSPECIFIED`.
    - `message`, and `disclosure` with no protected data (the latter is
      evaluated under the `message` permission): unspecified ->
      `allow OK_UNSPECIFIED`; recipient not matched -> `deny RECIPIENT`;
      else `allow OK` (or `OK_CIRCLE`, Section 6.5).
    - `disclosure` with protected data: evaluated under the
      `disclosure` permission's own recipients: recipients unspecified
      (Section 6.2: `to` and `domains` both null or absent, which
      includes a permission that names only `data` and a permission
      that is absent or null) -> `allow OK_UNSPECIFIED` (step 12 then
      decides, normally `defer ESCALATE_DATA`); recipient not
      matched -> `deny RECIPIENT`; else `allow OK`. Because this rule
      runs before step 12, a disclosure to a recipient outside the
      explicit list is `RECIPIENT`, whatever data classes it names.
    - `delete` (permission `dp`; `reversible` is true only for the
      boolean `true`): `dp` absent or null -> reversible: `defer
      ESCALATE_DELETE`, irreversible: `deny IRREVERSIBLE_DELETE`;
      `dp` present: the resource id (`recipient`) not matched by
      `dp.targets` (Section 5.6.1) -> `deny RESOURCE`; irreversible and
      `dp.allow_irreversible` not `true` -> `deny IRREVERSIBLE_DELETE`;
      else `allow OK`.
    - `publish` (permission `pp`): any protected data in `A.data` ->
      `deny DATA_FORBIDDEN` (whatever `disclosure` grants and before any
      other publish check); `pp` absent, null or without `channels` ->
      `defer ESCALATE_PUBLISH`; channel (`recipient`) not matched by
      `pp.channels` -> `deny RESOURCE`; else `allow OK`. Step 12 does not
      apply to `publish`.
    - `file`: unspecified permission or unspecified recipients ->
      `defer ESCALATE_FILE`; not matched -> `deny RECIPIENT`; else
      `allow OK` / `OK_CIRCLE`.
    - `refund`: granted -> `allow OK`; else `defer ESCALATE_MONEY`.
    - `sale`: unspecified or `min_price` null -> `defer ESCALATE_MONEY`;
      amount < `min_price` -> `deny PRICE`; else `allow OK`.
    - `purchase`: amount > `max_per_action` -> `deny PER_ACTION_LIMIT`;
      committed(M) + amount > `budget` -> `deny BUDGET`;
      committed(principal) + amount > ceiling -> `deny CEILING`;
      any of permission, `max_per_action`, `budget` unspecified ->
      `defer ESCALATE_MONEY`; else `allow OK`.
11. If R is `deny`, return R.
12. Protected-data rule (result D), applied when `A.data` contains a
    protected class, for every action class except `publish` (which
    never reaches it): `disclosure` permission
    `false` -> `deny DATA_FORBIDDEN`; absent or `data` null ->
    `deny DATA_NOT_PERMITTED`; a protected class not in `data` ->
    `deny DATA_FORBIDDEN`; recipients unspecified ->
    `defer ESCALATE_DATA`; recipient not matched by the `disclosure`
    recipients (the named circle never applies) -> `deny RECIPIENT`.
13. Combine: if D is `deny`, return D; if D is `defer` and R is `allow`,
    return D; otherwise return R.

The order encodes: explicit denial beats deferral, deferral beats
allowance. The evaluation is a pure function of principal-signed inputs
and ledger state; Section 10 depends on this.

### 6.5 Named circle (opt-in)

If and only if `named_circle` is `true`, a recipient that is not
matched by the permission under which the action is evaluated but is in
an explicit list for another class is allowed with reason `OK_CIRCLE`.
An **explicit list** is the `to` array of the `message`, `file` or
`disclosure` permission; a `domains` list and `to: "*"` do NOT belong to
the circle and an empty array contributes nobody. The circle applies to
`message`, to `file` and to a `disclosure` without protected data (which
is evaluated under `message`). The circle never opens protected data,
never overrides `false`, and never turns an unspecified `file`
permission into an allowance. The default is `false` (see Appendix B for the divergence
from the reference implementation).

### 6.6 Deferral and approval

On `defer`, the witness appends the RECEIPT entry with verdict `defer`
and, for a `purchase`, holds the reservation (Section 7.4). The principal decides
with a COSE_Sign1 under the principal key (`typ`
`application/aar-approval+cbor`). There is exactly one approval form,
used in the protocol and in the ledger:

```cddl
approval = { "v": "deus-aar-0.1", "t": "approval", "receipt": tstr,
             "mandate": bstr, "action": bstr, "approved": bool }
```

`receipt` is the id of the deferred RECEIPT (the CWT `sub` of its
AAR); `mandate` is the mandate hash and `action` the action hash of
Section 5.7. An approval is therefore bound to one receipt, one
mandate and one request and cannot be reused for a second, identical
request. An approval signed by any other key, or whose members differ
from what the ledger recomputes, MUST be rejected (`APPROVAL_SIG`, or
`MANDATE_KEY` in a verifier). A verifier applies the state test too: an
APPROVAL entry whose `receipt` is not a `defer` RECEIPT earlier in the
ledger that has not been decided before (no earlier APPROVAL for it)
and has not expired at the entry's `t` is `MANDATE_KEY` (Section 10
step 4); the witness answers `NOT_DEFERRED` for the same fault. The witness checks the approval in this
order: the principal signature and its payload (`APPROVAL_SIG`), then
that the receipt is a `defer` that has not been decided and has not
expired, that is, witness time is not after its `expires`
(`NOT_DEFERRED`). An approval that arrives after the deferral timeout
therefore returns `NOT_DEFERRED`, as does a second approval or an
approval of a refused or non-deferred receipt.

On `approved: true` the witness appends an APPROVAL entry and issues an
`allow` AAR (the **approved AAR**) with these members:

- the same CWT `sub` as the deferral AAR (the receipt id) and a `chain`
  that names the DEFERRED RECEIPT entry (its `ledger`, `seq` and entry
  hash), not the APPROVAL entry;
- `verdict` = `{ "decision": "allow", "reason": "OK_APPROVED", ... }`
  and `mandate.approved_by` = a `hash-ref` whose `digest` is the entry
  hash of the APPROVAL entry;
- `expires` = the `expires` of the deferred RECEIPT. An approval does
  not extend the receipt; there is no new `ttl`;
- `budget` as for the deferral (informative; it is not checked by a
  verifier).

A deferred RECEIPT followed by an approving APPROVAL entry (`approved`
true) counts as an `allow` receipt for Section 10 steps 6 and 9 and for
the reservation rules of Section 7.4; the reservation of the deferral is the one
consumed. A tool that receives an approved AAR applies Section 8.4 with
the additions of check 8 (the proof covers the RECEIPT entry, which
records `defer`, and the APPROVAL entry). The deferral AAR itself
(decision `defer`) is `NOT_ALLOWED` at a tool.

On `approved: false` the witness appends the APPROVAL entry (it records
the refusal) and then a RELEASE with cause `refused`. On timeout the
reservation expires like any other (`expires` of the deferred receipt is
the deferral timeout; there is no separate `decide_by`). An agent or
operator statement is never an approval.

### 6.7 Revocation

A principal-signed revocation (COSE_Sign1, `typ`
`application/aar-revocation+cbor`) with payload
`{ "v": "deus-aar-0.1", "t": "revocation", "mandate": bstr }`
(`mandate` = mandate hash, Section 5.7) takes effect at the ledger
position where its REVOCATION entry is appended. Actions evaluated
after it are denied (`EXPIRED`). Outstanding active reservations of the
mandate are released, one RELEASE with cause `revoked` each, directly
after the REVOCATION entry; a reservation already consumed (presented
to a tool) is not touched. A revocation signed by another key is
`KEY_MISMATCH` and changes nothing.

### 6.8 Relationship to payment mandates

For payment actions, implementations SHOULD use a Verifiable Intent L2
credential or an AP2 mandate as the authority and reference it with
`payment_mandate_ref`; the AAR then records the witness decision and the
cumulative ledger state. The AAR mandate is intended for actions those
credentials do not cover. Mapping VI constraints onto this ledger is an
Open Question.

---

## 7. Cumulative Mandate Ledger

### 7.1 Entries

The ledger is a sequence of entries, each a COSE_Sign1 signed by the
witness key, with payload:

```cddl
entry = {
  "ledger": bstr,          ; ledger identifier: SHA-256("deus-aar/ledger/" ||
                           ;   principal-id || witness-kid), fixed at creation
  "seq": uint,             ; 0, 1, 2, ... no gaps; the first entry has seq 0 and prev null
  "prev": bstr / null,     ; SHA-256 of previous entry (full COSE bytes)
  "t": uint,               ; witness time, integer seconds
  "type": "MANDATE" / "CEILING" / "REVOCATION" / "RECEIPT" /
          "APPROVAL" / "CONSUME" / "RELEASE" / "REFUND" / "CHECKPOINT",
  "body": any,             ; principal-signed object or witness record
}
```

The ledger entry itself is a COSE_Sign1 with `typ`
`application/aar-ledger-entry+cbor` under the witness key.

**Shape of the entry.** The payload MUST match the `entry` CDDL above:
exactly these six members, no others. An entry whose `ledger`, `seq` or
`prev` is missing or of the wrong type is `CHAIN_BREAK` (Section 10
step 3). An entry whose `t` is missing or not a non-negative integer,
whose `type` is not one of the nine listed, whose `body` is missing, or
that carries a member not named in the CDDL is `MALFORMED` at that entry
(Section 10 step 4). `WITNESS_SIG` stays the code for the signature and
the encoding (not CDE, duplicate key, no tag 18). The
ledger identifier is `SHA-256("deus-aar/ledger/" || principal-id ||
witness-kid)` where `principal-id` is the UTF-8 `principal` string and
`witness-kid` the 32 raw bytes of the witness key's thumbprint
(Section 6.1); it is fixed at creation and every entry MUST carry it.

MANDATE, CEILING, REVOCATION and APPROVAL bodies embed the
principal-signed COSE object unchanged (body field `cose`), so a verifier
checks the principal signature directly under the pinned key. The
`typ` header and the signed payload are:

- MANDATE: `application/aar-mandate+cbor`, the `mandate` map of 6.1
  (body field `mandate` holds the same map);
- CEILING: `application/aar-ceiling+cbor`, the `ceiling` map of 6.3
  (body fields `id`, `amount`, `currency`, `window_s`);
- APPROVAL: `application/aar-approval+cbor`, the `approval` map of 6.6
  (body fields `receipt`, `approved`; mandate and action hashes are
  recomputed from the ledger);
- REVOCATION: `application/aar-revocation+cbor`, the map of 6.7
  (body field `mandate` = the mandate id; the hash is recomputed).

**Entry bodies.** The `body` of each entry type has the following
shape. Members not named are ignored by a verifier (they are covered by
the entry hash); a body that does not match its shape is `MALFORMED`
(a CEILING body: `CEILING_MALFORMED`; the `mandate` map of a MANDATE
body: `MANDATE_MALFORMED`), reported at the entry (Section 10 step 4).

```cddl
mandate-body   = { "mandate": mandate, ? "cose": bstr,
                   ? "pin": { "source": tstr, "principal": tstr },   ; Section 4.2
                   ? "signed_by": tstr / null }                       ; abstract mode only
ceiling-body   = { "id": tstr, "amount": uint, "currency": tstr, "window_s": uint,
                   ? "cose": bstr, ? "signed_by": tstr / null }
revocation-body = { "mandate": tstr, ? "cose": bstr, ? "signed_by": tstr / null }
receipt-body   = { "id": tstr, "mandate": tstr,              ; mandate id
                   "action": { * tstr => any },              ; request map as submitted
                   "verdict": "allow" / "defer" / "deny",
                   "reason": tstr,                           ; a code of Section 8.5
                   "ttl": uint,                              ; seconds
                   ? "audience": tstr }                      ; REQUIRED except for deny NO_MANDATE
approval-body  = { "receipt": tstr, "approved": bool, ? "cose": bstr,
                   ? "signed_by": tstr / null }
consume-body   = { "receipt": tstr }
release-body   = { "receipt": tstr, "cause": tstr }          ; Section 7.4
refund-body    = { ? "receipt": tstr, ? "amount": uint }     ; recorded, not interpreted
checkpoint-body = { "seq": uint, "head": bstr, "root": bstr } ; Section 9.1; seq < own seq
```

`cose` is optional in the shape on purpose: a missing `cose` is never a
shape error (`MALFORMED`, `CEILING_MALFORMED`) but a signature fault,
`MANDATE_KEY` in real mode (below). A CEILING body that is otherwise
complete and has no `cose` is therefore `MANDATE_KEY`. In the abstract
vectors `cose` is absent and `signed_by` names the symbolic signer. `ttl` (seconds), `reason` and, except for a logged
`deny NO_MANDATE`, `audience` are REQUIRED in a RECEIPT body; the
receipt expires at `t + ttl` where `t` is the entry's `t`. `id` is
unique within the ledger (the AAR `sub`); a witness MUST refuse a
second RECEIPT with the same `id` (`DUPLICATE_RECEIPT_ID`), and a verifier
answers `DUPLICATE_RECEIPT_ID` at the entry of a RECEIPT whose `id` equals
that of an earlier RECEIPT of the same ledger (Section 10 step 5). The
requirement is per ledger, not per witness: two ledgers of one witness
may contain the same `id` (Section 8.4 check 6). The verifier
compares `verdict` and `reason` of Section 10 step 5 with the
re-evaluated ones.

The verifier recomputes the payload from the plain body fields and the
ledger state and requires it to equal the signed payload; a body that
differs from what the principal signed is `MANDATE_KEY`. Symbolic
signer names are an abstract-mode device only. A MANDATE, CEILING,
REVOCATION or APPROVAL entry without `cose` is rejected with
`MANDATE_KEY` by a real-mode verifier. Abstract vectors (kinds
`decision`, `sequence`, `verification`) are abstract mode; every
byte-level vector is real mode, so a vector does not carry a mode flag.

**Where encoding failures are reported.** Section 5.1 applies to the
payload and the protected header of every COSE_Sign1 here. An entry of
the ledger that fails it (not CDE, duplicate key, no tag 18) is
`WITNESS_SIG` (Section 10 step 2). A principal object embedded as
`cose` that fails it, or whose signature does not verify under the
pinned key, is `MANDATE_KEY` in a verifier and `KEY_MISMATCH` when
presented to the witness (Section 8.5, stage table). The outer array and
the unprotected header must be well-formed CBOR but need not be CDE.

### 7.2 One logical ledger per principal

- There MUST be exactly one logical ledger per principal and witness
  service. All witness instances serving that principal MUST append to
  it with linearizable semantics (single writer, compare-and-swap on
  `seq`/`prev`, or an equivalent consensus).
- Ledger state (reservations, consumption, ceilings, revocations) MUST
  be derived from the ledger entries, not from process memory. On start,
  an instance MUST rebuild state from the ledger before evaluating any
  action.

These requirements close three attacks measured against an earlier
witness (adversary v1, Appendix A, S08-S10): restart, two instances,
and many mandates.

### 7.3 Committed amount

For a mandate M at witness time t:

```
committed(M, t) = sum of amounts of reservations for M created in
                  (t - budget_window_s, t] whose state is active or consumed
```

Only a `purchase` creates a reservation (Section 7.4); a `sale` or a
`refund` is logged in a RECEIPT but never counts toward `committed`.
A reservation whose AAR has expired is `active` until its RELEASE entry
is appended; the witness appends that entry before any other entry
(Section 7.4), so the difference is invisible in an honest ledger, and a
verifier reports a missing RELEASE before it re-evaluates anything
(Section 10 step 7(a)).

`committed(principal, t)` is the same sum across all mandates of the
principal, using the ceiling's window. A REFUND entry records money
returned but MUST NOT reduce committed amounts (a refund is not new
authority). Sessions do not exist at the ledger level: a new agent
session MUST NOT reset any sum.

### 7.4 Reservation life cycle

- **Reserve.** A `purchase` with verdict `allow` or `defer` creates a
  reservation for its full amount in the same ledger append as the
  RECEIPT entry. A `sale` or a `refund` (also monetary, Section 5.6)
  creates NO reservation, whatever its verdict, and does not use the
  budget or the ceiling: the amount of a sale is income, not spending,
  and a refund request is not new authority (Section 7.3). The verdict and the reservation are atomic with respect
  to other appends for the principal.
- **Consume.** When a tool accepts an AAR (Section 8.4) the witness
  appends CONSUME. A tool MUST NOT execute if the reservation is not
  active.
- **Release.** A reservation is released only by (a) a tool-signed
  statement that the action was not executed, (b) expiry of the AAR
  before any tool accepted it, (c) refusal or timeout of a deferral, or
  (d) revocation before presentation. A release appends RELEASE with
  the cause, which is exactly one of `tool_not_executed` (a),
  `expired` (b), `refused` (c: an APPROVAL with `approved: false`; a
  timeout is expiry and uses `expired`), `revoked` (d). A RELEASE with
  any other cause, for a reservation that is not active (already
  consumed or released), with `expired` before `expires`, with
  `revoked` without a preceding REVOCATION of its mandate, or with
  `refused` without a refusing APPROVAL, is `RELEASE_INVALID`. For (b) the witness MUST append `RELEASE` with cause
  `expired` at its first operation after `now > expires` and before any
  other entry. When several reservations have expired at that moment,
  it appends one such RELEASE for each of them, consecutively and in
  ascending order of the `seq` of their RECEIPT entries, before any
  other entry. A verifier MUST reject a ledger where an entry with
  `t > expires` follows an active reservation (`RELEASE_MISSING`)
  unless that entry is itself a RELEASE with cause `expired` (so the
  second of two consecutive expiry RELEASEs is legal while the first
  entry has already released only one reservation); a RELEASE with any
  other cause does not excuse the missing ones. A verifier does not check
  the order of consecutive expiry RELEASEs. A `RELEASE` with cause
  `expired` before expiry is `RELEASE_INVALID`.
- **Agent and operator statements MUST NOT release a reservation.** An
  agent reporting "not executed" is recorded and ignored (adversary v1
  `toctou_lozh`, vector S12).
- An AAR whose reservation was released MUST be rejected by tools
  (`RESERVATION_INACTIVE` or `RECEIPT_EXPIRED`), so releasing budget on
  expiry cannot cause double spending (vector S14).

### 7.5 What a third party can establish from the ledger

Replaying the ledger, a verifier can recompute every reservation,
consumption and release and confirm that, at the position of every
`allow`, `committed + amount` was within the mandate budget and the
ceiling. This does not require trusting the operator, any payment
network, or the witness's own statement of the totals. It does require
that the ledger is complete; see Sections 9 and 12.6.

---

## 8. Agent Action Receipt (SCITT Profile)

### 8.1 Envelope

An AAR is a SCITT Signed Statement: a COSE_Sign1 [RFC9052] with:

- protected `alg`: ES256 MUST be supported; EdDSA SHOULD be supported;
  an ES256 signature MUST be low-S (see below);
- protected `kid`: witness key identifier (RFC 9679 thumbprint, 6.1);
- protected `typ` [RFC9596]: `application/aar-receipt+cbor`;
- protected CWT Claims [RFC9597]: `iss` = witness identifier,
  `sub` = action identifier, `iat` = witness time;
- unprotected: zero or more COSE Receipts of inclusion from a TS
  [I-D.ietf-cose-merkle-tree-proofs] once registered;
- payload: the `aar` map below, attached.

The COSE_Sign1 MUST be tagged 18 and obey Section 5.1.

**ES256 and signature malleability.** For any ECDSA signature `(r, s)`
the pair `(r, n - s)` is also valid for the same message. This profile
chooses to KEEP ES256 (a principal device's secure element typically
offers nothing else) and to make signatures canonical: a signer MUST
emit `s <= n/2` (low-S) and a verifier MUST reject (`SIGNATURE_INVALID`)
an ES256 signature with `s > n/2`. Reason: entry hashes (7.1, 9.1)
are taken over COSE bytes, and a malleable signature would give one
statement two valid byte strings, two entry hashes and two chain
histories. Banning ES256 would break the most common key store; low-S
costs one comparison. Independently of this, replay detection never
uses signature or COSE bytes as its key (8.4 check 6).

### 8.2 Payload

```cddl
aar = {
  "spec": "deus-aar/0.1",
  "independence": "separate-party" / "tee" / "principal-hosted" / "none",
  "operator": tstr,
  "audience": tstr,                     ; the tool that may execute it
  "action": {
    "class": tstr, "agent": tstr,
    "recipient": tstr,                  ; canonical form (Sec. 5.4)
    "data": [* tstr],
    "amount": uint, "currency": tstr,
    ? "principal_present": bool,
    "params_hash": bstr,                ; SHA-256 over the CDE of {"data": action.data (absent = []), "amount": action.amount (absent = 0)}
    "binding_request_hash": bstr,       ; canonical request bytes, as in Permit
  },
  "mandate": {
    "ref": hash-ref,                    ; hash of the principal-signed mandate
    "principal_kid": bstr,
    "key_attestation": tstr,
    ? "approved_by": hash-ref,          ; APPROVAL entry, if deferred then approved
  },
  "budget": {                           ; present only for a purchase with allow or defer
    "reservation_id": bstr,
    "reserved": uint,
    "committed_before": uint, "limit": uint / null,
    "principal_committed_before": uint, "ceiling": uint / null,
    "window_s": uint,
  },
  "verdict": { "decision": "allow" / "defer" / "deny",
               "reason": tstr, "risk": tstr },
  "expires": uint,                      ; witness time = entry t + ttl (7.1)
  "chain": { "ledger": bstr, "seq": uint, "entry": bstr },   ; all REQUIRED
  ? "permit_ref": hash-ref,
}
```

`chain` names the RECEIPT entry that records this decision: `ledger` is
the ledger identifier, `seq` the entry's sequence number and `entry` the
entry hash (SHA-256 of the COSE_Sign1 bytes of that RECEIPT entry,
Section 5.7). (In -00 this member was called `prev`, which clashed with
the `prev` of Section 7.1 that points at the entry BEFORE.) `action.currency`
is the mandate's currency; the CWT `sub` is the RECEIPT `id`; the CWT
`iss` is `witness:` followed by the lower-case hex of the witness `kid`
(a string identifying the witness; tools compare it byte-exact). After
an approval the witness issues a second AAR for the same `sub` as
described in Section 6.6.

`deny` receipts MUST be produced and logged as well: a log of refusals
is part of the evidence (a verifier can see that harm was attempted and
stopped). A refusal for an unknown mandate (`NO_MANDATE`) is logged as a
RECEIPT entry with verdict `deny`; no AAR is signed for it because there
is no mandate to reference. Section 10 step 5 accepts exactly this case
for an unknown mandate. (Open: unauthenticated callers can grow the log
with such entries; rate limiting is an operator concern.)

### 8.3 Registration

The witness SHOULD register every AAR with at least one TS using SCRAPI
[I-D.ietf-scitt-scrapi] and attach the resulting COSE Receipt. The TS
MAY be operated by the witness; in that case the anchoring in Section 9
is REQUIRED.

### 8.4 Tool acceptance rules

A tool MUST execute an action only if all of the following hold, and
MUST reject otherwise with the given reason. The checks are evaluated in
this order and the first failure is reported:

1. an AAR is presented (`NO_RECEIPT`);
2. the AAR is a well-formed COSE_Sign1 (Section 5.1: `MALFORMED`), its
   `typ` is `application/aar-receipt+cbor` (`TYP_MISMATCH`), its `alg`
   is checked in this order: the key is selected by `kid`, which MUST
   equal the thumbprint of a key in the witness key set pinned by the
   tool (`KID_UNKNOWN`); then `alg` MUST be supported and equal the
   algorithm of THAT key (`ALG_MISMATCH`); then the signature verifies
   (`SIGNATURE_INVALID`; this includes a high-S ES256 signature); then
   its `independence` is not `none` (`WITNESS_NOT_INDEPENDENT`). An AAR
   with an unknown `kid` is therefore `KID_UNKNOWN` whatever its `alg`;
3. `verdict.decision` is `allow` (`NOT_ALLOWED`);
4. `audience` identifies this tool (`AUDIENCE`);
5. the hash of the canonical request the tool is about to execute
   (Section 5.7) equals `binding_request_hash` (`REQUEST_MISMATCH`);
6. this AAR has not been accepted before (`REPLAY`). The identity of an
   AAR for this purpose is the triple (`iss`, `chain.ledger`, `sub`):
   the CWT claims `iss` and `sub` and the ledger identifier of the
   `chain` member of the (signature-checked) payload. Tools MUST NOT
   use the COSE_Sign1 bytes, the signature or a hash of them as the
   replay key. Reason: `sub` is unique within one ledger (7.1), not
   across the ledgers of one witness (one ledger per principal), and the
   ledger identifier already contains the principal and the witness
   key; a rule of global uniqueness of `sub` would need a cross-ledger
   index that a sharded witness does not have. The approved AAR of
   Section 6.6 has the same identity as the deferral AAR, which is
   `NOT_ALLOWED` and never accepted, so it is accepted once;
7. witness time is not after `expires` (`RECEIPT_EXPIRED`);
8. the AAR comes with an inclusion proof: the RECEIPT entry (its entry
   hash equals `chain.entry`, its `seq` equals `chain.seq`, its `ledger`
   equals `chain.ledger`, its `id` equals the CWT `sub`, its request
   hashes to `binding_request_hash`, and its `verdict` is `allow`) and a
   Merkle path from that entry
   hash to the `root` of a witness-signed checkpoint covering it
   (Section 9.1) (`NO_INCLUSION` if absent, `INCLUSION_INVALID`
   otherwise, including a proof that names another entry than this
   AAR or a checkpoint whose `seq` is below the entry). The checkpoint
   is any signed checkpoint of Section 9.1.1; the tool does not wait for
   the hourly one. For an approved AAR (`approved_by` present, Section
   6.6) the RECEIPT entry records `defer`, and the proof MUST also carry
   the APPROVAL entry (its entry hash equals `approved_by.digest`, its
   `receipt` equals the `sub`, `approved` is true, it follows the
   RECEIPT) with a path to the same checkpoint (`NO_INCLUSION` if
   absent). The ledger entry is the record and the AAR is only a
   statement about it: the entry MUST record the decision that lets the
   tool execute, which is `allow`, or `defer` followed by the approving
   APPROVAL entry. A RECEIPT entry that records `deny`, or `defer` for an
   AAR without `approved_by`, or an APPROVAL entry with `approved` false,
   is `INCLUSION_INVALID` whatever the AAR says (Section 12.12). Tools
   MUST apply this check to every AAR. It closes
   receipts issued outside the ledger (V11);
9. for a `purchase`, the reservation is active
   (`RESERVATION_INACTIVE`); other actions have no reservation. A tool without a copy of the ledger cannot
   evaluate this; the check is made by the witness when the tool
   presents the AAR for consumption and the witness appends CONSUME.
   A stateless tool therefore applies checks 1-8 and reports
   acceptance as provisional until the witness has appended CONSUME.

Checks 6-9 and the transition to consumed MUST be atomic. Tools SHOULD
return a signed acceptance or non-execution statement; see Section 15
on making this REQUIRED.

### 8.5 Reason codes (registry, initial contents)

Reason codes are fixed upper-case ASCII strings. Implementations MUST
use exactly these strings; a code is a protocol value, not a log
message. The "where" column names the section that produces it.

| code | kind | where |
|---|---|---|
| `OK`, `OK_UNSPECIFIED`, `OK_CIRCLE`, `OK_APPROVED` | allow | 6.4, 6.6 |
| `ESCALATE_MONEY`, `ESCALATE_FILE`, `ESCALATE_DATA`, `ESCALATE_DELETE`, `ESCALATE_PUBLISH` | defer | 6.4 |
| `NO_MANDATE`, `MANDATE_SIG`, `AGENT_MISMATCH`, `EXPIRED`, `CLASS_UNKNOWN`, `CLASS_DENIED`, `BAD_AMOUNT`, `DATA_FORBIDDEN`, `DATA_NOT_PERMITTED`, `UNATTENDED_MEETING`, `RECIPIENT`, `PRICE`, `PER_ACTION_LIMIT`, `BUDGET`, `CEILING` | deny | 6.4 |
| `RESOURCE`, `IRREVERSIBLE_DELETE` | deny (delete, publish) | 6.4 step 10 |
| `KEY_NOT_PINNED`, `KEY_MISMATCH`, `NO_SIGNATURE`, `MANDATE_EXISTS`, `MANDATE_MALFORMED`, `CEILING_MALFORMED`, `MANDATE_UNKNOWN`, `APPROVAL_SIG`, `NOT_DEFERRED`, `DUPLICATE_RECEIPT_ID`, `MANDATE_SIG` (at registration) | witness input rejection | 4.2, 6.1, 6.3, 6.6 |
| `NO_RECEIPT`, `MALFORMED`, `TYP_MISMATCH`, `ALG_MISMATCH`, `KID_UNKNOWN`, `SIGNATURE_INVALID`, `WITNESS_NOT_INDEPENDENT`, `NOT_ALLOWED`, `AUDIENCE`, `REQUEST_MISMATCH`, `REPLAY`, `RECEIPT_EXPIRED`, `NO_INCLUSION`, `INCLUSION_INVALID`, `RESERVATION_INACTIVE` | tool rejection | 5.1, 8.4 |
| `MALFORMED` (entry body), `CEILING_MALFORMED`, `MANDATE_MALFORMED`, `WITNESS_SIG`, `CHAIN_BREAK`, `MANDATE_KEY`, `DUPLICATE_RECEIPT_ID`, `VERDICT_NOT_REPRODUCIBLE`, `CONSUME_INVALID`, `RELEASE_MISSING`, `RELEASE_INVALID`, `CHECKPOINT_SIG`, `CHECKPOINT_HEAD`, `CHECKPOINT_ROOT`, `ANCHOR_MISMATCH`, `OFFLOG_RECEIPT` | verifier result | 10 |

`WITNESS_SIG` is the verifier's code for a bad entry signature or
encoding (Section 10 step 2); a tool uses the finer codes of 8.4 check 2.

**Stage table.** The same fault has a different code at each stage that
sees it; a vector names its stage by its `kind`.

| fault | witness, on registration | witness, decision function (6.4 step 2) | verifier of a ledger (10 step 4) | tool (8.4 check 2) |
|---|---|---|---|---|
| principal object signed by another key, or its signature/encoding invalid | `KEY_MISMATCH` (`KEY_NOT_PINNED` if the principal is not pinned) | n/a | `MANDATE_KEY` | n/a |
| principal object verifies but its payload differs from the body / ledger | `MANDATE_SIG` | `MANDATE_SIG` (abstract flag) | `MANDATE_KEY` | n/a |
| mandate or ceiling does not match its CDDL | `MANDATE_MALFORMED` / `CEILING_MALFORMED` | n/a | same | n/a |
| AAR signed by an unknown or wrong key | n/a | n/a | n/a | `KID_UNKNOWN` / `ALG_MISMATCH` / `SIGNATURE_INVALID` |
| ledger entry signature or encoding invalid | n/a | n/a | `WITNESS_SIG` | n/a |
| entry payload does not match the `entry` CDDL (7.1) | n/a | n/a | `CHAIN_BREAK` (`ledger`, `seq`, `prev`) / `MALFORMED` (the rest) | n/a |
| second RECEIPT with an id already in the ledger | `DUPLICATE_RECEIPT_ID` | n/a | `DUPLICATE_RECEIPT_ID` | n/a |
| APPROVAL of a receipt that is not an undecided, unexpired `defer` | `NOT_DEFERRED` | n/a | `MANDATE_KEY` | n/a |
| MANDATE or CEILING with another principal or currency than the ledger's (6.1) | `MANDATE_MALFORMED` / `CEILING_MALFORMED` | n/a | same | n/a |
| RECEIPT entry presented as the record of an AAR it does not support (records `deny`, or `defer` without approval) | n/a | n/a | `OFFLOG_RECEIPT` (10 step 9) | `INCLUSION_INVALID` (8.4 check 8) |

`MANDATE_SIG` appears twice in the registry on purpose: it is a `deny`
of the decision function (Section 6.4 step 2) and a witness input
rejection at registration (stage table). Release causes
(`tool_not_executed`, `expired`, `refused`, `revoked`) are values, not
reason codes. Abstract-harness-only strings (`ok`, `ignored`, `clamped`,
`released`) are not protocol values.

---

## 9. Anchoring

### 9.1 Checkpoints

At least once per hour, and at least once per 10 000 entries, the
witness MUST append a CHECKPOINT entry and publish a signed checkpoint
(an anchor checkpoint; further, on-demand checkpoints are defined in
Section 9.1.1):

```cddl
checkpoint = { "ledger": bstr, "seq": uint, "head": bstr,
               "t": uint, "root": bstr, ? "ts_tree_head": bstr }
```

The checkpoint is a COSE_Sign1 under the witness key
(`typ` `application/aar-checkpoint+cbor`). `root` is the Merkle root over the entry hashes 0..`seq` as defined
by [RFC9162] Section 2.1: the tree has `seq + 1` leaves; the leaf for
entry `i` is `SHA-256(0x00 || entry_hash_i)` (entry hash = 32 bytes,
Section 5.7) and interior nodes are `SHA-256(0x01 || left || right)`,
split at the largest power of two smaller than the size.
An inclusion path for entry `i` is a list of `[side, hash]` pairs, leaf
to root, where `side` is `"L"` or `"R"` and names the position of the
sibling relative to the node being combined. Each `hash` is the RFC
9162 **node hash** of the sibling subtree: for a sibling that is a
single leaf it is `SHA-256(0x00 || entry_hash)`, the leaf hash, NOT the
entry hash itself; for a larger subtree it is the Merkle root of that
subtree. A verifier derives the
sides from `i` and the tree size (RFC 9162 Section 2.1.3) and MUST
reject (`INCLUSION_INVALID`) a path whose labels differ from the
derived ones, whose hashes do not combine to `root`, or whose
checkpoint has a `seq` below `i` or an invalid signature. A proof that
does verify but belongs to another entry than the presented receipt
(its `id`, `ledger`, `seq`, entry hash or request differ from the
presented AAR) is `INCLUSION_INVALID` at a tool (8.4 check 8) and
`OFFLOG_RECEIPT` at a third-party verifier (Section 10 step 9). A verifier checks the
signature (`CHECKPOINT_SIG`), `head` (`CHECKPOINT_HEAD`) and `root`
(`CHECKPOINT_ROOT`) against the ledger. A checkpoint does not cover
entries after `seq`: rewriting only the tail after the latest
checkpoint is detected by the next checkpoint, not by this one.

The body of a CHECKPOINT ledger entry is `{ "seq", "head", "root" }`
(Section 7.1; all REQUIRED, `seq` less than the entry's own `seq`), the
same values as the published checkpoint. A verifier checks every
CHECKPOINT entry like a published checkpoint (Section 10 step 8); a
body without `root` is `MALFORMED`.

`head` is the hash of the entry at `seq`. If the witness serves many
principals it SHOULD aggregate their heads into a Merkle tree and anchor
the root, publishing per-ledger inclusion paths.

### 9.1.1 Anchor checkpoints and inclusion checkpoints

Two obligations meet here and are kept apart.

- **Anchor checkpoint.** The "at least once per hour, and at least once
  per 10 000 entries" rule above, and the anchoring of Section 9.2,
  apply to the checkpoints the witness publishes on that schedule.
- **Inclusion checkpoint.** A tool needs, for every AAR it executes, a
  proof of inclusion into a signed checkpoint (Section 8.4 check 8). The
  witness MUST be able to supply, at the time a tool presents an
  unexpired AAR (and at the latest by its `expires`), a signed
  checkpoint whose `seq` is at least the `seq` of its RECEIPT entry,
  with the path. It does so ON DEMAND: it appends a CHECKPOINT entry and
  signs it (one signature), unless an already signed checkpoint covers
  the entry. A signed checkpoint covers every entry up to its `seq`, so
  a batch of receipts may share one checkpoint, and a witness MAY
  serve a checkpoint it signed earlier (for example in the last few
  seconds) to many tools; there is no minimum or maximum batch size. The
  AAR itself carries no proof and is never withheld until a checkpoint
  exists; execution waits for the proof, which costs one signature, not
  the hour.

A witness SHOULD append every checkpoint it signs as a CHECKPOINT ledger
entry (it does so for the checkpoints of this section), and a verifier
checks every CHECKPOINT entry (Section 10 step 8). A verifier does NOT
require that the checkpoint named in a proof is a CHECKPOINT entry: it
checks that checkpoint against the audited ledger itself (Section 10
step 9: signature, `ledger`, and `root` equal to the Merkle root of the
entries 0..`seq` of the audited ledger). A signed checkpoint that was
never appended is therefore not invalid, and it gives no evidence beyond
that check. Only the scheduled checkpoints must be anchored; an
inclusion checkpoint is anchored implicitly, because the ledger entries
it covers are covered by the next anchored checkpoint's `root`. The
trade-off is explicit: an inclusion checkpoint proves inclusion in the
witness's own signed history; its time (not later than) comes from the
next anchor (Section 9.4). Anchoring every checkpoint is permitted but
not required.

### 9.2 Primary anchor: OpenTimestamps

The witness MUST submit the SHA-256 of the checkpoint COSE_Sign1 bytes
as published (or of the aggregated root) to at least two OpenTimestamps calendar servers
[OTS] and MUST store and publish the resulting proof in the standard
`.ots` serialisation. The witness SHOULD later upgrade the proof to one
that contains a Bitcoin block attestation and SHOULD publish the
upgraded `.ots`. A witness MAY run its own calendar from the open-source
calendar server; a self-run calendar does not count as one of the two
required calendars unless it is operated by a party other than the
witness.

A verifier checks an anchor by verifying the `.ots` proof against the
checkpoint hash and, for a complete proof, against a Bitcoin block
header obtained independently. Outcomes: `bitcoin` (complete),
`pending` (calendar commitments only), `invalid` (the proof commits to
a different digest: `ANCHOR_MISMATCH`).

### 9.3 Optional second anchor

A witness MAY add a second, independent anchor of the same checkpoint
hash, for example an RFC 3161 timestamp [RFC3161] from a TSA not
controlled by the witness or operator, or a transaction carrying the
32-byte hash on a public chain. A second anchor MUST NOT be required
for conformance, MUST NOT introduce a token, and MUST NOT be the only
place where any receipt is stored.

### 9.4 What anchoring proves and does not prove

An anchor proves that a checkpoint existed no later than the anchor
time. Combined with the hash chain it makes rewriting, truncating or
forking the ledger *before* that checkpoint detectable: two different
heads for the same `seq` cannot both be consistent with anchored
checkpoints. It does not prove that entries were appended at their
stated times, does not prove completeness (an entry never appended is
invisible), and gives no protection for entries after the last
anchored checkpoint.

---

## 10. Third-Party Verification

Given the ledger, the witness key set, the operator key set, the
witness's independence statement, the pinned principal key, and the
checkpoints with their anchors, a verifier MUST first apply step 1,
then process the entries **in ledger order** and, for each entry, apply
steps 2-7 in numerical order, with ONE exception: the first part of
step 7 (7(a), the missing RELEASE) is evaluated for each entry directly
after step 3 and before step 4. The result is the FIRST failure found,
reported with `at` = the `seq` of the failing entry. Steps 8-10 are
whole-ledger checks made after all entries (no `at`).

1. Reject if the witness key is in the operator key set
   (`WITNESS_NOT_INDEPENDENT`) or the independence statement is `none`.
2. Verify the entry's witness signature and encoding (`WITNESS_SIG`).
3. Verify the chain: the first entry has `seq` 0 and `prev` null; every
   later `seq` is the previous plus one and `prev` equals the hash of
   the previous entry; the entry's `ledger` equals the ledger
   identifier of Section 7.1 (`CHAIN_BREAK`).
4. Check the entry payload against the `entry` CDDL (`MALFORMED`,
   Section 7.1 "Shape of the entry") and the entry body against its
   shape in Section 7.1 (`MALFORMED`; for a CEILING body
   `CEILING_MALFORMED`; a missing `cose` is not a shape error); for a
   MANDATE entry check the mandate against the CDDL of 6.1
   (`MANDATE_MALFORMED`); for a MANDATE and a CEILING check the principal
   and the currency against the ledger (Section 6.1, consistency:
   `MANDATE_MALFORMED`, `CEILING_MALFORMED`); verify every MANDATE,
   CEILING, REVOCATION and APPROVAL body under the pinned principal key
   and against the payload recomputed from the ledger (`MANDATE_KEY`;
   this includes a missing `cose` and an encoding failure of the
   principal object, Section 7.1); an APPROVAL of a receipt that is not,
   at the entry's `t`, an undecided and unexpired `defer` RECEIPT earlier
   in the ledger is `MANDATE_KEY` (Section 6.6).
5. For a RECEIPT: its `id` is not the `id` of an earlier RECEIPT of the
   ledger (`DUPLICATE_RECEIPT_ID`); its mandate is
   present earlier in the ledger (`MANDATE_UNKNOWN`; the only exception
   is a logged `deny` with reason `NO_MANDATE`, Section 8.2) and the
   action **re-evaluated** with the algorithm of Section 6.4, at the
   entry's `t`, against the state reconstructed so far gives the signed
   verdict and reason (`VERDICT_NOT_REPRODUCIBLE`). This is what makes
   the witness's decision checkable rather than trusted.
6. For a CONSUME, check the corresponding receipt was `allow` (a
   `defer` receipt followed by an approving APPROVAL entry counts as
   `allow`, Section 6.6), unconsumed, unexpired, and its reservation
   active (`CONSUME_INVALID`).
7. Check the Section 7.4 rules for this entry. (a) An entry with `t`
   after the `expires` of a still-active reservation, unless the entry
   is itself a RELEASE with cause `expired` (`RELEASE_MISSING`); this
   part is evaluated first for each entry (see above), so an expired
   reservation that has not been released is reported before the
   re-evaluation of step 5 can disagree with it. (b) A RELEASE that
   breaks 7.4 (`RELEASE_INVALID`).
8. Check every checkpoint (every CHECKPOINT entry and every
   published one): signature, `head` and `root` against the ledger
   (`CHECKPOINT_SIG`, `CHECKPOINT_HEAD`, `CHECKPOINT_ROOT`) and its
   anchor (Section 9.2, `ANCHOR_MISMATCH`). The signature of a CHECKPOINT
   entry is the signature of the entry, already checked in step 2; a
   published checkpoint has its own signature. In abstract vectors a
   checkpoint without `seq` refers to the last entry, and the anchor
   digest is symbolic.
9. For every receipt that a tool reports as accepted, check that it is
   included in this ledger under a signed checkpoint and that the ledger
   RECORDS the decision that lets a tool execute. No proof (for an
   approved AAR: no proof of either entry, the RECEIPT or the APPROVAL):
   `NO_INCLUSION`. A proof that does not verify as a proof (signature,
   path, side labels, checkpoint `seq` below the entry):
   `INCLUSION_INVALID`. A proof that verifies but whose entry or
   checkpoint is not in the audited ledger (the checkpoint is checked
   against the audited ledger as Section 9.1.1 says; it need not be a
   CHECKPOINT entry), or whose entry is not this receipt (another `id`,
   entry hash, `ledger` or `seq`; for an approved AAR also the APPROVAL
   entry), or whose RECEIPT entry does not record `allow` (it records
   `deny`; or it records `defer` and no APPROVAL entry with `approved`
   true for it follows it under the same checkpoint, which is
   `NO_INCLUSION` when no approval proof was given and `OFFLOG_RECEIPT`
   when one was given and does not fit): `OFFLOG_RECEIPT`. The decision
   an AAR claims is not read from the AAR: an AAR whose `verdict` is not
   `allow` is never an accepted receipt (Section 12.12).
10. Optionally verify COSE Receipts of inclusion from the TS.

The result is `valid` with an anchor status (`bitcoin`, `pending`,
`none`) or `invalid` with the first failing reason and position.

---

## 11. Transport Binding (Informative)

For MCP [MCP], the witness acts as an MCP server in front of the real
tools. The mandate reference MAY be carried in the request `_meta`
field (`deus.aar/mandate`), and the AAR (or its hash and a retrieval
URI) in the response `_meta` (`deus.aar/receipt`). Because MCP
protocol-level logging is deprecated in favour of OpenTelemetry, AAR
hashes SHOULD also be emitted as span attributes. A formal MCP
extension proposal is future work and requires the owner's decision.

---

## 12. Security Considerations

### 12.1 Threat model

Trusted: the principal (honest about the mandate, but may express it
imperfectly), the principal's device key store, the witness within its
independence model, tools in applying Section 8.4, cryptographic
primitives, and the Bitcoin block-header history for anchors.
Untrusted: the agent (literal-minded, injected, greedy or forgetful),
the operator, the network, the host clock, and the agent's own
statements about execution.

### 12.2 Lying operator before signing

The documented weakness of an operator-signed permit is that a
privileged operator can change the inputs to the decision before the
decision is signed, and the verifier cannot tell. In this profile:

- the **authority** input is principal-signed; the operator cannot widen
  it (vectors V05, V06, S10);
- the **decision** is reproducible: a verifier recomputes it from signed
  inputs (Section 10 step 5), so a wrong decision is detectable even if
  the witness signed it (V04);
- the **signer** is not the operator (Section 4.3; V02);
- the **request bytes** are bound: a tool executes only the request
  whose hash the witness signed, so substitution after the decision is
  rejected (S18).

What remains: the operator still describes the action to the witness.
If the description is false in a way the witness cannot check (a data
class label, Section 12.8) or if the operator also controls the tool
and the tool ignores Section 8.4, the receipt will be correct about a
false description. The profile narrows the operator's lie to the action
description and makes it attributable; it does not eliminate it.

### 12.3 Budget splitting

Splitting one forbidden spend into permitted pieces is handled by the
cumulative ledger: the sum is over the mandate's window regardless of
session (S05), process restart (S08), witness instance (S09), number of
pieces (S01, S03), or mandates of the same principal (ceiling, S11).
Negative and fractional amounts are rejected (S04, D15, D16). Deferred
purchases hold their reservation, so splitting into deferrals does not
escape the budget. Residual risks: (a) a principal who issues several
mandates without a ceiling has granted their sum (Section 6.3); (b) a
sliding window still allows `budget` per window, so long-lived mandates
with short windows permit more total spend than a principal may expect;
(c) splitting across principals (e.g. household members) is out of
scope; (d) splitting across currencies is prevented only by rejecting
other currencies.

### 12.4 Replay

An AAR is bound to one action (`params_hash`, `binding_request_hash`),
one tool (`audience`), one acceptance (single use at the tool, identified by the CWT
`iss`, the ledger identifier and `sub` and not by signature bytes, 8.4 check 6), a deadline (`expires`) and, for money, one active reservation (S06, S17,
S14). An approval is bound to the receipt id, the mandate hash and the
action hash (6.6) and cannot be reused for another action or an
identical request. A mandate is bound to one agent
label and validity interval (D32, D33). Ledger entries are bound to the
ledger identifier, preventing transplanting entries between ledgers.
Not covered: replay of the *same* action through a tool that does not
implement Section 8.4.

### 12.5 Mandate substitution

Substituting a broader or older mandate is prevented by: the receipt
carrying the mandate hash; the verifier requiring that mandate to be in
the ledger before the receipt (V05); the principal key being pinned
from a source outside operator and witness control (Section 4.2, V06);
revocation being an ordered ledger event. Trust-on-first-use is
explicitly NOT conforming; a ledger whose first MANDATE was accepted
without a pinned key provides no assurance about who authorised it.
Downgrade of `key_attestation` (presenting a `software` mandate where a
`secure-element` one was expected) is a verifier policy decision and
MUST be visible because the field is signed.

### 12.6 Witness in collusion with the operator

A witness that colludes with the operator can:

- sign `allow` for an action outside the mandate or beyond budget -
  **detected** by recomputation (V04);
- sign a receipt for a false action description - **not detected** by
  this profile alone (Section 12.2);
- issue a receipt directly to a tool without appending it to the ledger,
  or append to a private fork - **not detected** by ledger replay alone
  (V11). As of deus-aar-0.1 revision 4.1 a tool refuses a receipt
  without an inclusion proof into a signed checkpoint (Section 8.4 check 8) and
  a verifier flags a presented receipt that is not in the audited ledger
  (`OFFLOG_RECEIPT`). A witness that signs a checkpoint for a private fork
  is still not detected by one ledger alone: that needs anchoring of
  checkpoints (both heads anchored) or tool-countersigned consumption;
- sign an `allow` AAR over an entry that records a refusal or a
  deferral that was never approved - **detected** since -03: the tool
  and the verifier require the entry to record the decision (Sections
  8.4 check 8, 10 step 9, 12.12);
- refuse service - fails closed (no AAR, no execution), which is a
  denial of service, not a bypass.

Mitigations: k-of-n witnesses from different legal entities, each
co-signing the RECEIPT entry; tool-countersigned CONSUME entries;
registration with a TS not run by the witness. None is REQUIRED in -00
(Section 15).

### 12.7 Clock

Witness time is monotonic (backwards steps clamped, S14), but a host
clock jumping forward can expire receipts and release unpresented
reservations early (harmless for overspend, harmful for availability),
and validity windows are only as accurate as the host clock. Secure
time sources (Roughtime, RFC 3161 tokens for each checkpoint) are
RECOMMENDED for deployments where validity windows matter to disputes.

### 12.8 Declared data classes

The witness evaluates declared data classes; it does not inspect
content. An agent or operator that labels a street address as `city`,
or puts it inside an opaque file, passes the protected-data rule. Files
are therefore deferred by default when unspecified. Content inspection
is out of scope; a deployment MAY place a classifier before the witness,
but the receipt then attests the classifier's output, not the content.

### 12.9 Bypass

The guarantees hold only for tools that hold no credentials except the
witness's and that implement Section 8.4. An agent with its own
credentials to a tool is invisible to this profile (MIR-W pair `obhod`
is closed only because the tool requires a receipt, S07).

### 12.10 Human approval quality

Deferral moves the decision to the principal, who may approve without
reading. The project's simulation assumes this for 97 % of approvals
(a simulation parameter, not measured on people),
which is why protected-data disclosure is denied rather than
deferred (Section 6.2). Approval prompts SHOULD show the context that
makes harm visible (price against market, recipient history).

### 12.11 What this profile does NOT guarantee

- that an allowed action was wise, or what the principal really wanted
  (only that it was within what the principal signed);
- that the mandate's wording matches the principal's intent;
- that the content of a message or file is what its labels say;
- that an allowed action was actually executed, or had the intended
  effect (unless a tool-signed outcome is added);
- completeness of the ledger, in particular for entries never appended,
  and anything after the last anchored checkpoint;
- the identity or integrity of the agent software;
- availability of the witness;
- security against compromise of the principal's device or key;
- confidentiality from the witness, which sees every action;
- that a timestamp anchor shows when an entry was created (it shows
  only "no later than");
- any legal effect.

### 12.12 AAR that disagrees with its ledger entry

Found by implementation C (`AMBIGUITY-C2-11`) in -02. The AAR is a
witness signature over a statement; the ledger entry is the record. -02
tied them together by entry hash, `seq`, `ledger`, `id` and request, but
not by decision. A witness in collusion with the operator could therefore
append `deny` for an action (or `defer` that the principal never
approved), sign an `allow` AAR for the same `sub`, `chain` and request,
and hand the AAR and the real inclusion proof to a tool. Checks 1-8
passed; a verifier of the ledger found the ledger valid, because it
re-evaluated the RECEIPT (a correct `deny`) and checked only that the
presented receipt is included. The signed refusal in the ledger and the
signed `allow` outside it both existed, and nothing compared them.

-03 requires the RECEIPT entry to record `allow`, or `defer` followed by
the approving APPROVAL entry (`approved` true), in the tool (Section 8.4
check 8: otherwise `INCLUSION_INVALID`) and in the verifier (Section 10
step 9: otherwise `OFFLOG_RECEIPT`, or `NO_INCLUSION` for a deferral
presented without an approval proof). The verifier does not need the AAR
to know which decision a tool relied on: a receipt reported as accepted
is by definition one that let the tool execute.

What this does not do. A witness that appends `allow` for something it
should have refused is caught by recomputation (Section 10 step 5), as
before. A witness that shows one ledger to the tool and another to the
auditor is still the fork problem of Section 12.6. A tool that reports
a refusal as accepted is itself colluding; the audit then fails with
`OFFLOG_RECEIPT` instead of passing silently.

---

## 13. Privacy Considerations

The ledger contains recipients, data classes and amounts. Publishing it
reveals the principal's contacts and spending. Ledgers SHOULD therefore
be disclosed to verifiers on demand rather than published; only
checkpoints and anchors need to be public. Recipients MAY be replaced in
published copies by salted commitments with the salt held by the
principal; selective disclosure in the style of
[I-D.mih-scitt-agent-action-capsule] is an Open Question. Anchoring
publishes only hashes. The witness necessarily sees all actions and is
a privacy-sensitive party; the independence statement SHOULD include a
data-retention policy.

---

## 14. IANA Considerations

None in -01. A future revision would request: media types
`application/aar-mandate+cbor`, `application/aar-receipt+cbor`,
`application/aar-checkpoint+cbor`, `application/aar-ledger-entry+cbor`,
`application/aar-ceiling+cbor`, `application/aar-approval+cbor`,
`application/aar-revocation+cbor`; a registry of action classes; a
registry of data classes; a registry of reason codes (its initial
contents are the table in Section 8.5); and integer CBOR labels.

---

## 15. Open Questions

1. **Integer labels and CDDL freeze.** Text keys are used for
   readability. Byte-level test vectors wait for this decision.
2. **Mandate encoding.** COSE_Sign1 (chosen for -00) versus W3C VC 2.0
   or SD-JWT, which would let a mandate share format and wallet with
   Verifiable Intent. Interop argues for SD-JWT; ledger replay and
   compactness argue for COSE.
3. **Default semantics of "unspecified".** The tri-state mandate
   language, of which "unspecified low-risk = allow" is one part,
   reduced false alarms from 15.3 to 3.6 per 100 honest actions in the
   project's L1 simulation (model principals and agents, not people),
   but it is a policy choice a
   standard may not want to fix. Alternative: make the risk table a
   signed field of the mandate.
4. **Deletion and publication.** Registered in -01 (Sections 5.6.1,
   6.4 step 10). Still open: retention periods for soft delete, a
   richer pattern language than a trailing `*`, and per-target
   reversibility rather than a flag in the request (which the requester
   asserts).
5. **Window versus lifetime budgets.** A sliding window is implemented;
   lifetime budgets (and both together) are probably needed.
6. **Tool-signed consumption.** Inclusion proofs (Section 8.4 check 8) close
   receipts issued off-log, but not a witness that serves a forked
   ledger. Making tool countersignatures REQUIRED would, but excludes
   tools that cannot sign.
7. **Multiple witnesses.** k-of-n co-signing format and how verifiers
   learn k.
8. **Key pinning sources.** Which out-of-band registries are acceptable
   in practice; how a principal rotates a device key without a TOFU gap.
9. **Composition with Permit.** Whether an AAR should be expressible as
   a Permit with an additional human-authority binding and ledger
   claims, rather than a sibling profile. Keel's planned extensions
   (lanes without monetary value, fact profiles for databases and CX)
   may make the sibling unnecessary; this is the main competitive
   uncertainty.
10. **Data-class registry.** Only four classes are registered; real
    deployments need a mapping to existing taxonomies.
11. **Named circle.** Kept as opt-in; evidence that it matches real
    intent is one simulated world, not people.
12. **Evidence level of this draft.** All behavioural numbers cited come
    from the project's simulations (L0 scripted, L1 model agents). No
    external deployment exists. No external review has taken place.
13. **Submission.** Whether and where to submit (IETF SCITT, MCP SEP)
    is a decision for the project owner and is not implied by this
    draft.
14. **One currency per ledger.** -01 compares the action currency with
    the mandate's currency but does not forbid mandates of different
    currencies in one ledger, where the ceiling would sum amounts of
    different units. A single-currency ledger rule (or a ceiling per
    currency) is open.
15. **Low-S versus a ban on ES256.** -01 keeps ES256 and requires
    low-S. Ed25519-only profiles would remove the question; the choice
    depends on which principal key stores matter in practice.
16. **Reversibility is requester-asserted.** `reversible` and
    `principal_present` are claims in the request, like data classes
    (Section 12.8); the witness cannot check them.
17. **Dated requester `t`.** `t` stays inside the request bytes so that
    tools can rebuild the exact request; a profile without a
    requester timestamp would drop it.
18. **Sale and refund flows.** -02 reserves only purchases (Section
    7.4). A cap on cumulative sales or refunds, and the relation of a
    refund to the purchase it reverses, are open.
19. **Inclusion checkpoint cadence.** -02 makes inclusion checkpoints
    on demand with unbounded batching (Section 9.1.1). A maximum
    interval between a RECEIPT and a covering checkpoint, and anchoring
    of every checkpoint, are policy choices a standard may fix.

---

## 16. References

### 16.1 Normative

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
  Requirement Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
  Key Words", BCP 14, RFC 8174.
- [RFC8949] Bormann, C., Hoffman, P., "Concise Binary Object
  Representation (CBOR)", STD 94, RFC 8949.
- [RFC9052] Schaad, J., "CBOR Object Signing and Encryption (COSE):
  Structures and Process", STD 96, RFC 9052.
- [RFC9596] "CBOR Object Signing and Encryption (COSE) "typ" (type)
  Header Parameter", RFC 9596.
- [RFC9597] "CBOR Web Token (CWT) Claims in COSE Headers", RFC 9597.
- [RFC9679] "CBOR Object Signing and Encryption (COSE) Key Thumbprint",
  RFC 9679.
- [RFC9162] Laurie, B., et al., "Certificate Transparency Version 2.0",
  RFC 9162 (Merkle tree hashing and inclusion paths, Section 2.1).
- [RFC9943] "An Architecture for Trustworthy and Transparent Digital
  Supply Chains" (SCITT), RFC 9943, June 2026.
- [I-D.ietf-cose-merkle-tree-proofs] "COSE Receipts", work in progress.
- [I-D.ietf-scitt-scrapi] "SCITT Reference APIs", work in progress.
- [OTS] OpenTimestamps, https://opentimestamps.org/ (proof format and
  calendar protocol as implemented by the reference client and server).

### 16.2 Informative

- [I-D.munoz-scitt-permit-profile] Munoz, C., "SCITT Permit Profile",
  draft-munoz-scitt-permit-profile-01, July 2026.
- [KEEL-PERMIT] Keel API, keel-permit (Apache-2.0),
  https://github.com/keelapi/keel-permit (README v1.24.0 and /spec, read
  2026-10-17).
- [KEEL-VERIFIER] Keel API, keel-verifier (MIT),
  https://github.com/keelapi/keel-verifier (read 2026-10-17).
- [VI] Mastercard, "Verifiable Intent" v0.1,
  https://github.com/agent-intent/verifiable-intent (spec/constraints.md,
  credential-format.md, security-model.md).
- [AP2] Agent Payments Protocol,
  https://github.com/google-agentic-commerce/AP2.
- [I-D.noa-scitt-ai-agent-receipt] draft-noa-scitt-ai-agent-receipt-01,
  August 2026.
- [I-D.mih-scitt-agent-action-capsule]
  draft-mih-scitt-agent-action-capsule-05, September 2026.
- [I-D.emirdag-scitt-ai-agent-execution]
  draft-emirdag-scitt-ai-agent-execution-01, October 2026.
- [I-D.sharif-agent-audit-trail] draft-sharif-agent-audit-trail-08,
  October 2026.
- [I-D.veridom-omp] draft-veridom-omp-02.
- [MCP] Model Context Protocol specification, 2025-11-25 and 2026-07-28.
- [WebAuthn] W3C, "Web Authentication: An API for accessing Public Key
  Credentials".
- [VC2] W3C, "Verifiable Credentials Data Model v2.0", May 2025.
- [RFC3161] Adams, C., et al., "Internet X.509 Public Key
  Infrastructure Time-Stamp Protocol (TSP)", RFC 3161.
- [RFC9334] Birkholz, H., et al., "Remote ATtestation procedureS (RATS)
  Architecture", RFC 9334.
- [SELLO] Figuera, J., "Sello", arXiv:2606.04193, June 2026 (receipts
  signed by the callee; an alternative answer to the same
  self-reporting problem).

---

## Appendix A. Test Vectors and Conformance

Vectors are in `vectors/`, one JSON file per vector, indexed by
`vectors/index.json`. They are **abstract (semantic) vectors**:
signatures and hashes are symbolic, and signature validity is an input
flag. They test Sections 5-10 logic. Byte-level COSE vectors (`vectors/cose/`) are produced by the
reference implementation and use real COSE_Sign1 with RFC 9679 `kid`.

Three kinds:

- `decision` (D01-D65): mandate, action and ledger state -> verdict and
  reason (Section 6.4);
- `sequence` (S01-S22): a sequence of ledger operations (register,
  authorize, tool presentation, reports, clock, restart, approval,
  revocation) -> the result of each step (Sections 6.6, 6.7, 7, 8.4);
- `verification` (V01-V22): a ledger and checkpoint -> verifier result
  (Sections 9, 10).

Harness conventions for the abstract vectors (not protocol): (1) in a
`sequence` vector `action.t` means "the witness clock reads at least
`t` before this step" (a `clock` op can only move time forward; a step
that would move it back is `clamped`); (2) every authorize op states
`ttl`; (3) every mandate carries `v` and `currency`, every monetary
action `currency`; (4) a vector reader MUST distinguish `100` from
`100.0` (Section 5.2); (5) `null` for a permission means absent; (6) a `register_ceiling` op
carries `id`, `amount`, `currency` and `window_s` (and the harness
members `signed_by`, `instance`); `v` and `principal` are implied (those
of the ledger) and any other member of the op is a member of the ceiling
map that the CDDL of Section 6.3 does not name (`CEILING_MALFORMED`);
(7) a `tool_report` that appends nothing (no active reservation to
release) has the result `ignored`, one that appends a RELEASE has the
result `released`, and `ok` is the result of `restart` and `clock` only;
(8) in a `sequence` vector the refusal of an input by the witness is the
step result `{"result": "reject", "reason": CODE}` for every op,
including `authorize` (`DUPLICATE_RECEIPT_ID`); (9) in the abstract
vectors hashes are symbolic, and every field the CDDL types `bstr`
(`head`, `root`, `prev`, `digest`) may be a string; a reader MUST accept
a string there and MUST NOT report `MALFORMED` for it (V29 and V30 depend
on this); (10) an item of `presented` in a `verification` vector is
`{"id", "inclusion": {"seq"}}`, plus `"approval": {"seq"}` for a receipt
whose RECEIPT entry records `defer` (the entry of the approving
APPROVAL).

`class` is `valid` for honest traces (a conforming implementation MUST
allow, accept or validate) and `invalid` for attacks and malformed
inputs (it MUST deny, defer, reject or invalidate). V11 was a
known-limitation vector in -00 (expected `valid`); in revision 4.1 it
is `invalid` (`NO_INCLUSION`): a receipt presented without an inclusion
path is refused. V12-V18 (4.1) cover wrong inclusion, missing/valid
RELEASE, logged refusal for an unknown mandate, truncation and rewriting
after a checkpoint. Byte-level ledger-file vectors are `cose/C15-C25`.

Sources: the six red/green pairs of the project's simulated world
MIR-W (robb, inzhekciya, limit, bukvalist, droblenie, obhod); the seven
attacks of adversary v0 (toctou, otric_summa, novaya_sessiya, replay,
dvoynik_poluchatelya, dannye_v_tele, obhod); the six attacks of
adversary v1 (perezapusk, dva_shlyuza, mnogo_mandatov, toctou_lozh,
chasy_otkat, obhod); and the mandate-language rules of witness v3.

Counts (-00): 72 vectors, 19 valid, 53 invalid (decision 13/30,
sequence 3/15, verification 3/8).
Counts (revision 4.1): 90 vectors, 24 valid, 66 invalid (decision 16/38, sequence 3/15, verification 5/13); plus 25 byte-level COSE/ledger vectors.
Byte-level tool vectors (`cose-tool`) may carry `presentations`, a list
of presentations to ONE tool in order (the replay store is kept between
them); each element may override `cose_hex`, `request`, `now` and
`proof`, and takes the vector's value for what it omits. Byte-level
ledger vectors (`cose-ledger`) may carry `presented`, the AARs that
tools reported as accepted, each with its proof (with an optional
`approval` proof for an approved AAR). A reader that ignores the
per-element `proof` cannot run vectors that need two proofs.

Counts (-03, revision 4.4): see `vectors/index.json` (`total`, `counts`;
`changes_in_03` lists the additions). Revision 4.4 adds the abstract
vectors D82, S31-S36, V31-V41 and the byte vectors C61-C71; no vector of
-02 changed its bytes or its expectation. The C2-11 vectors are V36-V39
(abstract) and C61-C65 (byte-level).

Counts (-02, revision 4.3): see `vectors/index.json` (`total`, `counts`;
`changes_in_02` lists, per vector, what changed against -01). Revision
4.3 adds the abstract vectors D66-D81, S23-S30, V23-V30 and the byte
vectors C42-C60, rewrites S11 and S21 (complete ceiling map), gives
every verification entry a `t`, a `reason` and (except `deny
NO_MANDATE`) an `audience`, and removes the `require_cose` member of
the byte-level ledger vectors.

Counts (-01, revision 4.2): 109 abstract vectors, 26 valid, 83 invalid (decision 17/48, sequence 4/18, verification 5/17); plus 41 byte-level
vectors `cose/C01-C41` (10 valid, 31 invalid). `vectors/index.json` has a
`changes_in_01` member that lists, per vector, what changed against 4.1.

`vectors/check_vectors.py` is an executable reading of Sections 5-10 as
of -00/4.1; it is frozen, skips the vectors that exist only because of
-01, and is kept as the ancestor model. The two live implementations are
A (`aar_ref`, Python) and B (`verifier_js`, JavaScript, written from
-00 without reading A). It is not the reference implementation.

## Appendix B. Mapping to the Reference Implementation

The reference implementation is the project's witness v3
(`svidetel/mandat.py`, `svidetel/shluz.py`). Names map as follows:
`soobshchenie`=message, `fayl`=file, `raskrytie`=disclosure,
`pokupka`=purchase (`prodazha`=sale), `vstrecha`=meeting,
`vozvrat`=refund; `propustit/zaderzhat/zapretit`=allow/defer/deny;
`potolok`=ceiling; `odobrenie`=approval.

All 43 decision vectors were also run through `mandat.reshit` of
witness v3: 42 agree in verdict and reason. One divergence is
intentional: D38. Witness v3 applies the named-circle rule (KRUG)
unconditionally; this draft requires an explicit, principal-signed
opt-in (Section 6.5), because the only evidence for the rule is one
simulated world.

Revision 4.4 (`aar_ref`) implements -03: the RECEIPT entry must
record `allow` (C2-11) in the tool and the verifier, entry shape, APPROVAL
state and duplicate id at the verifier, principal and currency of the
ledger, null optional members, trailing bytes after a COSE_Sign1.
Revision 4.3 (`aar_ref`) implements -02: optional mandate members,
CEILING_MALFORMED, only purchases reserve, replay key (`iss`,
`chain.ledger`, `sub`), approved AAR, kid before alg, invalid-recipient
rule, `principal_present` boolean, CHECKPOINT body, step 7(a) first.
Revision 4.2 (`aar_ref`) implemented -01: RFC 9679 kid, low-S,
strict CDE, `delete`/`publish`, REVOCATION, refusal, single approval
form, `chain.entry`, replay by (`iss`, `sub`), entry-major verifier.

Known gaps of witness v3 against this draft (Step 2 work, now closed in
v4.x except where noted in the v4 reports): the ledger is
not yet shared across instances on disk with linearizable appends
(Section 7.2); no COSE_Sign1 output; no checkpoints or anchoring; no
`audience` or `binding_request_hash`; principal key pinning exists only
as an optional registry parameter.

## Appendix C. Comparison with Neighbouring Work

Status as read on 2026-10-17 (full method and quotations in the
project's standards map). "Partial" entries are partial for the reasons
given.

| | human key is the authority | cumulative ledger verifiable by third party | non-payment actions |
|---|---|---|---|
| Permit profile -01 | partial: optional reference to external authority | no (not in I-D) | generic action label |
| keel-permit / verifier | partial: WebAuthn co-signature over an issuer-signed decision; issuer does not yet accept co-signatures | yes for money (root-wide value ledger) | partial: lanes without value, use limits only |
| Verifiable Intent v0.1 | yes (L2 signed by user device key) | partial: budget signed by user, tracked by payment network | no |
| Agent Action Capsule -05 | no (self-declared flag) | no | partial (records, not mandates) |
| AI Agent Execution -01 | partial (optional fields, operator signs) | no | partial (post-facto) |
| **deus-aar-0.1** | **yes** | **yes** | **yes: message, file, disclosure, meeting, deletion, publication** |

Limits of this comparison: keel-permit specifications were read in part;
other drafts by keyword search; the comparison can be overtaken within
months.

---

## Appendix D. Changes from -00

Each row is one ambiguity found by the second implementation (B, report
`verifier_js/OTCHET-INTEROP-2026-10-18.md`, numbering `AMBIGUITY-n`),
where -01 closes it and what the closing rule is.

| # | topic | resolution in -01 | where |
|---|---|---|---|
| 1 | disclosure with protected data: order of RECIPIENT and DATA_FORBIDDEN | `disclosure` with protected data is evaluated under its own recipients first, so RECIPIENT precedes step 12 | 6.4 step 10 |
| 2 | `delete`/`publish` only prose | CDDL members (`delete`, `publish`, null = absent), pattern syntax (trailing `*`, no bare `*`, never across `.`/`..`), codes `RESOURCE`, `IRREVERSIBLE_DELETE`, `ESCALATE_DELETE`, `ESCALATE_PUBLISH`; step 9 no longer overrides delete; unspecified reversible delete is `defer`, never `OK_UNSPECIFIED` | 5.6, 5.6.1, 6.1, 6.2, 6.4, 8.5 |
| 3 | publish with protected data and a wide disclosure grant | any protected data on `publish` is `DATA_FORBIDDEN` before everything else | 6.4 step 10 |
| 4 | order of verifier checks, meaning of position | entry-major: step 1, then entries in order with steps 2-7, `at` = `seq`; whole-ledger checks last | 10 |
| 5 | "unspecified recipients" | `to` null/absent and `domains` absent; empty lists are explicit and match nobody | 6.2 |
| 6 | no default for AAR lifetime or deferral timeout | RECEIPT carries `ttl` (REQUIRED), `expires = t + ttl`; the deferral timeout is the receipt's own `expires` | 7.1, 8.2, 6.6 |
| 7 | what "this AAR" is for replay; ES256 malleability | identity = CWT (`iss`, `sub`); bytes/signature never a key; ES256 kept, low-S mandatory for signers and verifiers | 8.1, 8.4 check 6 |
| 8 | codes for signature/format failures at the tool | `MALFORMED`, `TYP_MISMATCH`, `ALG_MISMATCH`, `KID_UNKNOWN`, `SIGNATURE_INVALID` registered; registry of all codes | 8.4, 8.5 |
| 9 | three shapes of CEILING | one map `{v,id,principal,amount,currency,window_s}`, also the signed payload; no default window | 6.3, 7.1 |
| 10 | case folding | `toNFKC_Casefold` once, then remove `White_Space` | 5.4 |
| 11 | CDDL against vectors (`null`, `id`, `v`, `currency`) | `null` = absent; `id` is `tstr`; `v` and `currency` required; witness rejects non-CDDL mandates (`MANDATE_MALFORMED`) | 6.1 |
| 12 | abstract checkpoint without `seq`, anchor digest | abstract `seq` absent = last entry; anchored digest = SHA-256 of the checkpoint COSE bytes | 9.2, 10 step 8 |
| 13 | float versus integer in JSON | a number with fraction or exponent is a float | 5.2 |
| 14 | `Name <addr>` with several `<...>` | exactly one pair or the recipient is invalid | 5.4 |
| 15 | tool and `independence: none` | tool rejects `WITNESS_NOT_INDEPENDENT` | 8.4 check 2 |
| 16 | `meeting` without `principal_present` | absent = false | 5.6 |
| 17 | data class label comparison | byte-exact, registered labels lower-case ASCII | 5.5 |
| 18 | RELEASE causes and illegal ones | four causes; anything else, or release of a non-active reservation, is `RELEASE_INVALID` | 7.4, 10 step 7 |
| 19 | start of `seq`, meaning of `at` | first entry `seq` 0, `prev` null; `at` = `seq` | 7.1, 10 |
| 20 | CDE as property or check | verifiers and tools MUST reject non-CDE and duplicate keys (`MALFORMED`) | 5.1 |
| 21 | tag 18 | tag is mandatory; untagged is `MALFORMED` | 5.1 |
| 22 | inclusion path format | RFC 9162 tree, leaf = SHA-256(0x00 \|\| entry hash), size `seq+1`, `[side, hash]` pairs, labels checked against derived sides | 9.1 |
| 23 | binding to the ledger identifier | step 3 compares each entry's `ledger` with the identifier of 7.1 (`CHAIN_BREAK`) | 7.1, 10 |
| 24 | `kid` | RFC 9679 SHA-256 thumbprint, 32 bytes, for every key; verifier recomputes it | 6.1 |
| 25 | `chain.prev` in the AAR | renamed `chain.entry` (hash of the RECEIPT entry); `ledger`, `seq`, `entry` REQUIRED | 8.2 |
| 26 | place and version of the inclusion check | renumbered in execution order; check 8; applies to every AAR | 8.4 |
| 27 | two forms of approval | one form `{v,t,receipt,mandate,action,approved}`; refusal expressible; bound to receipt id, mandate hash, action hash | 6.6, 7.1 |
| 28 | "canonical request" | the action map as submitted, CDE, SHA-256 | 5.7 |
| 29 | witness time in abstract vectors | decision function takes witness time; `action.t` is requester-asserted and never validity input; harness shorthand documented | 5.3, App. A |
| 30 | currency | REQUIRED in mandate and in monetary actions; absence is `BAD_AMOUNT` | 5.2, 6.4 step 6 |
| 31 | check 9 (reservation) without state | made by the witness at CONSUME; a stateless tool applies checks 1-8 | 8.4 |
| 32 | `typ` of ledger entries | `application/aar-ledger-entry+cbor` | 7.1, 14 |

Other changes: REVOCATION payload defined (`application/aar-revocation+cbor`,
6.7) and implemented; the Section 5.6 versus 6.4 step 9 contradiction on
irreversible deletion is removed (5.6 now points to the single normative
rule); the approval binds the receipt id (a new member beyond B's
proposal, so that two identical requests cannot share one approval);
release by `refused` and `revoked` added; item 14-17 of Section 15 added.

What -01 deliberately does NOT change: the profile identifier
`deus-aar-0.1`; text member names; the labelled inclusion path
(`["L", hash]`) of the vectors; the three-valued verdicts; the ledger
format apart from the members listed above.

---

## Appendix E. Changes from -01

Each row is one ambiguity found by the third implementation (C,
`verifier_swift/OTCHET-INTEROP-C-2026-10-18.md`, numbering `AMBIGUITY-C-n`),
where -02 closes it and what the closing rule is. Rows marked "choice"
record a decision between two defensible readings; the reason is given.

| # | topic | resolution in -02 | where |
|---|---|---|---|
| C-1 | CDDL of the mandate against 6.2/6.4 and the vectors | members of the permission maps are optional (`?`): `max_per_action`, `budget`, `min_price`, `to`, `data`, `domains` (`/ null`), and `named_circle`; an absent optional member is `null` (`named_circle`: `false`); `domains: null` is allowed; unknown members stay forbidden. Vectors C15/C17/C39-C41 are well formed as they stand. | 6.1, 6.2 |
| C-2 | CEILING without window in S11/S21 | all six members REQUIRED, `window_s` >= 1, no default; a bad ceiling is `CEILING_MALFORMED` at the witness and in the verifier (step 4). S11/S21 now carry the complete map. | 6.3, 7.1, 8.5, 10 |
| C-3 | order of `ALG_MISMATCH` and `KID_UNKNOWN` | choice: select the key by `kid` first (`KID_UNKNOWN`), then `alg` must equal that key's algorithm (`ALG_MISMATCH`); the algorithm of "the pinned key" does not exist before a key is selected | 8.4 check 2 |
| C-4 | two reservations expiring together | one expiry RELEASE per expired reservation, consecutive, ascending by RECEIPT `seq`; step 7(a) excuses an entry that is a RELEASE with cause `expired`; a RELEASE with another cause does not | 7.4, 10 step 7 |
| C-5 | order of steps 5 and 7 inside one entry | choice: step 7(a) is evaluated first for each entry (after step 3). Reason: it depends only on the earlier state and the entry's `t`; a lenient order would make the verdict of step 5 depend on whether the verifier imagines the reservation released | 7.3, 10 |
| C-6 | AAR after an approval | same `sub`; `chain` names the deferred RECEIPT; `expires` = the RECEIPT's; `approved_by` = hash of the APPROVAL entry; reason `OK_APPROVED`; a deferred RECEIPT plus an approving APPROVAL counts as `allow` for step 6; the tool's proof also carries the APPROVAL entry | 6.6, 8.4 check 8, 10 step 6 |
| C-7 | reservations for `sale` and `refund` | choice: only a `purchase` reserves. Reason: the budget and the ceiling bound spending; a sale is income and a refund request is not new authority (7.3 already said a REFUND never reduces `committed`) | 7.3, 7.4 |
| C-8 | invalid recipient with an unspecified permission | `deny RECIPIENT` for `message`, `file`, `disclosure` in every permission state (also `to: "*"`), before the unspecified rule | 5.4, 6.4 step 10 |
| C-9 | which permission step 8 reads for a `disclosure` without protected data | the permission of the class false, or (for that disclosure) `message` false: `CLASS_DENIED`; explicit denial wins | 6.4 step 8 |
| C-10 | scope of the named circle | explicit list = a `to` array; `domains` and `"*"` do not open it; applies to `message`, `file`, and `disclosure` without protected data | 6.5 |
| C-11 | `amount` of non-monetary actions | non-monetary: absent or 0, else `BAD_AMOUNT`; monetary: `amount` REQUIRED | 5.2, 6.4 step 6 |
| C-12 | `NO_INCLUSION` / `INCLUSION_INVALID` / `OFFLOG_RECEIPT` at the verifier | no proof: `NO_INCLUSION`; proof that does not verify: `INCLUSION_INVALID`; proof that verifies but names another entry or an entry not in the audited ledger: `OFFLOG_RECEIPT` (V12, C20 unchanged). A tool answers `INCLUSION_INVALID` for all but the first | 9.1, 8.4, 10 step 9 |
| C-13 | time of entries in abstract V01-V10 | every abstract verification entry carries `t` (vectors updated); no shorthand for entries | App. A |
| C-14 | `reason` and `audience` of the RECEIPT body | `reason` REQUIRED; `audience` REQUIRED except for a logged `deny NO_MANDATE`; missing is `MALFORMED` | 7.1 |
| C-15 | replay key across ledgers | choice: key = (`iss`, `chain.ledger`, `sub`). Alternative rejected: global uniqueness of `sub` per witness, which needs a cross-ledger index; the ledger identifier already contains principal and witness key and is signed | 8.4 check 6, 7.1 |
| C-16 | where CDE is checked, and the code | ledger entry encoding failure: `WITNESS_SIG`; principal object encoding or signature failure: `MANDATE_KEY` (verifier), `KEY_MISMATCH` (witness input); outer array and unprotected header need only be well formed | 7.1, 8.5 |
| C-17 | entry without `cose` | `MANDATE_KEY`; byte-level vectors are always real mode, the `require_cose` flag is removed | 7.1 |
| C-18 | body of a CHECKPOINT entry | `{seq, head, root}` all REQUIRED (`MALFORMED` otherwise); every CHECKPOINT entry is checked like a published one | 7.1, 9.1, 10 step 8 |
| C-19 | extra members of the MANDATE body, `pin` | body shapes defined; unknown body members are ignored; `pin` and `signed_by` are optional members of the MANDATE body | 7.1 |
| C-20 | meaning of `hash` in a path | RFC 9162 node hash of the sibling subtree (leaf hash for a leaf), not the entry hash | 9.1 |
| C-21 | inclusion proof for every AAR against hourly checkpoints | two kinds: anchor checkpoints (hourly/10 000, anchored) and inclusion checkpoints (on demand, one signature, shareable by a batch, anchored implicitly by the next anchor). The AAR is not delayed; the proof is supplied at presentation | 9.1.1, 8.4 check 8 |
| C-22 | non-boolean `principal_present` | only the boolean `true` counts (same rule as `reversible`) | 5.6 |
| C-23 | approval after the deferral timeout | `NOT_DEFERRED`, checked after the signature | 6.6 |
| C-24 | codes for "mandate by the wrong key" per stage | stage table | 8.5 |

Minor items of C, also closed: `params_hash` is defined (8.2); `iss` is
`witness:` plus the hex of the witness `kid` (8.2); the REFUND entry
body is defined and not interpreted (7.1); the witness's independence
statement is a verifier input (10).

What -02 deliberately does NOT change: the profile identifier
`deus-aar-0.1`; text member names; the labelled inclusion path; the
three-valued verdicts; the ledger format apart from the entry bodies of
Section 7.1 (which describe what implementations already wrote) and the
`reason`, `audience` members that were already written but optional.

Residual doubts the author records instead of hiding: C-5 and C-15 are
choices between readings, and an implementer who read -01 the other way
must change code; the approved AAR (C-6) is new wire behaviour that only
A implements before C and B are re-run; the inclusion checkpoint
(C-21) trades anchoring of every proof for latency and is a policy
decision a standard may revisit (Open Question 19).

## Appendix F. Changes from -02

Each row is one ambiguity (or the security defect C2-11) found by the
third implementation (C, `verifier_swift/OTCHET-INTEROP-C-02-2026-10-18.md`,
numbering `AMBIGUITY-C2-n`), where -03 closes it and the closing rule.
"Choice" marks a decision between two defensible readings, with the
reason. Row C2-11 comes first because it is a defect.

| # | topic | resolution in -03 | where |
|---|---|---|---|
| C2-11 | **AAR `allow` over a RECEIPT entry that records `deny`** (security defect) | the RECEIPT entry MUST record `allow` (or `defer` followed by an APPROVAL with `approved` true). Tool: `INCLUSION_INVALID`. Verifier of a ledger, for every receipt a tool reports as accepted: `OFFLOG_RECEIPT` (`NO_INCLUSION` for a deferral presented without an approval proof). Section 12.12 and a bullet in 12.6 | 8.4 check 8, 10 step 9, 12.6, 12.12 |
| C2-1 | `null` for optional members without `/ null` | choice: the prose wins, the CDDL follows: every `?` member also accepts `null` (`named_circle`, `pin_source`, `payment_mandate_ref`, `permit_ref`, `allow_irreversible`). Reason: -02 said "absent and `null` mean the same everywhere" and the permission maps already accepted `null`; rejecting `null` in the top-level members would make the two halves of 6.1 disagree | 6.1 |
| C2-2 | missing `cose` in real mode: shape or signature | `cose` is optional in every body shape (`? "cose"`); its absence is `MANDATE_KEY` in real mode, never `MALFORMED` or `CEILING_MALFORMED`. A complete CEILING body without `cose` is `MANDATE_KEY` | 7.1, 10 step 4 |
| C2-3 | repeated RECEIPT `id` at the verifier has no code | the verifier answers `DUPLICATE_RECEIPT_ID` at the second RECEIPT (first part of step 5); listed in the verifier result row and in the stage table | 7.1, 8.5, 10 step 5 |
| C2-4 | APPROVAL at the verifier | an APPROVAL whose receipt is not, at the entry's `t`, an undecided and unexpired `defer` RECEIPT earlier in the ledger is `MANDATE_KEY` (the witness says `NOT_DEFERRED`). Choice of `MANDATE_KEY` over a new code: the fault is that the entry is not a valid principal decision, the family of codes step 4 already uses | 6.6, 10 step 4, stage table |
| C2-5 | errors of the entry itself | the payload must match the `entry` CDDL: `ledger`, `seq`, `prev` wrong or missing is `CHAIN_BREAK` (step 3); `t`, `type`, `body` wrong or missing, or an extra member, is `MALFORMED` (step 4). `WITNESS_SIG` stays for signature and encoding | 7.1, 10 steps 3-4 |
| C2-6 | disclosure with `data` but no `to`/`domains` | step 10 says "recipients unspecified" (6.2: `to` and `domains` both null or absent), not "permission unspecified": `OK_UNSPECIFIED`, then step 12 gives `defer ESCALATE_DATA` | 6.4 step 10 |
| C2-7 | `register_ceiling` in the abstract harness | convention (6): the op carries `id`, `amount`, `currency`, `window_s`; `v` and `principal` are implied; another member is `CEILING_MALFORMED` | App. A |
| C2-8 | approved AAR without proof of the APPROVAL at the verifier | "no proof (for an approved AAR: of either entry): `NO_INCLUSION`" | 10 step 9 |
| C2-9 | proof checkpoint against "every signed checkpoint is also a CHECKPOINT entry" | choice: the witness SHOULD append every checkpoint it signs, but a verifier checks the checkpoint of a proof against the audited ledger (signature, `ledger`, `root` = Merkle root of entries 0..`seq`) and does not require it to be an entry. Reason: the requirement is unobservable for a proof (a witness can sign without appending) and the root check is what carries the evidence. The signature of a CHECKPOINT entry is the entry signature (step 2) | 9.1.1, 10 steps 8-9 |
| C2-10 | `principal` and `currency` consistency | `principal` of a MANDATE is the ledger's; `currency` of a MANDATE and a CEILING is the currency of the first MANDATE; codes `MANDATE_MALFORMED`, `CEILING_MALFORMED` at the witness and at the entry | 5.2, 6.1, 6.3, 10 step 4 |
| C2-12 | types in the abstract mode | convention (9): a string may stand for any `bstr` hash in the abstract vectors | App. A |
| ed. | broken stage table and `MANDATE_SIG` in the registry | table closed, four stage rows added, the paragraph on release causes starts after the table; `MANDATE_SIG` listed as both a `deny` (6.4 step 2) and a witness input rejection | 8.5 |

Also added from C's own vectors, as conventions of Appendix A: a
`tool_report` that releases nothing has the result `ignored` (7); the
refusal of an input by the witness is a step result (8); the shape of
`presented` in an abstract verification vector (10). Two defects of the
reference implementation A that C's vectors exposed are not changes of
the text: A accepted trailing bytes after a COSE_Sign1 (Section 5.1 (a)
already forbids them) and failed on a tool presentation without a
request (check 5: `REQUEST_MISMATCH`).

What -03 deliberately does NOT change: the profile identifier
`deus-aar-0.1`; the order of the checks of Section 8.4; the codes of -02
for every case that -02 already decided; the bytes and expectations of
every vector of -02.

Residual doubts the author records instead of hiding: C2-1 and C2-9 are
choices between readings, and an implementer who read -02 the other way
must change code (C reads `null` literally by default; its
`--lenient-cddl` switch is the -03 reading). C2-11 is closed in the text
and in the vectors, but the vectors are signed by test keys of the same
project, so a third party has not yet tried to bypass it.
