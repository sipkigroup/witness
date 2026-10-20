---
title: "Agent Action Receipts with Human Mandate and Cumulative Ledger"
abbrev: "Deus AAR"
docname: draft-deus-aar-00
category: info
ipr: trust200902
submissiontype: independent
date: 2026-10-17
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
credential [VI]. It adds exactly three things:

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
anywhere. Section numbers, field names and labels will change. Do not
implement against it except for the test vectors in Appendix A.

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
   monetary, appends a RECEIPT entry and signs the AAR.
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
Deterministic Encoding (Section 4.2.1 of [RFC8949]). In -00 map keys
are text strings for readability; integer labels are an Open Question
(Section 15). Hashes are SHA-256 over the deterministic encoding.

### 5.2 Amounts

Amounts are non-negative integers in minor units (e.g. cents) together
with an ISO 4217 currency code. Floating-point values, negative values,
values above 10^15 and any currency other than the mandate's currency
MUST be rejected with `BAD_AMOUNT`. Witnesses MUST NOT round or convert.

### 5.3 Time

All validity checks use the witness clock, never a time asserted by the
agent or operator. The witness clock MUST be monotonic: a backwards
step of the host clock MUST NOT move witness time backwards (it is
clamped). Times are integer seconds since the Unix epoch
everywhere in this document (ledger `t`, `expires`, `window_s`, ttl). See Section 12.7 for the limits of this.

### 5.4 Recipients

A recipient is canonicalised before comparison: if it contains
`Name <addr>`, take `addr`; apply Unicode NFKC; apply case folding;
remove all white space. Comparison is exact on the canonical form.
Domain grants match the canonical domain exactly; a subdomain does NOT
match its parent. Homoglyphs are not mapped and therefore do not match
(fail closed).

### 5.5 Data classes

Each action declares the data classes it carries (`data`). This profile
registers `city` as non-protected and `address`, `phone`, `passport` as
protected. Every unregistered data class MUST be treated as protected.
The declaration is made by the party proposing the action; see Section
12.8 for why this is a limitation.

### 5.6 Action classes and risk levels

| class        | meaning                                   | risk level |
|--------------|-------------------------------------------|------------|
| `message`    | send a message                            | `low`, or `disclosure` if protected data |
| `file`       | share a file (content opaque to witness)  | `disclosure` |
| `disclosure` | reveal personal data to a recipient       | `low` if only non-protected data, else `disclosure` |
| `purchase`   | spend the principal's money               | `monetary` |
| `sale`       | sell on the principal's behalf            | `monetary` |
| `refund`     | request or issue a refund                 | `monetary` |
| `meeting`    | arrange a physical meeting                | `low` if principal present, else `irreversible` |
| `delete`     | delete a resource (`recipient` = resource id; `reversible` flag, default false) | `low` if reversible, else `irreversible` (Step 2, -01) |
| `publish`    | publish to an open channel (`recipient` = channel id) | `disclosure`; any protected data is denied (Step 2, -01) |

The risk level is computed from the action content, not from the tool
name. Any class not in this table MUST be evaluated as `irreversible`
and denied (`CLASS_UNKNOWN`). Deletion and publication are registered from Step 2 (-01 working text; vectors D30, D44-D54): `delete`
needs a resource target in the mandate and denies irreversible deletion unless the mandate allows it; `publish`
needs a permitted channel and never carries protected data.

---

## 6. Human-Key Mandate

### 6.1 Structure

A mandate is a COSE_Sign1 signed with the principal key. Protected
header: `alg`, `kid` (COSE Key Thumbprint [RFC9679] of the principal
key), `typ` = `application/aar-mandate+cbor` [RFC9596].

```cddl
mandate = {
  "v": "deus-aar-0.1",
  "id": bstr .size 16,               ; random, unique
  "principal": tstr,                 ; principal identifier
  "agent": tstr,                     ; agent label this mandate binds
  "nbf": uint, "exp": uint,          ; validity, witness clock
  "currency": tstr,                  ; ISO 4217
  "budget_window_s": uint,           ; sliding window for budgets
  "permissions": permissions,
  "forbidden_data": [* tstr],        ; never, overrides all grants
  "named_circle": bool,              ; Section 6.5, default false
  "key_attestation": "secure-element" / "passkey" / "software",
  ? "pin_source": tstr,              ; Section 4.2
  ? "payment_mandate_ref": hash-ref, ; VI L2 / AP2 for payments
  ? "permit_ref": hash-ref,          ; Permit [I-D.munoz-...]
}
permissions = {
  ? "message":    recipients / false,
  ? "file":       recipients / false,
  ? "disclosure": disclosure / false,
  ? "purchase":   { "max_per_action": uint / null, "budget": uint / null } / false,
  ? "sale":       { "min_price": uint / null } / false,
  ? "meeting":    true / false,
  ? "refund":     true / false,
}
recipients = { "to": "*" / [* tstr] / null, ? "domains": [* tstr] }
disclosure = { "to": "*" / [* tstr] / null, ? "domains": [* tstr],
               "data": [* tstr] / null }
hash-ref   = { "alg": "sha-256", "digest": bstr, ? "uri": tstr }
```

### 6.2 Tri-state permissions

Each permission is in one of three states. **Absent** means the
principal did not say (unspecified). **false** means explicitly denied.
A **specification** names whom or how much. An explicit list or number
is stronger than the default: a recipient outside an explicit list, or
an amount above an explicit limit, is denied, not deferred.

The meaning of "unspecified" depends on the risk level:

| risk level     | unspecified permission means              |
|----------------|-------------------------------------------|
| `low`          | allow, with reason `OK_UNSPECIFIED` in the receipt |
| `monetary`     | defer to the principal (`ESCALATE_MONEY`), reservation held |
| `disclosure` (file) | defer (`ESCALATE_FILE`)              |
| `disclosure` (protected data) | deny unless the data class is explicitly granted (`DATA_NOT_PERMITTED`) |
| `irreversible` | deny                                      |

Rationale for denying, rather than deferring, protected data: disclosure
cannot be undone, and approval of deferrals is often blind. In the
project's L1 simulation (approvals modelled as blind with probability
0.97, an assumption, not a measurement of people) deferring protected
data produced 11 disclosures and 0 honest ones; denying produced 0. This is a contested choice (Section 15).

### 6.3 Ceiling

A ceiling is a principal-signed statement
`{ "v", "id", "principal", "amount", "currency", "budget_window_s" }`
that bounds the sum of committed amounts across **all** mandates of the
principal. A witness MUST enforce the most recent valid ceiling. A
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
4. Witness time outside `[M.nbf, M.exp]` or mandate revoked:
   `deny EXPIRED`.
5. `A.class` not registered: `deny CLASS_UNKNOWN`.
6. Amount invalid (Section 5.2): `deny BAD_AMOUNT`.
7. `A.data` intersects `M.forbidden_data`: `deny DATA_FORBIDDEN`.
8. Permission for the class is `false`: `deny CLASS_DENIED`.
9. Risk level `irreversible`: `deny UNATTENDED_MEETING` (meeting) or
   `deny CLASS_UNKNOWN`.
10. Class rule (result R):
    - `meeting`: `allow OK` if granted, else `allow OK_UNSPECIFIED`.
    - `message`, and `disclosure` with no protected data (the latter is
      evaluated under the `message` permission): unspecified ->
      `allow OK_UNSPECIFIED`; recipient not matched -> `deny RECIPIENT`;
      else `allow OK` (or `OK_CIRCLE`, Section 6.5).
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
    protected class, for **every** action class: `disclosure` permission
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

If and only if `named_circle` is `true`, a recipient that is not in the
list for the action's class but is in an explicit list for another of
`message`, `file`, `disclosure` is allowed for `message` and `file`
with reason `OK_CIRCLE`. The circle never opens protected data, never
overrides `false`, and never turns an unspecified `file` permission into
an allowance. The default is `false` (see Appendix B for the divergence
from the reference implementation).

### 6.6 Deferral and approval

On `defer`, the witness appends the RECEIPT entry with verdict `defer`
and, for monetary actions, holds the reservation. The principal decides
with a COSE_Sign1 under the principal key over
`{ "v", "t": "approval", "mandate": hash, "action": hash, "approved": bool }`.
An approval signed by any other key MUST be rejected (`APPROVAL_SIG`).
On approval the witness appends an APPROVAL entry and issues an `allow`
AAR that references it (`approved_by`). On refusal or timeout the
reservation is released. An agent or operator statement is never an
approval.

### 6.7 Revocation

A principal-signed revocation `{ "v", "t": "revocation", "mandate": hash }`
takes effect at the ledger position where it is appended. Actions
evaluated after it are denied (`EXPIRED`). Outstanding reservations are
released unless already presented to a tool.

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
  "seq": uint,             ; 0, 1, 2, ... no gaps
  "prev": bstr / null,     ; SHA-256 of previous entry (full COSE bytes)
  "t": uint,               ; witness time, integer seconds
  "type": "MANDATE" / "CEILING" / "REVOCATION" / "RECEIPT" /
          "APPROVAL" / "CONSUME" / "RELEASE" / "REFUND" / "CHECKPOINT",
  "body": any,             ; principal-signed object or witness record
}
```

MANDATE, CEILING, REVOCATION and APPROVAL bodies embed the
principal-signed COSE object unchanged (body field `cose`), so a verifier
checks the principal signature directly under the pinned key. The
`typ` header and the signed payload are:

- MANDATE: `application/aar-mandate+cbor`, canonical CBOR of the mandate;
- CEILING: `application/aar-ceiling+cbor`, `{"ceiling": uint, "window_s": uint, "principal": tstr}`;
- APPROVAL: `application/aar-approval+cbor`, `{"approve": receipt-id, "principal": tstr}`.

The verifier recomputes the payload from the plain body fields
(`amount`, `window_s`, `receipt`) and requires it to equal the signed
payload; a body that differs from what the principal signed is
`MANDATE_KEY`. Symbolic signer names are an abstract-mode device only; a
real-mode verifier MUST reject an entry without `cose`.

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

`committed(principal, t)` is the same sum across all mandates of the
principal, using the ceiling's window. A REFUND entry records money
returned but MUST NOT reduce committed amounts (a refund is not new
authority). Sessions do not exist at the ledger level: a new agent
session MUST NOT reset any sum.

### 7.4 Reservation life cycle

- **Reserve.** A monetary action with verdict `allow` or `defer` creates
  a reservation for its full amount in the same ledger append as the
  RECEIPT entry. The verdict and the reservation are atomic with respect
  to other appends for the principal.
- **Consume.** When a tool accepts an AAR (Section 8.4) the witness
  appends CONSUME. A tool MUST NOT execute if the reservation is not
  active.
- **Release.** A reservation is released only by (a) a tool-signed
  statement that the action was not executed, (b) expiry of the AAR
  before any tool accepted it, (c) refusal or timeout of a deferral, or
  (d) revocation before presentation. A release appends RELEASE with
  the cause. For (b) the witness MUST append `RELEASE` with cause
  `expired` at its first operation after `now > expires` and before any
  other entry; a verifier MUST reject a ledger where an entry with
  `t > expires` follows an active reservation (`RELEASE_MISSING`), and a
  `RELEASE` with cause `expired` before expiry (`RELEASE_INVALID`).
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
- protected `kid`: witness key identifier;
- protected `typ` [RFC9596]: `application/aar-receipt+cbor`;
- protected CWT Claims [RFC9597]: `iss` = witness identifier,
  `sub` = action identifier, `iat` = witness time;
- unprotected: zero or more COSE Receipts of inclusion from a TS
  [I-D.ietf-cose-merkle-tree-proofs] once registered;
- payload: the `aar` map below, attached.

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
    "params_hash": bstr,                ; as in noa-receipt
    "binding_request_hash": bstr,       ; canonical request bytes, as in Permit
  },
  "mandate": {
    "ref": hash-ref,                    ; hash of the principal-signed mandate
    "principal_kid": bstr,
    "key_attestation": tstr,
    ? "approved_by": hash-ref,          ; APPROVAL entry, if deferred then approved
  },
  "budget": {                           ; absent for non-monetary actions
    "reservation_id": bstr,
    "reserved": uint,
    "committed_before": uint, "limit": uint / null,
    "principal_committed_before": uint, "ceiling": uint / null,
    "window_s": uint,
  },
  "verdict": { "decision": "allow" / "defer" / "deny",
               "reason": tstr, "risk": tstr },
  "expires": uint,                      ; witness time
  "chain": { "ledger": bstr, "seq": uint, "prev": bstr },
  ? "permit_ref": hash-ref,
}
```

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
MUST reject otherwise with the given reason:

1. an AAR is presented (`NO_RECEIPT`);
2. the witness signature verifies under a key in the witness key set
   pinned by the tool;
3. `verdict.decision` is `allow` (`NOT_ALLOWED`);
4. `audience` identifies this tool (`AUDIENCE`);
5. the hash of the canonical request the tool is about to execute equals
   `binding_request_hash` (`REQUEST_MISMATCH`);
   (9, evaluated after 7) the AAR comes with an inclusion proof: the
   RECEIPT entry (its hash equals `chain.prev`, its seq equals
   `chain.seq`, its id equals the CWT `sub`) and a Merkle path from that
   entry hash to the `root` of a witness-signed checkpoint covering it
   (`NO_INCLUSION` if absent, `INCLUSION_INVALID` otherwise). This closes
   receipts issued outside the ledger (V11);
6. this AAR has not been accepted before (`REPLAY`);
7. witness time is not after `expires` (`RECEIPT_EXPIRED`);
8. for monetary actions, the reservation is active
   (`RESERVATION_INACTIVE`).

Checks 6-8 and the transition to consumed MUST be atomic. Tools SHOULD
return a signed acceptance or non-execution statement; see Section 15
on making this REQUIRED.

---

## 9. Anchoring

### 9.1 Checkpoints

At least once per hour, and at least once per 10 000 entries, the
witness MUST append a CHECKPOINT entry and publish a signed checkpoint:

```cddl
checkpoint = { "ledger": bstr, "seq": uint, "head": bstr,
               "t": uint, "root": bstr, ? "ts_tree_head": bstr }
```

The checkpoint is a COSE_Sign1 under the witness key
(`typ` `application/aar-checkpoint+cbor`). `root` is the RFC 6962 style
Merkle root over the entry hashes 0..`seq`. A verifier checks the
signature (`CHECKPOINT_SIG`), `head` (`CHECKPOINT_HEAD`) and `root`
(`CHECKPOINT_ROOT`) against the ledger. A checkpoint does not cover
entries after `seq`: rewriting only the tail after the latest
checkpoint is detected by the next checkpoint, not by this one.

`head` is the hash of the entry at `seq`. If the witness serves many
principals it SHOULD aggregate their heads into a Merkle tree and anchor
the root, publishing per-ledger inclusion paths.

### 9.2 Primary anchor: OpenTimestamps

The witness MUST submit the SHA-256 of the checkpoint (or of the
aggregated root) to at least two OpenTimestamps calendar servers
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

Given the ledger, the witness key set, the operator key set, the pinned
principal key, and the checkpoints with their anchors, a verifier MUST:

1. Reject if the witness key is in the operator key set
   (`WITNESS_NOT_INDEPENDENT`) or the independence statement is `none`.
2. Verify every entry's witness signature (`WITNESS_SIG`).
3. Verify the chain: `seq` increments by one and `prev` equals the hash
   of the previous entry (`CHAIN_BREAK`).
4. Verify every MANDATE, CEILING, REVOCATION and APPROVAL body under the
   pinned principal key (`MANDATE_KEY`).
5. For every RECEIPT, check that its mandate is present earlier in the
   ledger (`MANDATE_UNKNOWN`; the only exception is a logged `deny` with
   reason `NO_MANDATE`, Section 8.2) and **re-evaluate** the action with the
   algorithm of Section 6.4 against the state reconstructed so far. The
   recomputed verdict MUST equal the signed verdict
   (`VERDICT_NOT_REPRODUCIBLE`). This is what makes the witness's
   decision checkable rather than trusted.
6. For every CONSUME, check the corresponding receipt was `allow`,
   unconsumed, unexpired, and its reservation active (`CONSUME_INVALID`).
7. Check every checkpoint signature, `head` and `root` against the ledger
   (`CHECKPOINT_SIG`, `CHECKPOINT_HEAD`, `CHECKPOINT_ROOT`) and its anchor
   (Section 9.2). Check Section 7.4 explicit releases (`RELEASE_MISSING`,
   `RELEASE_INVALID`). For every receipt that a tool reports as accepted,
   check that it is included in this ledger under the checkpoint
   (`NO_INCLUSION`, `OFFLOG_RECEIPT`).
8. Optionally verify COSE Receipts of inclusion from the TS.

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
one tool (`audience`), one acceptance (single use at the tool), a
deadline (`expires`) and, for money, one active reservation (S06, S17,
S14). An approval is bound to the mandate hash and the action hash and
cannot be reused for another action. A mandate is bound to one agent
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
  without an inclusion proof into a signed checkpoint (Section 8.4(9)) and
  a verifier flags a presented receipt that is not in the audited ledger
  (`OFFLOG_RECEIPT`). A witness that signs a checkpoint for a private fork
  is still not detected by one ledger alone: that needs anchoring of
  checkpoints (both heads anchored) or tool-countersigned consumption;
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

None in -00. A future revision would request: media types
`application/aar-mandate+cbor`, `application/aar-receipt+cbor`,
`application/aar-checkpoint+cbor`; a registry of action classes; a
registry of data classes; a registry of reason codes; and integer CBOR
labels.

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
4. **Deletion and publication.** Named in the motivation, not yet
   registered as classes; fail-closed until then (D30). Deletion needs a
   reversibility attribute (soft delete, retention).
5. **Window versus lifetime budgets.** A sliding window is implemented;
   lifetime budgets (and both together) are probably needed.
6. **Tool-signed consumption.** Inclusion proofs (Section 8.4(9)) close
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
flag. They test Sections 5-10 logic. Byte-level COSE vectors are
deferred to -01 together with the reference implementation.

Three kinds:

- `decision` (D01-D43): mandate, action and ledger state -> verdict and
  reason (Section 6.4);
- `sequence` (S01-S18): a sequence of ledger operations (register,
  authorize, tool presentation, reports, clock, restart, approval) ->
  the result of each step (Sections 6.6, 7, 8.4);
- `verification` (V01-V11): a ledger and checkpoint -> verifier result
  (Sections 9, 10).

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

`vectors/check_vectors.py` is an executable reading of Sections 5-10;
`python3 check_vectors.py` recomputes every expected result (0
mismatches at the time of writing). It is not the reference
implementation.

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

Known gaps of witness v3 against this draft (Step 2 work): the ledger is
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
| **deus-aar-0.1** | **yes** | **yes** | **yes: message, file, disclosure, meeting; deletion and publication planned** |

Limits of this comparison: keel-permit specifications were read in part;
other drafts by keyword search; the comparison can be overtaken within
months.
