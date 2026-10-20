# A WebAuthn Signature Profile for Authorization Mandates and Approvals of draft-deus-aar-04

draft-deus-aar-profile-webauthn-00 (working text, 2026-10-19)

## Abstract

draft-deus-aar-04 requires principal-signed objects (mandate, approval, revocation, ceiling) to be COSE_Sign1 structures. A WebAuthn authenticator (a passkey) cannot produce such a structure: it signs only `authenticatorData || SHA-256(clientDataJSON)`. This profile defines an envelope, "wa-sig", that carries the same -04 payload together with a passkey assertion, a challenge construction that binds the assertion to the payload, a key-pinning record, and an offline verification algorithm for third parties. The profile is an appendix to -04; -04 itself is unchanged.

## 1. Introduction

-04 Section 4.1 allows `key_attestation: "passkey"`, while Sections 6.1 and 6.6 require a COSE_Sign1 signature under the principal's key. This profile closes the gap. The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 2. Envelope

A wa-sig envelope is a CBOR map in Core Deterministic Encoding (RFC 8949 Section 4.2.1, as required by -04 Section 5.1). It is not a COSE structure; a reader distinguishes the two by the first byte: 0xA7 (map of 7 members) for wa-sig, 0xD2 (tag 18) for COSE_Sign1.

```cddl
wa-sig = {
  "v": "deus-aar-wa-0.1",
  "typ": tstr,          ; media type of the -04 object:
                        ;   application/aar-mandate+cbor | application/aar-approval+cbor |
                        ;   application/aar-revocation+cbor | application/aar-ceiling+cbor
  "kid": bstr .size 32, ; RFC 9679 thumbprint of the principal's EC2 P-256 key (as -04 Section 6.1)
  "payload": bstr,      ; the exact CDE bytes -04 would place in the COSE_Sign1 payload of this type
  "authData": bstr,     ; authenticatorData of the assertion
  "clientDataJSON": bstr, ; clientDataJSON bytes exactly as returned by the browser
  "sig": bstr .size 64  ; ECDSA P-256 r || s, 32 bytes each big-endian, low-S
}
```

The envelope has exactly these 7 members. In a ledger entry of type MANDATE, APPROVAL, REVOCATION or CEILING the member `cose` carries the wa-sig bytes in place of a COSE_Sign1 (Section 6).

## 3. Challenge

```
challenge = SHA-256( "deus-aar-wa-0.1" || 0x00 || typ (UTF-8) || 0x00 || payload )   ; 32 bytes
```

The signer passes `challenge` to `navigator.credentials.get({publicKey: {challenge, rpId, allowCredentials: [pinned credential], userVerification: "required"}})`.

Freshness is not provided by the challenge. The payload carries a unique identifier (`id` for a mandate, `receipt` for an approval), and the witness rejects a replayed envelope under -04 (`MANDATE_EXISTS`, `NOT_DEFERRED`).

The DER signature in `AuthenticatorAssertionResponse.signature` is converted to r || s. If s > n/2 the signing side (browser, or the server on receipt) replaces s with n - s, which is an equally valid signature. A verifier MUST reject high-S (as -04 Section 8.1).

## 4. Key pinning

```json
{"alg": "ES256", "pub": "<hex, 65 bytes 04||x||y>",
 "webauthn": {"rp_id": "witness.sipkigroup.com", "origins": ["https://witness.sipkigroup.com"], "credential_id": "<base64url>"},
 "pin_source": "webauthn-registration:witness.sipkigroup.com:<ISO-8601 time>:registry-log#<seq>"}
```

The key is taken from the attestedCredentialData at registration (attestation "none"; only COSE algorithm -7, ES256). `kid` is the RFC 9679 thumbprint of that key.

## 5. Verification algorithm

Inputs: the envelope, the expected `typ`, the expected payload (the verifier recomputes it from the ledger, as -04 Section 10 step 4), and the registry entry of Section 4. Steps, in this order; the first failing step determines the code:

1. The envelope is a CDE map with exactly the 7 members of Section 2 and `v` = "deus-aar-wa-0.1"; otherwise `WA_MALFORMED`. A map whose bytes differ from its own canonical re-encoding (key order, non-shortest lengths, indefinite items) is malformed.
2. `typ` equals the expected type and `payload` equals the expected payload byte for byte; otherwise the -04 code for the type: `MANDATE_SIG`, `APPROVAL_SIG`, `REVOCATION_SIG`, `CEILING_SIG`.
3. `kid` equals the thumbprint of the pinned key; otherwise `KEY_MISMATCH`.
4. `clientDataJSON` parses as JSON; `type` = "webauthn.get"; `challenge` = base64url (no padding) of the challenge of Section 3; `origin` is in `origins`; `crossOrigin` is absent or false; otherwise `WA_CLIENTDATA`.
5. `authData` is at least 37 bytes; its first 32 bytes equal SHA-256(rp_id); the flags UP (0x01) and UV (0x04) are both set; otherwise `WA_AUTHDATA`. `signCount` is not checked (synchronised passkeys report 0).
6. s <= n/2 and the ECDSA P-256 / SHA-256 signature is valid over `authData || SHA-256(clientDataJSON)` under the pinned key; otherwise `WA_SIG`.

A failure of steps 1-6 maps to the -04 code a verifier would give for an invalid principal signature in that entry (`MANDATE_KEY` in the verifier; `MANDATE_SIG`, `APPROVAL_SIG` or `KEY_MISMATCH` at the witness); the `WA_*` code refines it in the output. A -04 verifier that does not implement this profile MUST report such a ledger as invalid.

## 6. Placement in the ledger

In the body of MANDATE, APPROVAL, REVOCATION and CEILING entries, the member `cose` holds the wa-sig bytes. The mandate has `key_attestation: "passkey"`.

## 7. Security considerations

The profile does not remove the following limits; implementations MUST state them to users.

- What the human sees. An authenticator does not display the mandate; the human sees a web page. The browser encodes the mandate in CDE and computes the challenge from what it shows (the server sends fields, not a hash). A compromised server can still serve altered JavaScript. MVP mitigation: strict CSP, no external scripts, SHA-256 hashes of the signing-page files published and included in the evidence pack. This is -04 Section 12.10.
- One key for login and for signing. Login uses a random challenge, signing uses the payload hash. A malicious server could present a mandate hash as a login challenge. This gives no more power than altered JavaScript; a separate signing key is future work.
- Pinning (-04 Section 4.2). Registration happens on the witness's own site, so the pinning source is controlled by the witness. This WEAKENS the requirement of Section 4.2. Mitigation: an append-only hash-chained registry log whose head enters the periodic timestamp anchor; the user sees a key card (kid, first 8 bytes in groups) at registration and can compare it with the evidence pack. This does not detect a substitution at the moment of registration. `pin_source` honestly says `webauthn-registration`.
- No device attestation (attestation "none"). `key_attestation: "passkey"` is a claim, not a proof.

## 8. Test vectors

`vectors/wa/*.json`, one file per vector: `{id, class: "valid"|"invalid", expect: <code or null>, typ, payload_hex, reg_entry, envelope_hex, note}`. A conforming verifier returns `expect` for every vector when called with `typ`, `payload_hex`, `reg_entry` and `envelope_hex`. The set contains 4 valid vectors (mandate, approval true, approval false, high-S normalised) and invalid vectors for each step of Section 5: foreign origin, crossOrigin true, webauthn.create type, wrong challenge, wrong rpIdHash, UV clear, UP clear, high-S, substituted payload, foreign kid, extra map member, non-CDE key order, wrong typ. `vectors/cde/*.json` holds JSON-value to CDE-hex vectors for the payload encoder (byte strings are written `{"$bytes": "<hex>"}`).

The reference implementation is `wa_profile.py` (verify_envelope, make_envelope, SoftAuthenticator).

## 9. References

draft-deus-aar-04; RFC 8949 (CBOR); RFC 9052 (COSE); RFC 9679 (COSE Key Thumbprint); W3C WebAuthn Level 2/3.
