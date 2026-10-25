# Recovery: a lost phone without weaker security (0.2.2)

Your passkey lives on a device. Lose the device and, until 0.2.2, you lost the account. 0.2.2 gives three ways back, and none of
them lets anyone sign for you without either a passkey you already hold or other people who know you.

| you lost | way back | what vouches for the new key |
|---|---|---|
| one device, you still have another passkey | **Devices**: remove the lost one | a signature by a passkey you still hold |
| every passkey, you have a recovery code | **Recovery code** -> add a new passkey | only the witness (said so in the pack) |
| your team key (organisation with a policy) | the **other members** replace your key | their signatures (rule `recovery`, k >= 2) |

## 1. Several passkeys (Devices page)
- Keep at least two passkeys on different devices (a phone and a hardware key, or a phone and a laptop). Any active one signs you in
  and signs for your own account.
- **Adding** one is two separate prompts: the new device creates its passkey, then a passkey you already use **signs exactly that new
  key** (a wa-sig of type `application/dw-key-event+cbor` over `{principal, op, kid, pub, cred, nonce}`). Until that signature arrives
  the new key is not active. A cookie alone cannot add a key; the new key cannot vouch for itself (`409 KEY_SELF`).
- **Removing** one is signed the same way. The last active passkey can never be removed (`409 LAST_KEY`). A removed passkey stops at
  once: it cannot sign in (`401 CREDENTIAL_REVOKED`), step up, approve or sign anything (`409 KEY_REVOKED`), and the sessions it
  opened end.
- Every addition and removal is a row of the registry hash chain (`registry_log`, hourly anchor) and shows in the evidence pack.
  Your other devices get a push ("a passkey was added to or removed from your account").

## 2. Recovery codes
- Ten one-time codes, made on the **Recovery codes** page after a fresh passkey signature (step-up). They are **shown once**; the server
  keeps only a scrypt hash of each (N = 2^14, r = 8, p = 1, 16-byte salt per code). Making new codes voids the old ones.
- A code has 20 symbols (`XXXX-XXXX-XXXX-XXXX-XXXX`, no I/O/0/1): the first group finds the row, the other 80 bits are the secret.
  Wrong, unknown and used codes get the same answer (`401 RECOVERY_INVALID`) after the same scrypt work. Limits: 10 attempts per hour
  per IP; 10 FAILED attempts per hour per account the code's lookup group reaches (0.2.12, R7-05: then that account's codes wait an hour);
  a code no account has (garbage) also counts against one ceiling for the whole server (300 per hour), which real codes never pay - a flood of
  garbage from many addresses cannot lock owners out.
- Using a code: the code is spent, **every session of the account ends**, every device of the person gets a push ("a recovery code was
  just used"), and the browser gets a 15-minute session that can do **one thing only**: add a new passkey (every other path answers
  `403 RECOVERY_ONLY`). After the new passkey is created the recovery session ends; you sign in with the new passkey, remove the lost one
  on Devices, and make new codes.
- **Phone or computer (0.2.14).** With confirmation levels the new key is a **laptop** key unless you choose "my new phone"
  on the recovery page (`POST /api/auth/recovery/passkey/begin {"label", "device": "phone"}`). Only a phone key may remove or demote your lost
  phone's key, so after losing the phone: run recovery **on the new phone**, choose "my new phone", sign in with it, remove the lost key.
  The declaration is recorded (`key_device`, `by: "recovery-code"`) and pushed to your devices. Keep the codes on paper: whoever holds a code
  can declare a new "phone".
- A key added with a code is recorded `by: "recovery-code"`. No old passkey signed it, so **only the witness vouches for it**, and the
  pack checker says exactly that: `keys: 2 keys (1 added: 0 by passkey, 1 by recovery code (witness-attested); 1 removed)`.

## 3. Organisations: the others replace your key
A team policy names **one key per member**. A new passkey on your account does not sign for the team until the policy names it.
- The policy may carry an optional rule `recovery: {"role": "any", "k": K}` (Team page, "Other members who replace someone's lost key").
  K must be **at least 2** - one person alone never takes over someone else's key - and reachable whichever one member is lost
  (otherwise `POLICY_MALFORMED`).
- After you added a new passkey (code or another device), any signer opens **"Lost passkey: replace key"** on the Team page. The request
  is a policy version that changes **only your key** (same roles, label and rules). It needs K signatures of OTHER members; your lost key
  never counts (`409 RECOVERY_SELF`). The sign page tells each signer to confirm with you in person or by phone first.
- Without a `recovery` rule the replacement is an ordinary policy change (rule `policy`). If the only owner loses the only owner key and
  there is no `recovery` rule, nobody can change the policy any more: add the rule while you can.
- The registry row of that version names the swap (`"key_swap": {"old_kid", "new_kid"}`), and the checker prints it:

```
org policy: chain ok (v1..v4)
org recovery: v4 replaced key 3992a358 -> b97f1671 (rule recovery any k=2, 2 signers, the replaced key not among them: yes)
keys: 2 keys (1 added: 0 by passkey, 1 by recovery code (witness-attested); 1 removed), 0/0 signatures by a key active at the time
quorum: 1/1 entries meet policy-at-time
RESULT: VALID
```
(from a test run, 19.10.2026: the owner of a
3-member organisation lost the phone; Bob and Carol replaced the key.)

## 4. Mandates signed by the lost key
They **stay valid**: each signature was good when it was recorded, the agents keep working, and the pack still verifies. The checker's
second pass accepts a signature only from a key that was active at the entry's witnessed time - before its removal, yes; after, `INVALID`
(`keys: FAIL KEY_NOT_ACTIVE@<seq>`).
If you do not trust them any more (the phone was stolen unlocked), **Devices -> "Revoke all"** lists the active mandates that key signed
and revokes them with a current passkey in one ceremony per 20 mandates: one batch envelope `wb` of typ
`application/aar-revocation+cbor` whose challenge covers the items **and the type**, so an approval batch can never be replayed as a
revocation (`REVOCATION_SIG`), nor the other way round. API: `GET /api/mandates/by-key/{kid}`, `POST /api/mandates/revoke-batch`.

## 5. API (machine form: `contract/v02/openapi-0.2.2-recovery.yaml`)
Person-level (under `/api/auth/`, any member including an observer): `GET /api/auth/keys`, `POST /api/auth/keys/add/{begin,finish,confirm}`,
`POST /api/auth/keys/{kid}/remove/begin`, `POST /api/auth/keys/{kid}/remove`, `GET|POST /api/auth/recovery-codes`,
`POST /api/auth/recovery/login`, `GET /api/auth/recovery/state`, `POST /api/auth/recovery/passkey/{begin,finish}`.
Organisation-level: `POST /api/org/key-replace`, `GET /api/mandates/by-key/{kid}`, `POST /api/mandates/revoke-batch`.
`GET /api/me` adds `signing_keys` (the passkeys that may sign in the current account: every active one of a solo account, the member's
key in a team).

## 6. Honest limits
1. **A recovery code is a key to the account.** Whoever holds one (and knows nothing else) can add a passkey, then remove yours and make
   new codes. What stands in the way: the push to your devices, the registry row, and in a team the other members. Keep codes offline.
2. **The witness vouches for a code-added key.** The pack shows `by recovery code (witness-attested)`; a third party trusts the witness
   for that step, as for the time of every entry.
3. **Removal does not reach the lost device.** It stops the key here; it does not erase the passkey on the phone, nor at the platform
   (iCloud Keychain / Google Password Manager may sync it to the thief's other devices - remove it there too).
4. **Old sessions.** Sessions opened before 0.2.2 do not record which passkey opened them; removing any key ends all of those.
5. **Agent API keys are separate.** A stolen session could have read nothing secret, but if you fear it was used, recreate the agents' keys.
6. **Checkers.** A pack with key changes needs the 0.2.2 checker. A 0.2.1 checker ignores the key rows: where a second passkey signed
   it answers `INVALID` (`ledger: invalid MANDATE_KEY@0` in my probe), otherwise it may say `VALID` without having looked at the key
   changes. The Swift checker does
   not know key events yet.
7. Push delivery is best effort (see Approvals): a security notice can arrive late or not at all.


## 0.2.5: what a recovery-code key can do in a team (R4-09)

A team policy names one key per member. A passkey you added with a recovery code (or on a second device) is **not** in the policy. In an organisation with a policy that key gets **no rights there** until the other members swap it in (Team -> "Lost passkey: replace key", rule `recovery`):
- step-up in that organisation is refused: `403 KEY_NOT_IN_POLICY` (this blocks editing tool maps, protected data, advisor, invites, agent keys, push routing, recovery codes);
- the protected literals are shown **masked**, as to an observer;
- your own account (no policy) and its pages behave as before; once the quorum replaced your key, the new key is in the policy and everything works.

So a stolen paper code of a team owner does not by itself open the team: before the quorum looks at the replacement request, the thief can read nothing protected and change nothing in the team.

**Not covered (decision of the product owner, not built):** the same key can still remove the owner's *other* keys from the personal account and make new recovery codes, and then open a key-replacement request that looks like an ordinary "lost phone". The team's confirmation by voice or in person (shown on the signing page) is the protection. A cooling-off period (for example the key added by a code may not remove older keys or make codes for 24-72 hours, or needs the old key's signature) would close it at a price in convenience; it is an open question for the owner.
