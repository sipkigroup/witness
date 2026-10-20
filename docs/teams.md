# Teams: roles, the organisation policy, quorum

A Witness account is an **organisation** (principal `dw:<account_id>`, one ledger). People join it with their own passkeys; who may
sign what is written in a **signed policy**, and the witness checks every signature against the policy that was in force at the time.
An account without a policy works exactly as in 0.1 ("solo": the owner's pinned key signs everything).

## 1. Roles
| role | may |
|---|---|
| `owner` | the policy, members, invitations, agents, tool maps, organisation settings |
| `budget` | sign mandates and approvals of **money** classes (purchase, sale, refund) |
| `access` | sign mandates and approvals of the other classes (message, file, disclosure, delete, publish, meeting) |
| `observer` | read only: the feed, the digest, the evidence pack. Signs nothing and is **not** in the policy |
One person may hold several roles. A quorum is counted over **different keys** (`kid`), so one person with two roles closes both
requirements only where each needs k = 1. Every changing request passes one rights check on the server (`require(user, account, action)`);
an observer gets `403` on every changing path *(tested, `server/tests/test_org.py::test_6_observer_403_on_every_changing_path`)*.

## 2. The policy
A signed CBOR document (`typ application/dw-org-policy+cbor`, version `dw-org-policy-0.1`): members (<= 16; key id, public key, roles,
a label of <= 32 characters without `@` - no e-mail addresses), and rules:
- `mandate`: tiers such as `{"if": "money_over", "amount": 50000, "role": "budget", "k": 2}` - mandates whose money limits exceed $500 need 2 budget signers; `money` (any money class) and `access` (any other class) tiers exist too;
- `approval`: the same tiers for approving a deferred action (by its class and amount);
- `policy`: who signs the next version; `revocation`: default `{"role": "any", "k": 1}`; `ceiling`;
- `recovery` (optional, 0.2.2): `{"role": "any", "k": 2}` - k >= 2 OTHER members replace one member's lost key (a version that changes
  only that key); see the recovery page.
Version 1 (genesis) is created by the owner on the first team action: one member (the owner's pinned key), all roles, all k = 1.
Every change (add / remove a member, roles, rules) is a new version `ver + 1` with `prev` = SHA-256 of the previous one, signed by the
`policy` rule of the **previous** version, and appended to the registry hash chain (which goes into the hourly anchor).

## 3. Quorum
Each signer's browser signs the ordinary single-signature challenge (`deus-aar-wa-0.1`) - no new code on the phone. The server
collects the signatures in a sign request (`sign.html?req=<id>`, shown to members with the needed role) and, when k are present,
builds a quorum envelope `wq` (`deus-aar-wq-0.1`: typ, payload, policy hash, signatures sorted by kid) and registers the mandate or the
approval once. Until then the mandate stays "collecting 1/2" and the agent is refused (`NO_MANDATE`). A mandate draft lives 24 h.
**Stopping is easy, permitting is hard**: revocation needs ONE signature of any signer; widening rights needs the quorum of the role.

*Tested in the browser* (`cloud/e2e/test_team.py`, three Chromium profiles with three CDP virtual authenticators, real 0.2.0 server,
19.10.2026): invitations -> policy v2 "mandates with purchases over 500 USD: 2 of 3 budget signers" -> a $2000 mandate: after one
signature "collecting 1/2" and the agent gets `NO_MANDATE`; after the second, the ledger's MANDATE entry carries a `wq` with exactly the
two signers' key ids and the agent's $300 purchase is allowed -> a **non-owner** budget signer revokes with one signature (the ledger's
revocation carries only that signer's key id) -> the agent is refused.

## 4. What a third party sees
The evidence pack carries `org/policy-v<N>.cbor` with the envelope of each version, the registry chain, and for every
MANDATE / APPROVAL / REVOCATION which key ids signed and under which version. `verify_pack.py` checks the chain, the signatures and,
in a second pass over the ledger, that each quorum met the policy **in force at the entry's time**. My run of
`server/tests_pack/test_team_pack_server.py` (19.10.2026: a 3-member organisation built by the real server, a 2-of-3 mandate, a quorum
approval, a one-signature refusal, a batch of 3 publications, an advisory hold + release, coverage from the proxy, a revocation, the
anchor job with two **test** TSAs) printed:
```
org policy: chain ok (v1..v2)
ledger: valid (24 entries)
receipts: 6/6 included
quorum: 8/8 entries meet policy-at-time
batch approvals: 1 envelopes, 3 items
coverage ag_6517aa036bc9: C1 (operator-declared, not verified)
advisory: 1/1 releases signed (the L3 advice itself is not evidence)
anchor 20261019T020441Z-b2995c14: pending (inclusion in batch root proven; not stamped)
tsa 20261019T020441Z-b2995c14: OK (tsa-a, tsa-b)
RESULT: VALID
```
It does **not** see: names and e-mail addresses (only labels and key ids), observers, who pressed "refuse" before a quorum was reached.

## 5. Limits
1. **Policy time is the witness's time.** "Was version v in force when this entry was written" is decided by the entry time, which the
   witness signs (-04 §12.6). A dishonest or wrong-clock witness could accept a signature of a member removed a minute earlier. Same
   trust as key pinning in 0.1. In the pack the time of each policy version is signed only by the manifest (OTCHET-0.2.0 §4 p.8).
2. The quorum check inside the core's registry is stateless; policy-at-time is a **second pass** outside the core (server at intake,
   `verify_pack` on the ledger). An error there would accept a removed member's signature; the contract vectors include "removed in v3,
   signed by v2 after v3 -> `WQ_POLICY_STALE`".
3. Team packs are verified by the **Python** verifier only; the Swift verifier says `INVALID WA_MALFORMED` on them until 0.3.
4. One key per member **in the policy**. 0.2.2: a person may hold several passkeys, and a lost member key is replaced by the other
   members under the optional rule `recovery` (k >= 2, the lost key never counts) - see the Recovery page. Without that rule a
   lost passkey of the only owner still means the policy cannot change. No SSO/SCIM yet.
5. A batch (`wb`) and a quorum are not combined: items whose approval needs k >= 2 are approved one by one, by quorum.
6. The deferred-action TTL for organisations with k >= 2 rules is a setting (`defer_ttl_s` 900...3600 s): a quorum not gathered in time
   lets the action expire.
