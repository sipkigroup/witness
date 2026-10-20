# Security policy

## Reporting a vulnerability

Email **support@sipkigroup.com** with the subject `SECURITY`. Please do not open a public issue for a vulnerability.
We read this mailbox every day; we aim to acknowledge within 3 business days and to give you a first assessment within 10.
The same contact is published at `https://witness.sipkigroup.com/.well-known/security.txt`.

Include: affected component and version, what an attacker gains, steps or a proof of concept. Encrypted mail is not set up yet; if you need it, ask for a channel in your first message (without details).

## Scope

In scope: the specification (`spec/`) where it allows a forged or ambiguous receipt, the verifiers (`verifier_js/`, `verifier_swift/`), the TypeScript client (`sdk-ts/`), and this repository's release workflows.
Out of scope: social engineering, denial of service by volume, findings that need a modified client or a stolen owner key.
The hosted service at witness.sipkigroup.com is covered by the same contact; please do not test it at volume.

## Supported versions

Only the latest released version gets fixes (this is a young project, 0.x).

## Our commitments

Coordinated disclosure: we fix, release, then publish an advisory crediting you (if you want), normally within 90 days of your report.
We do not run a paid bounty program at this time. We will not take legal action against good-faith research that follows this policy.
