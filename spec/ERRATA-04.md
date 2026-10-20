# Errata to draft-deus-aar-04 (18.10.2026)

The text of `draft-deus-aar-04.md` is NOT changed. This file lists corrections that apply to -04 and are folded into the next revision.
Source: security review of cloud/ (`cloud/review/OTCHET-REVIEW-2026-10-18.md`), finding R-01.

## E1. Section 5.4: a recipient is exactly one mailbox

Problem. Section 5.4 canonicalises the string and Section 6.2 takes the domain "after the last `@`" of the WHOLE string. A string that is a LIST
(`thief@attacker.example, colleague@acme.example`) or has two `@` (`thief@attacker.example@acme.example`) is canonicalised (white space removed)
and matched by the domain grant `acme.example`. Mail software treats the first as two recipients, so the grant is bypassed.

Rule (new step 4 of Section 5.4, after step 3). The canonical form MUST match, as a whole,

    [^@,;:<>()\[\]"\\]+ @ [^@,;:<>()\[\]"\\]+

(exactly one `@`, a non-empty local part and a non-empty domain, none of the characters `, ; : < > ( ) [ ] " \`; white space is already removed by step 3).
Otherwise the recipient is **invalid** in the sense of Section 5.4 step 1: it matches nothing, `deny RECIPIENT` for `message`, `file`, `disclosure`
in every permission state (including `to: "*"`, rule C-8). Entries of `to` and `domains` of a mandate follow the same rule for `to` (an invalid entry matches nothing).

A display name stays allowed through Section 5.4 step 1 (`Doe, J <buh@firma1.example>`: the text between `<` and `>` is checked, not the display name).

Vectors. `spec/vectors/D83-D91` (generator `aar_ref/make_vectors_v45e.py`) and `cloud/contract/vectors/recipient/*.json`.
Implementation A (`aar_ref/decide.py`) follows E1. Implementations B (node) and C (Swift) do not yet; their expected failures are D83 D84 D85 D86 D88 D91
(D87 D89 D90 are controls and pass). They are to be updated by a separate clean-room pass.

## Out of scope of E1 (kept for the next revision)
Several recipients are a matter of the caller: a tool that takes several addresses MUST be presented as several actions (the cloud tool map does this, R-02).
