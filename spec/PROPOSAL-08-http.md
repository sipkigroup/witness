# Proposal for draft-deus-aar-06: action class `http` - a signed list of HTTP requests, the rest asked (25.10.2026)

Кратко по-русски. Модуль Witness для NVIDIA OpenShell (`openshell-modul/`) шлёт в Witness HTTP-запрос агента (метод, хост, порт, путь,
query, SHA-256 тела, sandbox_id). До сих пор он занимал класс `publish`: либо спрашивать всё (`publish: null`), либо подписанный список
каналов и ОТКАЗ всему остальному. Нужного режима «список — без вопроса, остальное — спросить человека» не было. Предложение: свой класс
`http` по образцу `command` (PROPOSAL-06): разрешение `http = {allow: [правило...], unlisted: "ask" | "deny"}`, правило =
`МЕТОД хост[:порт]/путь-шаблон` в каноническом виде, без регулярных выражений; код `ESCALATE_HTTP`. Тело и query в правило не входят, но
входят в хеш запроса (подписанная привязка квитанции и одобрения, как сейчас). Реализация A: `svidetel_v4/httpcanon.py`, `decide.py`,
`schema.py`; тесты `svidetel_v4/test_v49.py`. Номер 08 уже занят `PROPOSAL-08-exec.md`; разделы здесь помечены `PH-`, при сведении в -06
номер будет другим.

Status: proposal on top of PROPOSAL-06. Nothing below is normative for -05 implementations.

## PH-1. Why a new class, not `publish` + `unlisted`

- `publish` means "make public on a channel": its reason code (`ESCALATE_PUBLISH`), its text on the approval page and in the ledger
  would say "publication" for a `GET` of a repository. PROPOSAL-06 removed the same mis-naming for shell commands.
- A `publish` channel is an opaque byte string (Section 5.6.1). An HTTP target is not opaque: `API.github.com`, `api.github.com.`,
  `/repos/a/%62` and `/repos/a/b` are one resource to a server. A list over opaque strings is either bypassed (the agent writes the
  variant the list does not name, under `unlisted: "ask"` that only costs a question) or, worse, a prefix entry `GET h/repos/a/*` matches
  `GET h/repos/a/x/../../../admin`. Matching HTTP needs its own canonical form; adding it to `publish` would change what every existing
  `publish` list means.
- Compatibility is cleaner: a new permission key and a new class are both refused by every older implementation (PH-8).

## PH-2. Action (Section 5.6)

| class | meaning | risk level |
|---|---|---|
| `http` | one HTTP request the agent's sandbox sends (`recipient` = request target, below) | `disclosure`; any protected data is denied |

**Request target** (`recipient`, set by the integration from what the proxy saw, never by the agent's arguments):
`<METHOD> SP <host> ":" <port> <path>` - the port is ALWAYS written (`PUT api.github.com:443/repos/acme/app/pulls/7/merge`); the query
string, the fragment and the body are not part of it. The reference module (`openshell-modul/witness_openshell/policy.py`) builds it from
OpenShell's `HttpRequestTarget` and binds the query, `body_sha256`, `body_bytes` and `sandbox_id` as further arguments; the tool map
entry is `{"class": "http", "recipient": "$.target", "text": ["$.body", "$.query"], "extra_keys": [...], "strict": true}` (preset
`openshell` of the reference server). Every argument is in `args_sha256`, so in the request hash, the receipt and any approval.

## PH-3. Permission (Section 6.1, CDDL)

```cddl
permissions = { ...,  ? "http": http-perm / false / null }          ; PH
http-perm = { ? "allow": [* http-rule] / null,                        ; requests that run without a question (at most 200)
              ? "unlisted": "ask" / "deny" / null }                   ; absent or null = "ask"; there is NO "allow"
http-rule = tstr       ; canonical (PH-4), 1..512 characters; a mandate with a non-canonical rule, or with the same rule twice in `allow`
                       ; (byte-equal canonical texts), is MANDATE_MALFORMED
count-class = ... / "http"
```
`http: true` is malformed. `unlisted: "allow"` does not exist on purpose: "any request of this agent runs" is not a list, it is the
absence of the witness; whoever wants it does not select the traffic for the witness in the proxy policy.

## PH-4. Canonical form and matching (no regular expressions)

**Rule** `<method> SP <host-pattern> [":" <port>] <path-pattern>`:
- method: `*` (any method) or 1..16 ASCII letters, upper-case (`GET`);
- host-pattern: lower-case ASCII host name (labels `[a-z0-9_-]{1,63}`, no empty label, no trailing dot, <= 253 characters), or `*.` +
  such a name of at least two labels (`*.example.com` = any name that ends in `.example.com`, not `example.com` itself), or a dotted
  IPv4 address in its only canonical form (four decimal octets, no leading zeros). No IPv6, no user info, no non-ASCII: an
  international name is written in punycode (`xn--...`);
- port: absent = 443; 1..65535 without leading zeros; `:443` is not canonical (the rule is written without it);
- path-pattern: `/` + segments; a segment is a canonical literal (below, without `*` and `,`), `*` (exactly one non-empty segment), or,
  as the LAST segment only, `**` (one or more segments of the target, where an empty trailing segment, i.e. a trailing slash, counts as
  one: `/app/**` covers `/app/` and `/app/x/y`, but not `/app`). An empty last segment in a rule is a trailing slash and is literal.
  The rules of one `allow` list are pairwise different; a duplicate makes the mandate MANDATE_MALFORMED (fail closed).

**Request target** is canonicalised the same way, then matched; any failure makes the request **unmatchable**: no rule ever covers it
and it is judged as unlisted (asked, or denied under `unlisted: "deny"`). Canonicalisation:
1. method: 1..16 ASCII letters, upper-cased; anything else unmatchable;
2. host: ASCII only (else unmatchable: no IDNA mapping in the core, so no homograph is ever "equal"); lower-cased; ONE trailing dot
   removed; label rules as above; a name whose labels are all digits must be a canonical dotted IPv4 (so `127.1`, `0x7f.0.0.1`,
   `2130706433`, `010.0.0.1` are unmatchable), a name whose last label is all digits otherwise is unmatchable; `[` (IPv6) unmatchable;
3. port: explicit, 1..65535, no leading zeros; a target without a port is unmatchable (no default on the request side, so `:80` and
   `:443` can never be confused);
4. path, per segment between `/`:
   - raw characters only from RFC 3986 `pchar` (unreserved, sub-delims, `:`, `@`) and `%`; anything else (space, `\`, `?`, `#`, non-ASCII,
     control) -> unmatchable;
   - `%XX` must be two hex digits; an octet that is unreserved is decoded (`%61` -> `a`, `%2e` -> `.`), every other one is kept with
     upper-case hex (`%c3%a9` -> `%C3%A9`);
   - encoded `/` (`%2F`), `\` (`%5C`), `%` (`%25`, double encoding), controls (`%00`-`%1F`, `%7F`) -> unmatchable: a server that
     decodes them would route to a different resource than the one the rule names;
   - the octets of the segment must be valid UTF-8 (strict: overlong forms such as `%C0%AE` are unmatchable), NFKC-stable (fullwidth
     `%EF%BC%8E` `．` is unmatchable) and free of characters of the Unicode general categories Cf (format, bidi marks), Cc (control),
     Zl (U+2028), Zp (U+2029), Co (private use), Cn (unassigned) and Cs (surrogates); NFKC and the categories are those of
     Unicode 16.0 (a verifier on another Unicode version is not conformant);
   - a segment whose part before the first `;` decodes to `.` or `..` is unmatchable (`..`, `.%2e`, `..;`, `%2e%2e%3Bx` - the Tomcat
     `..;/` bypass);
   - an empty segment that is not the last one (`//`) is unmatchable.
5. Length: a target (the whole `recipient` string, and the path alone) longer than 8192 characters is unmatchable.
6. Matching: method equal (or rule `*`), port equal, host equal (or the suffix rule above), path segments equal one by one (`*` = one
   non-empty segment, final `**` = one or more segments, an empty trailing one included). Comparison is byte-exact on the canonical forms; the path is case-sensitive (a
   case-insensitive server can only make a request NOT match, never match a rule it was not written for).

The reference server canonicalises what the owner types (lower-case host, upper-case method and hex, `:443` dropped, unreserved octets
decoded) and refuses what cannot be made canonical; the signing page shows the canonical text, which is what is signed and matched.

## PH-5. Decision (Section 6.4, step 10; tri-state 6.2)

`http` (permission `hp`):
1. any protected data in `A.data` -> `deny DATA_FORBIDDEN` (before everything else; step 12 does not apply, as for `publish`/`command`);
2. `hp` is `true` (malformed) -> `deny CLASS_DENIED`; `hp` = `false` was returned by step 8 (`CLASS_DENIED`);
3. `hp.allow` covers the canonical target (PH-4) -> `allow OK`;
4. `hp.unlisted` is `"deny"` -> `deny RESOURCE`; otherwise (absent, null, `"ask"`, `hp` absent or null) -> `defer ESCALATE_HTTP`.
Unspecified is never `OK_UNSPECIFIED`. Steps 12a/13 (count limits) apply as to every class.

Reason codes: `ESCALATE_HTTP` joins the `defer` row; `RESOURCE` also comes from `http`. Appendix I: `http` is a non-money (`access`)
class: a team policy that requires an access signer is not bypassed by a mandate granting only `http`.

## PH-6. Attacks and what stops them

| attack | defence |
|---|---|
| prefix escape `/repos/a/app/../../admin`, `/app/%2e%2e/`, `/app/..;/admin`, `/app/.%2E/` | dot segments (also with `;params`, encoded) make the target unmatchable; rules have no partial-segment prefix, only whole segments |
| encoded slash / backslash `/app/x%2F..%2F..%2Fadmin`, `\..\` | `%2F`, `%5C`, raw `\` unmatchable |
| double encoding `%252e%252e` | `%25` unmatchable |
| case `API.GitHub.com`, `get` | host and method case-folded (ASCII); hex upper-cased; the path is NOT folded: a different case can only miss a rule |
| encoding of ordinary letters `/rep%6Fs/` | unreserved octets decoded before comparison: the same target as `/repos/` |
| overlong UTF-8 `%C0%AE`, fullwidth `．`, bidi marks | strict UTF-8, NFKC-stable, no Cf/Cc/Zl/Zp/Co/Cn/Cs (Unicode 16.0): unmatchable |
| IDN / homograph `аpple.com` (Cyrillic) | non-ASCII hosts unmatchable; rules are ASCII; punycode compared byte-exact (`xn--pple-43d.com` != `apple.com`) |
| trailing dot `api.github.com.` | one trailing dot removed (same name in DNS) |
| numeric IP forms `127.1`, `0x7f.1`, `2130706433`, `010.0.0.1` | unmatchable; only the canonical dotted quad matches |
| default port `api.github.com:80` vs a rule written without a port | request port always explicit; rule without port = 443 only |
| user info `user@host`, IPv6 `[::1]` | not in the host grammar: unmatchable |
| query `GET /search?q=...&delete=1` | the rule allows the endpoint with ANY query and body (said on the page); both are in the request hash, both go through DLP (a secret or protected data is denied before the list) |
| method override `X-HTTP-Method-Override: DELETE` on an allowed `POST` | headers are not bound; the reference module refuses a selected request that carries a method-override header (`witness_method_override`) |
| redirect (3xx) to another host / path | the witness judges one request; the client's follow-up request goes through the proxy again and is judged anew (a redirect cannot widen a rule). An approval is consumed by the request it was given for |
| replay of an approval for a different request | unchanged: the approval signs the request hash (target, query, body hash, sandbox) and is consumed once |
| an agent forging the target | the target comes from the proxy (OpenShell `HttpRequestTarget`), not from the agent; the agent cannot reach the witness key (it lives in the middleware's environment) |
| old implementation meeting `permissions.http` or class `http` | `MANDATE_MALFORMED` / `CLASS_UNKNOWN`: fail closed (PH-8) |

What this does NOT stop (stated on the approval page / in the docs): what an allowed endpoint does with its body (a `POST /graphql`
rule allows every mutation); a host whose DNS the agent can influence (the proxy's network policy decides where a name goes); a
server that is case-insensitive or decodes beyond RFC 3986 in a way that makes two DIFFERENT canonical targets one resource - such a
target can only match a rule that names it.

## PH-7. Approval page and mandate text

Mandate: "HTTP requests: run without asking: GET api.github.com/repos/acme/app/** ...; other requests need your approval" (or "are
refused"); unspecified: "every request needs your approval". Approval of a deferred `http` action is a phone-level approval (it sends
data out of the machine).

## PH-8. Compatibility

- Mandates without `http`: unchanged; every `http` action is `defer ESCALATE_HTTP`. Nothing that -05/-06 decides for other classes changes.
- An older witness or verifier (implementation A before this change, B, C) rejects a mandate with `permissions.http`
  (`MANDATE_MALFORMED`, unknown permission key) and answers `CLASS_UNKNOWN` for an `http` action: a receipt of class `http` is
  `VERDICT_NOT_REPRODUCIBLE` there, never a false "valid". The mandate version string stays `deus-aar-0.1` (as for `command`).
- Tool maps are bound to the mandate by hash: an agent created with the `publish` map of the module keeps it; a new map needs a new signed
  mandate. The module's old `publish` mode is not supported any more (it was a prototype, never deployed).
- The client library does not re-run decisions (it checks the receipt signature and the request hash): no client change is needed.

## PH-9. What implementations B and C will need (not done here)

Port `httpcanon.py` (about 150 lines, no dependencies beyond UTF-8 decoding and NFKC), add `http` to classes, count classes, permission
keys (`allow` list of canonical rules, `unlisted` ask/deny), the step-10 rule of PH-5, the access tier, and run `svidetel_v4/test_v49.py`
cases as vectors.
