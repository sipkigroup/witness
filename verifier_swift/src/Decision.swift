// §6.4 evaluation algorithm, implemented from the text of draft-deus-aar-02 only; -05 additions (step 4a, `pass`,
// ask_over money tiers in step 10, counter rule 12a, combination 13 with K) from the text of -05 only.
import Foundation

struct Verdict: Equatable { let decision: String; let reason: String }
func allow(_ r: String) -> Verdict { Verdict(decision: "allow", reason: r) }
func deny(_ r: String) -> Verdict { Verdict(decision: "deny", reason: r) }
func deferV(_ r: String) -> Verdict { Verdict(decision: "defer", reason: r) }

let REGISTERED_CLASSES: Set<String> = ["message", "file", "disclosure", "purchase", "sale", "refund", "meeting", "delete", "publish", "pass", "http"]   // -05 §5.6: `pass`; PROPOSAL-08-http: `http`
let MONETARY: Set<String> = ["purchase", "sale", "refund"]
let MAX_AMOUNT: Int64 = 1_000_000_000_000_000   // 10^15, allowed (§5.2)

/// §5.5: only `city` is registered non-protected; every other label (byte-exact) is protected.
func isProtected(_ label: String) -> Bool { return Array(label.utf8) != Array("city".utf8) }

struct LedgerView {
    var committedMandate: Int64 = 0
    var committedPrincipal: Int64 = 0
    var ceiling: Int64? = nil
    var revoked: Bool = false
    var counts: [String: Int64] = [:]   // -05 §7.3 count(M, c, t) per class c (earlier allow/defer RECEIPTs in the window)
}

/// -05 §6.1 / §6.9: `ask_over` member value, null-safe (absent = null)
func askOver(_ M: V, _ k: String) -> V? { let a = M["ask_over"]; if a == nil || a!.isNull { return nil }; let x = a![k]; return (x == nil || x!.isNull) ? nil : x }

/// Options that switch between two readings where -01 is ambiguous (reported as AMBIGUITY-C-n).
struct Options {
    /// -03 §6.1 (C2-1 closed): every `?` member also accepts null. `--cddl-02-literal` restores the literal -02 CDDL
    /// (null rejected where the -02 CDDL type had no `/ null`) for comparison only.
    var cddlLiteral = false
}
var OPT = Options()

// MARK: recipients (§5.4, §6.2)
func recipientsUnspecified(_ p: V?) -> Bool {
    guard let p = p, !p.isNull else { return true }
    guard p.isMap else { return false }
    return absentOrNull(p["to"]) && absentOrNull(p["domains"])
}

func canonList(_ v: V?) -> [String]? {
    guard let a = v?.arr else { return nil }
    return a.compactMap { $0.str }.compactMap { canonRecipient($0, angle: false) }
}

func recipientMatches(_ spec: V?, _ raw: String) -> Bool {
    guard let spec = spec, spec.isMap else { return false }
    guard let c = canonRecipient(raw) else { return false }          // invalid recipient matches nothing
    if let to = spec["to"] {
        if to.str == "*" { return true }
        if let l = canonList(to), l.contains(where: { Array($0.utf8) == Array(c.utf8) }) { return true }
    }
    if let doms = spec["domains"]?.arr?.compactMap({ $0.str }).compactMap({ canonDomain($0) }), let at = c.lastIndex(of: "@") {
        let d = String(c[c.index(after: at)...])
        if doms.contains(where: { Array($0.utf8) == Array(d.utf8) }) { return true }
    }
    return false
}

/// §6.5: recipient in an explicit `to` list of another of message/file/disclosure.
func inCircle(_ m: V, ownClass: String, _ raw: String) -> Bool {
    guard m["named_circle"]?.boolean == true, let c = canonRecipient(raw) else { return false }
    for cls in ["message", "file", "disclosure"] where cls != ownClass {
        if let l = canonList(m["permissions"]?[cls]?["to"]), l.contains(where: { Array($0.utf8) == Array(c.utf8) }) { return true }
    }
    return false
}

// MARK: resource patterns (§5.6.1)
func resourceMatches(_ entries: V?, _ r: String) -> Bool {
    guard let list = entries?.arr else { return false }
    let rb = Array(r.utf8)
    let hasDotSeg = r.split(separator: "/", omittingEmptySubsequences: false).contains { $0 == "." || $0 == ".." }
    for e in list {
        guard let s = e.str else { continue }
        let eb = Array(s.utf8)
        if eb == rb { return true }
        if eb.count >= 2, eb.last == UInt8(ascii: "*") {
            let prefix = Array(eb.dropLast())
            if !hasDotSeg && rb.count >= prefix.count && Array(rb[0..<prefix.count]) == prefix { return true }
        }
    }
    return false
}

// MARK: the decision function
func decide(mandate M: V?, mandateSigValid: Bool, action A: V, now: Int64, state S: LedgerView) -> Verdict {
    // 1
    guard let M = M, M.isMap else { return deny("NO_MANDATE") }
    // 2
    if !mandateSigValid { return deny("MANDATE_SIG") }
    // 3
    if A["agent"] == nil || !(A["agent"]! == (M["agent"] ?? .null)) { return deny("AGENT_MISMATCH") }
    // 4
    let nbf = M["nbf"]?.int ?? Int64.max, exp = M["exp"]?.int ?? Int64.min
    if now < nbf || now > exp || S.revoked { return deny("EXPIRED") }
    // 4a (-05): tool map. A.toolmap_sha256 (absent = null) must equal M.toolmap_sha256 (absent = null), byte-exact;
    // a `pass` needs a bound map (M.toolmap_sha256 not null)
    let atm = A["toolmap_sha256"] ?? .null, mtm = M["toolmap_sha256"] ?? .null
    if !(atm == mtm) || (A["class"]?.str == "pass" && mtm.isNull) { return deny("TOOLMAP_CHANGED") }
    // 5
    guard let cls = A["class"]?.str, REGISTERED_CLASSES.contains(cls) else { return deny("CLASS_UNKNOWN") }
    let monetary = MONETARY.contains(cls)
    // 6
    var amount: Int64 = 0
    if let a = A["amount"] {
        guard let x = a.int, x >= 0, x <= MAX_AMOUNT else { return deny("BAD_AMOUNT") }   // float, negative, > 10^15
        amount = x
        if !monetary && x != 0 { return deny("BAD_AMOUNT") }                    // -02 §5.2: non-monetary: absent or 0
    } else if monetary { return deny("BAD_AMOUNT") }
    if monetary {
        guard let cur = A["currency"]?.str, let mc = M["currency"]?.str, Array(cur.utf8) == Array(mc.utf8) else { return deny("BAD_AMOUNT") }
    }
    // 7
    let data: [String] = (A["data"]?.arr ?? []).compactMap { $0.str }
    let forbidden: [String] = (M["forbidden_data"]?.arr ?? []).compactMap { $0.str }
    if data.contains(where: { d in forbidden.contains { Array($0.utf8) == Array(d.utf8) } }) { return deny("DATA_FORBIDDEN") }
    // 8
    let perms = M["permissions"] ?? .map([])
    let P = perms[cls]
    let protectedData = data.contains(where: isProtected)
    if P?.boolean == false { return deny("CLASS_DENIED") }
    // -02 step 8: a disclosure without protected data is evaluated under `message`; message=false -> CLASS_DENIED
    if cls == "disclosure" && !protectedData && perms["message"]?.boolean == false { return deny("CLASS_DENIED") }
    // 9
    if cls == "meeting" && A["principal_present"]?.boolean != true { return deny("UNATTENDED_MEETING") }
    // 10
    let rcpt = A["recipient"]?.str ?? ""
    // -02 step 10 (and §5.4 step 1): for message/file/disclosure an invalid recipient is RECIPIENT in every permission state
    if ["message", "file", "disclosure"].contains(cls) && canonRecipient(rcpt) == nil { return deny("RECIPIENT") }
    var R: Verdict
    let rule = (cls == "disclosure" && !protectedData) ? "message" : cls
    switch rule {
    case "meeting":
        R = P?.boolean == true ? allow("OK") : allow("OK_UNSPECIFIED")
    case "message":
        let MP = perms["message"]
        if recipientsUnspecified(MP) { R = allow("OK_UNSPECIFIED") }
        else if recipientMatches(MP, rcpt) { R = allow("OK") }
        else if inCircle(M, ownClass: "message", rcpt) { R = allow("OK_CIRCLE") }
        else { R = deny("RECIPIENT") }
    case "disclosure":
        if recipientsUnspecified(P) { R = allow("OK_UNSPECIFIED") }
        else if recipientMatches(P, rcpt) { R = allow("OK") }
        else { R = deny("RECIPIENT") }
    case "delete":
        let reversible = A["reversible"]?.boolean == true
        if absentOrNull(P) { R = reversible ? deferV("ESCALATE_DELETE") : deny("IRREVERSIBLE_DELETE") }
        else if !resourceMatches(P?["targets"], rcpt) { R = deny("RESOURCE") }
        else if !reversible && P?["allow_irreversible"]?.boolean != true { R = deny("IRREVERSIBLE_DELETE") }
        else { R = allow("OK") }
    case "publish":
        // step 12 does not apply to publish; -05: the counter rule 12a does (count-class includes "publish"), so the
        // result goes through steps 11-13 instead of returning here (AMBIGUITY-05-1)
        if protectedData { return deny("DATA_FORBIDDEN") }
        if absentOrNull(P) || absentOrNull(P?["channels"]) { R = deferV("ESCALATE_PUBLISH") }
        else if !resourceMatches(P?["channels"], rcpt) { return deny("RESOURCE") }
        else { R = allow("OK") }
    case "http":
        // PROPOSAL-08-http PH-5: protected data first (step 12 does not apply); `true` is malformed; listed -> allow;
        // `unlisted: deny` -> RESOURCE; otherwise ask. Counter rule 12a applies as to every class.
        if protectedData { return deny("DATA_FORBIDDEN") }
        if P?.boolean == true { return deny("CLASS_DENIED") }
        let hrules = (P?["allow"]?.arr ?? []).compactMap { $0.str }
        if P?["allow"]?.arr != nil && httpAllowed(hrules, rcpt) { R = allow("OK") }
        else if P?["unlisted"]?.str == "deny" { return deny("RESOURCE") }
        else { R = deferV("ESCALATE_HTTP") }
    case "pass":
        // -05 §6.4 step 10 / §8.6: protected data -> DATA_FORBIDDEN, else OK_PASS (step 4a already required the map)
        if protectedData { return deny("DATA_FORBIDDEN") }
        R = allow("OK_PASS")
    case "file":
        if absentOrNull(P) || recipientsUnspecified(P) { R = deferV("ESCALATE_FILE") }
        else if recipientMatches(P, rcpt) { R = allow("OK") }
        else if inCircle(M, ownClass: "file", rcpt) { R = allow("OK_CIRCLE") }
        else { R = deny("RECIPIENT") }
    case "refund":
        if P?.boolean != true { R = deferV("ESCALATE_MONEY") }
        else if let x = askOver(M, "amount")?.int, amount > x { R = deferV("ESCALATE_MONEY") }     // -05 §6.9
        else { R = allow("OK") }
    case "sale":
        if absentOrNull(P) || absentOrNull(P?["min_price"]) { R = deferV("ESCALATE_MONEY") }
        else if let mp = P?["min_price"]?.int, amount < mp { R = deny("PRICE") }
        else { R = allow("OK") }
    case "purchase":
        let maxPA = P?["max_per_action"]?.int, budget = P?["budget"]?.int
        if let mx = maxPA, amount > mx { R = deny("PER_ACTION_LIMIT") }
        else if let b = budget, S.committedMandate + amount > b { R = deny("BUDGET") }
        else if let c = S.ceiling, S.committedPrincipal + amount > c { R = deny("CEILING") }
        else if absentOrNull(P) || maxPA == nil || budget == nil { R = deferV("ESCALATE_MONEY") }
        else if let x = askOver(M, "amount")?.int, amount > x { R = deferV("ESCALATE_MONEY") }             // -05 §6.9, "up to X" inclusive
        else if let x = askOver(M, "committed")?.int, S.committedMandate + amount > x { R = deferV("ESCALATE_MONEY") }
        else { R = allow("OK") }
    default:
        return deny("CLASS_UNKNOWN")
    }
    // 11
    if R.decision == "deny" { return R }
    // 12
    var D: Verdict? = nil
    if protectedData && rule != "publish" && rule != "pass" && rule != "http" {
        let DP = perms["disclosure"]
        if DP?.boolean == false { D = deny("DATA_FORBIDDEN") }
        else if absentOrNull(DP) || absentOrNull(DP?["data"]) { D = deny("DATA_NOT_PERMITTED") }
        else {
            let granted = (DP?["data"]?.arr ?? []).compactMap { $0.str }
            if data.filter(isProtected).contains(where: { d in !granted.contains { Array($0.utf8) == Array(d.utf8) } }) { D = deny("DATA_FORBIDDEN") }
            else if recipientsUnspecified(DP) { D = deferV("ESCALATE_DATA") }
            else if !recipientMatches(DP, rcpt) { D = deny("RECIPIENT") }
        }
    }
    // 12a (-05): counter rule K
    var K: Verdict? = nil
    if let tier = askOver(M, "count")?[cls], tier.isMap {
        let n = S.counts[cls] ?? 0
        if let mx = tier["max"]?.int, !(tier["max"]!.isNull), n + 1 > mx { K = deny("COUNT_LIMIT") }
        else if let ao = tier["ask_over"]?.int, !(tier["ask_over"]!.isNull), n + 1 > ao { K = deferV("ESCALATE_COUNT") }
    }
    // 13 (-05: with K)
    if let D = D, D.decision == "deny" { return D }
    if let K = K, K.decision == "deny" { return K }
    if let D = D, D.decision == "defer", R.decision == "allow" { return D }
    if let K = K, K.decision == "defer", R.decision == "allow" { return K }
    return R
}

func riskOf(_ A: V) -> String {
    let cls = A["class"]?.str ?? ""
    let data = (A["data"]?.arr ?? []).compactMap { $0.str }
    switch cls {
    case "message", "disclosure": return data.contains(where: isProtected) ? "disclosure" : "low"
    case "file", "publish", "http": return "disclosure"
    case "purchase", "sale", "refund": return "monetary"
    case "meeting": return A["principal_present"]?.boolean == true ? "low" : "irreversible"
    case "delete": return A["reversible"]?.boolean == true ? "low" : "irreversible"
    case "pass": return "low"
    default: return "irreversible"
    }
}
