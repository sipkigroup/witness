// Ledger state (§7.3, §7.4) and the mandate CDDL check (§6.1).
import Foundation

enum ResState { case none, active, consumed, released }

struct Rcpt {
    let id: String
    let mandateId: String
    let action: V
    var verdict: String
    let reason: String
    let t: Int64
    let ttl: Int64
    var expires: Int64 { t + ttl }
    let amount: Int64
    let monetary: Bool            // -02: true only for `purchase` (the class that holds a reservation, §8.4 check 9)
    var res: ResState
    var approved = false          // APPROVAL approved:true seen
    var refused = false           // APPROVAL approved:false seen
    var consumed = false
    let seq: Int64
    var effectiveAllow: Bool { verdict == "allow" || (verdict == "defer" && approved) }
}

struct LedgerState {
    var mandates: [String: (m: V, hash: [UInt8]?)] = [:]
    var revoked: Set<String> = []
    var ceiling: (amount: Int64, window: Int64)? = nil
    var receipts: [String: Rcpt] = [:]
    var receiptOrder: [String] = []
    var currency: String? = nil       // -03 §5.2: the currency of the first MANDATE

    func committed(mandate mid: String, at t: Int64) -> Int64 {
        guard let w = mandates[mid]?.m["budget_window_s"]?.int else { return 0 }
        return sum(at: t, window: w) { $0.mandateId == mid }
    }
    func committedPrincipal(at t: Int64) -> Int64 {
        let w = ceiling?.window
        return sum(at: t, window: w) { _ in true }
    }
    private func sum(at t: Int64, window: Int64?, _ f: (Rcpt) -> Bool) -> Int64 {
        var s: Int64 = 0
        for r in receipts.values where f(r) && (r.res == .active || r.res == .consumed) {
            if let w = window { if !(r.t > t - w && r.t <= t) { continue } } else if r.t > t { continue }
            s += r.amount
        }
        return s
    }
    /// -05 §7.3: count(M, c, t) = RECEIPT entries for M of class c whose RECORDED verdict is allow or defer and whose
    /// entry t is in (t - budget_window_s, t]. A refused or expired deferral still counts; a deny does not.
    func counts(mandate mid: String, at t: Int64) -> [String: Int64] {
        guard let w = mandates[mid]?.m["budget_window_s"]?.int else { return [:] }
        var c: [String: Int64] = [:]
        for r in receipts.values where r.mandateId == mid && (r.verdict == "allow" || r.verdict == "defer") && r.t > t - w && r.t <= t {
            if let cls = r.action["class"]?.str { c[cls, default: 0] += 1 }
        }
        return c
    }
    func view(mandate mid: String, at t: Int64) -> LedgerView {
        return LedgerView(committedMandate: committed(mandate: mid, at: t),
                          committedPrincipal: committedPrincipal(at: t),
                          ceiling: ceiling?.amount, revoked: revoked.contains(mid), counts: counts(mandate: mid, at: t))
    }
    func expiredActive(now: Int64) -> [Rcpt] {
        return receiptOrder.compactMap { receipts[$0] }.filter { $0.res == .active && now > $0.expires }
    }
    mutating func addReceipt(id: String, mandateId: String, action: V, verdict: Verdict, t: Int64, ttl: Int64, seq: Int64) {
        let cls = action["class"]?.str ?? ""
        let amt = action["amount"]?.int ?? 0
        let reserve = cls == "purchase" && (verdict.decision == "allow" || verdict.decision == "defer")   // -02 §7.4: only purchase
        receipts[id] = Rcpt(id: id, mandateId: mandateId, action: action, verdict: verdict.decision, reason: verdict.reason,
                            t: t, ttl: ttl, amount: reserve ? amt : 0, monetary: cls == "purchase", res: reserve ? .active : .none, seq: seq)
        receiptOrder.append(id)
    }
}

// MARK: CDDL of §6.1 (mandate)
func isUint(_ v: V?) -> Bool { if case .uint = v { return true }; return false }
func isTstrArray(_ v: V?) -> Bool { guard let a = v?.arr else { return false }; return a.allSatisfy { $0.str != nil } }
func onlyKeys(_ m: V, _ allowed: Set<String>) -> Bool {
    guard let p = m.mapPairs else { return false }
    return p.allSatisfy { k, _ in k.str != nil && allowed.contains(k.str!) }
}

/// -02 §6.1: recipients = { ? "to": "*" / [* tstr] / null, ? "domains": [* tstr] / null }; disclosure adds ? "data".
func recipientsOK(_ v: V, disclosure: Bool) -> Bool {
    guard v.isMap, onlyKeys(v, disclosure ? ["to", "domains", "data"] : ["to", "domains"]) else { return false }
    if let to = v["to"], !(to.str == "*" || to.isNull || isTstrArray(to)) { return false }
    if let d = v["domains"], !(d.isNull || isTstrArray(d)) { return false }
    if disclosure, let d = v["data"], !(d.isNull || isTstrArray(d)) { return false }
    return true
}

func optUintOrNull(_ m: V, _ k: String) -> Bool { guard let x = m[k] else { return true }; return x.isNull || isUint(x) }

/// -02 §6.1 CDDL, literal. `--lenient-cddl` (AMBIGUITY-C2-1) follows the prose instead ("absent and null mean the same
/// everywhere"): an optional member whose CDDL type has no `/ null` (`named_circle`, `pin_source`, `payment_mandate_ref`,
/// `permit_ref`, `allow_irreversible`) may be `null`. Literal mode rejects `null` there (MANDATE_MALFORMED).
func nullOK(_ m: V, _ k: String) -> Bool { !OPT.cddlLiteral && m[k]?.isNull == true }
/// -05 §6.1: count-class and the ask-over map.
let COUNT_CLASSES: Set<String> = ["message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish", "pass"]
func askOverOK(_ a: V) -> Bool {
    if a.isNull { return true }
    guard a.isMap, onlyKeys(a, ["amount", "committed", "count"]), optUintOrNull(a, "amount"), optUintOrNull(a, "committed") else { return false }
    if let c = a["count"], !c.isNull {
        // `{ + count-class => count-tier }`: at least one member
        guard let pairs = c.mapPairs, !pairs.isEmpty else { return false }
        for (k, t) in pairs {
            guard let ks = k.str, COUNT_CLASSES.contains(ks), t.isMap, onlyKeys(t, ["ask_over", "max"]),
                  optUintOrNull(t, "ask_over"), optUintOrNull(t, "max") else { return false }
        }
    }
    return true
}
/// -05 §6.1: `toolmap_sha256: bstr .size 32 / null`. Abstract mode (symbolic hashes, App. A) accepts a tstr as the
/// symbolic hash, as for every other hash of an abstract vector (AMBIGUITY-05-4).
var ABSTRACT_HASHES = false
func toolmapOK(_ v: V) -> Bool {
    if v.isNull { return true }
    if let b = v.bytes { return b.count == 32 }
    return ABSTRACT_HASHES && v.str != nil
}

func mandateMatchesCDDL(_ m: V) -> Bool {
    guard m.isMap else { return false }
    let req: Set<String> = ["v", "id", "principal", "agent", "nbf", "exp", "currency", "budget_window_s", "permissions",
                            "forbidden_data", "key_attestation"]
    let opt: Set<String> = ["named_circle", "pin_source", "payment_mandate_ref", "permit_ref", "ask_over", "toolmap_sha256"]   // -05
    guard onlyKeys(m, req.union(opt)) else { return false }
    for k in req where m[k] == nil { return false }
    guard m["v"]?.str == "deus-aar-0.1", m["id"]?.str != nil, m["principal"]?.str != nil, m["agent"]?.str != nil,
          isUint(m["nbf"]), isUint(m["exp"]), m["currency"]?.str != nil, isUint(m["budget_window_s"]),
          isTstrArray(m["forbidden_data"]),
          let ka = m["key_attestation"]?.str, ["secure-element", "passkey", "software"].contains(ka) else { return false }
    if let nc = m["named_circle"], nc.boolean == nil, !nullOK(m, "named_circle") { return false }          // `? "named_circle": bool` (null not allowed)
    if let ps = m["pin_source"], ps.str == nil, !nullOK(m, "pin_source") { return false }
    if let a = m["ask_over"], !askOverOK(a) { return false }               // -05
    if let t = m["toolmap_sha256"], !toolmapOK(t) { return false }         // -05
    for hr in ["payment_mandate_ref", "permit_ref"] {
        if let h = m[hr], !nullOK(m, hr) { guard h.isMap, h["alg"]?.str == "sha-256", h["digest"]?.bytes != nil, onlyKeys(h, ["alg", "digest", "uri"]) else { return false }
            if let u = h["uri"], u.str == nil { return false } }
    }
    guard let p = m["permissions"], p.isMap,
          onlyKeys(p, ["message", "file", "disclosure", "purchase", "sale", "meeting", "refund", "delete", "publish"]) else { return false }
    for (kv, v) in p.mapPairs! {
        let k = kv.str!
        if v.isNull || v.boolean == false { continue }                         // every permission: `/ false / null`
        switch k {
        case "message", "file": if !recipientsOK(v, disclosure: false) { return false }
        case "disclosure": if !recipientsOK(v, disclosure: true) { return false }
        case "purchase":
            guard v.isMap, onlyKeys(v, ["max_per_action", "budget"]), optUintOrNull(v, "max_per_action"), optUintOrNull(v, "budget") else { return false }
        case "sale":
            guard v.isMap, onlyKeys(v, ["min_price"]), optUintOrNull(v, "min_price") else { return false }
        case "meeting", "refund": if v.boolean != true { return false }
        case "delete":
            guard v.isMap, onlyKeys(v, ["targets", "allow_irreversible"]), isTstrArray(v["targets"]) else { return false }
            if let a = v["allow_irreversible"], a.boolean == nil, !nullOK(v, "allow_irreversible") { return false }
        case "publish":
            guard v.isMap, onlyKeys(v, ["channels"]), isTstrArray(v["channels"]) else { return false }
        default: return false
        }
    }
    return true
}

/// -02 §6.3: all six members REQUIRED, nothing else, window_s >= 1.
func ceilingMatchesCDDL(_ c: V) -> Bool {
    guard c.isMap, onlyKeys(c, ["v", "id", "principal", "amount", "currency", "window_s"]) else { return false }
    guard c["v"]?.str == "deus-aar-0.1", c["id"]?.str != nil, c["principal"]?.str != nil, isUint(c["amount"]),
          c["currency"]?.str != nil, isUint(c["window_s"]), (c["window_s"]?.int ?? 0) >= 1 else { return false }
    return true
}

// MARK: RFC 9162 Merkle tree (§9.1)
func leafHash(_ entryHash: [UInt8]) -> [UInt8] { sha256([0x00] + entryHash) }
func nodeHash(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] { sha256([0x01] + l + r) }
func largestPow2Below(_ n: Int) -> Int { var k = 1; while k << 1 < n { k <<= 1 }; return k }
func mth(_ leaves: ArraySlice<[UInt8]>) -> [UInt8] {
    if leaves.count == 0 { return sha256([]) }
    if leaves.count == 1 { return leafHash(leaves.first!) }
    let k = largestPow2Below(leaves.count)
    let s = leaves.startIndex
    return nodeHash(mth(leaves[s..<s+k]), mth(leaves[(s+k)...]))
}
/// sides of the siblings, leaf to root (RFC 9162 §2.1.3)
func derivedSides(_ m: Int, _ n: Int) -> [String] {
    if n <= 1 { return [] }
    let k = largestPow2Below(n)
    return m < k ? derivedSides(m, k) + ["R"] : derivedSides(m - k, n - k) + ["L"]
}
func rootFromPath(_ entryHash: [UInt8], index: Int, size: Int, path: [(String, [UInt8])]) -> [UInt8]? {
    guard index < size, path.map({ $0.0 }) == derivedSides(index, size) else { return nil }
    var h = leafHash(entryHash)
    for (side, sib) in path { h = side == "L" ? nodeHash(sib, h) : nodeHash(h, sib) }
    return h
}
