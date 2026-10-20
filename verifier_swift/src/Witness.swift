// Abstract witness + stateful tool for `sequence` vectors (§6.6, §6.7, §7, §8.4).
// State is ALWAYS derived from the ledger (§7.2): `restart` rebuilds it by replay.
import Foundation

struct WEntry { let type: String; let body: V; let t: Int64 }

final class Witness {
    let pinned: String
    var ledger: [WEntry] = []
    var st = LedgerState()
    var clock: Int64 = 0
    var toolAccepted: Set<String> = []     // tool replay set, identity = (iss, sub); one witness here -> sub

    init(pinned: String) { self.pinned = pinned }

    func append(_ type: String, _ body: V) { ledger.append(WEntry(type: type, body: body, t: clock)) }

    /// §7.4 (b): RELEASE expired at the first operation after now > expires, before any other entry
    func sweep() {
        for r in st.expiredActive(now: clock) {
            append("RELEASE", .map([(.text("receipt"), .text(r.id)), (.text("cause"), .text("expired"))]))
            st.receipts[r.id]!.res = .released
        }
    }

    /// Rebuild state from ledger entries only (restart, second instance).
    func rebuild() {
        var s = LedgerState()
        for e in ledger {
            switch e.type {
            case "MANDATE": let m = e.body["mandate"]!; s.mandates[m["id"]!.str!] = (m, nil); if s.currency == nil { s.currency = m["currency"]?.str }
            case "CEILING": s.ceiling = (e.body["amount"]!.int!, e.body["window_s"]!.int!)
            case "REVOCATION": s.revoked.insert(e.body["mandate"]!.str!)
            case "RECEIPT":
                let v = Verdict(decision: e.body["verdict"]!.str!, reason: e.body["reason"]!.str!)
                s.addReceipt(id: e.body["id"]!.str!, mandateId: e.body["mandate"]!.str!, action: e.body["action"]!,
                             verdict: v, t: e.t, ttl: e.body["ttl"]!.int!, seq: 0)
            case "APPROVAL":
                let rid = e.body["receipt"]!.str!
                if e.body["approved"]?.boolean == true { s.receipts[rid]!.approved = true } else { s.receipts[rid]!.refused = true }
            case "CONSUME":
                let rid = e.body["receipt"]!.str!
                s.receipts[rid]!.consumed = true
                if s.receipts[rid]!.monetary { s.receipts[rid]!.res = .consumed }
            case "RELEASE": s.receipts[e.body["receipt"]!.str!]!.res = .released
            default: break
            }
        }
        st = s
    }

    func step(_ op: V) -> [String: String] {
        let kind = op["op"]?.str ?? ""
        switch kind {
        case "register_mandate":
            sweep()
            guard op["signed_by"]?.str == pinned else { return ["result": "reject", "reason": "KEY_MISMATCH"] }
            guard let m = op["mandate"], mandateMatchesCDDL(m) else { return ["result": "reject", "reason": "MANDATE_MALFORMED"] }
            // -03 §6.1 consistency (C2-10): principal = the ledger's (pinned key); currency = that of the first MANDATE
            if m["principal"]?.str != pinned { return ["result": "reject", "reason": "MANDATE_MALFORMED"] }
            if let c = st.currency, m["currency"]?.str != c { return ["result": "reject", "reason": "MANDATE_MALFORMED"] }
            let id = m["id"]!.str!
            if st.mandates[id] != nil { return ["result": "reject", "reason": "MANDATE_EXISTS"] }
            append("MANDATE", .map([(.text("mandate"), m)]))
            st.mandates[id] = (m, nil)
            if st.currency == nil { st.currency = m["currency"]?.str }
            return ["result": "accept"]
        case "register_ceiling":
            sweep()
            guard op["signed_by"]?.str == pinned else { return ["result": "reject", "reason": "KEY_MISMATCH"] }
            // -02 §6.3: the signed ceiling map = the op members (harness keys `op`, `signed_by` removed); `v` and
            // `principal` are filled from the ledger when the harness omits them.
            // -03 App. A convention (6): harness members `op`, `signed_by`, `instance` are not members of the ceiling map
            var pairs: [(V, V)] = (op.mapPairs ?? []).filter { !["op", "signed_by", "instance"].contains($0.0.str ?? "") }
            if op["v"] == nil { pairs.append((.text("v"), .text("deus-aar-0.1"))) }
            if op["principal"] == nil { pairs.append((.text("principal"), .text(pinned))) }
            let c: V = .map(pairs)
            guard ceilingMatchesCDDL(c) else { return ["result": "reject", "reason": "CEILING_MALFORMED"] }
            // -04 §5.2/§6.3 (C3-2): the ceiling currency MUST be the ledger's; a CEILING before the first MANDATE has no
            // ledger currency and is CEILING_MALFORMED (only a MANDATE fixes the currency)
            guard let cur = st.currency, c["currency"]?.str == cur else { return ["result": "reject", "reason": "CEILING_MALFORMED"] }
            append("CEILING", .map([(.text("id"), c["id"]!), (.text("amount"), c["amount"]!), (.text("currency"), c["currency"]!),
                                    (.text("window_s"), c["window_s"]!)]))
            st.ceiling = (c["amount"]!.int!, c["window_s"]!.int!)
            return ["result": "accept"]
        case "authorize":
            let action = op["action"] ?? .map([])
            if let t = action["t"]?.int, t > clock { clock = t }       // harness: clock reads at least action.t
            sweep()
            let rid = op["id"]?.str ?? ""
            if st.receipts[rid] != nil { return ["result": "reject", "reason": "DUPLICATE_RECEIPT_ID"] }
            let mid = op["mandate"]?.str ?? ""
            let md = st.mandates[mid]
            let v = decide(mandate: md?.m, mandateSigValid: true, action: action, now: clock, state: st.view(mandate: mid, at: clock))
            let ttl = op["ttl"]?.int ?? 0
            append("RECEIPT", .map([(.text("id"), .text(rid)), (.text("mandate"), .text(mid)), (.text("action"), action),
                                    (.text("verdict"), .text(v.decision)), (.text("reason"), .text(v.reason)), (.text("ttl"), V.i(ttl))]))
            st.addReceipt(id: rid, mandateId: mid, action: action, verdict: v, t: clock, ttl: ttl, seq: Int64(ledger.count - 1))
            return ["verdict": v.decision, "reason": v.reason]
        case "tool_present":
            sweep()
            // §8.4 checks in order
            guard let rid = op["receipt"]?.str, let r = st.receipts[rid] else { return ["result": "reject", "reason": "NO_RECEIPT"] }
            if !r.effectiveAllow { return ["result": "reject", "reason": "NOT_ALLOWED"] }                // 3
            if op["audience_mismatch"]?.boolean == true { return ["result": "reject", "reason": "AUDIENCE"] }  // 4
            if let req = op["request"], sha256(CBOREncoder.encode(req)) != sha256(CBOREncoder.encode(r.action)) {
                return ["result": "reject", "reason": "REQUEST_MISMATCH"] }                                  // 5
            if toolAccepted.contains(rid) { return ["result": "reject", "reason": "REPLAY"] }               // 6
            if clock > r.expires { return ["result": "reject", "reason": "RECEIPT_EXPIRED"] }               // 7
            // 8: abstract receipts are always in the ledger
            if r.monetary && r.res != .active { return ["result": "reject", "reason": "RESERVATION_INACTIVE"] } // 9
            toolAccepted.insert(rid)
            append("CONSUME", .map([(.text("receipt"), .text(rid))]))
            st.receipts[rid]!.consumed = true
            if r.monetary { st.receipts[rid]!.res = .consumed }
            return ["result": "accept"]
        case "agent_report":
            return ["result": "ignored"]          // §7.4: agent statements never release
        case "tool_report":
            sweep()
            guard op["executed"]?.boolean == false, let rid = op["receipt"]?.str, let r = st.receipts[rid], r.res == .active else { return ["result": "ignored"] }
            append("RELEASE", .map([(.text("receipt"), .text(rid)), (.text("cause"), .text("tool_not_executed"))]))
            st.receipts[rid]!.res = .released
            return ["result": "released"]
        case "restart":
            rebuild(); return ["result": "ok"]
        case "clock":
            let t = op["t"]?.int ?? 0
            if t < clock { return ["result": "clamped"] }
            clock = t; return ["result": "ok"]
        case "approve":
            sweep()
            guard op["signed_by"]?.str == pinned else { return ["result": "reject", "reason": "APPROVAL_SIG"] }
            // -04 §6.6/§6.7 (C3-9): state test includes "its mandate is not revoked"
            guard let rid = op["receipt"]?.str, let r = st.receipts[rid], r.verdict == "defer", !r.approved, !r.refused,
                  clock <= r.expires, !st.revoked.contains(r.mandateId) else { return ["result": "reject", "reason": "NOT_DEFERRED"] }
            let approved = op["approved"]?.boolean ?? true
            append("APPROVAL", .map([(.text("receipt"), .text(rid)), (.text("approved"), .bool(approved))]))
            if approved { st.receipts[rid]!.approved = true; return ["result": "accept", "verdict": "allow"] }
            st.receipts[rid]!.refused = true
            if r.res == .active {
                append("RELEASE", .map([(.text("receipt"), .text(rid)), (.text("cause"), .text("refused"))]))
                st.receipts[rid]!.res = .released
            }
            return ["result": "accept", "verdict": "refused"]
        case "revoke":
            sweep()
            guard op["signed_by"]?.str == pinned else { return ["result": "reject", "reason": "KEY_MISMATCH"] }
            guard let mid = op["mandate"]?.str, st.mandates[mid] != nil else { return ["result": "reject", "reason": "MANDATE_UNKNOWN"] }
            append("REVOCATION", .map([(.text("mandate"), .text(mid))]))
            st.revoked.insert(mid)
            for id in st.receiptOrder where st.receipts[id]!.mandateId == mid && st.receipts[id]!.res == .active {
                append("RELEASE", .map([(.text("receipt"), .text(id)), (.text("cause"), .text("revoked"))]))
                st.receipts[id]!.res = .released
            }
            return ["result": "accept"]
        default:
            return ["result": "unsupported-op"]
        }
    }
}
