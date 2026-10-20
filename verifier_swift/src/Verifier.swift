// §10 third-party verification: entry-major replay, then whole-ledger checks.
import Foundation

struct Entry {
    var seq: Int64?
    var prev: String?          // nil = null
    var hash: String           // symbolic (abstract) or hex of SHA-256 over COSE bytes
    var hashBytes: [UInt8]? = nil
    var t: Int64?
    var type: String
    var body: V
    var sigOK = true           // step 2
    var ledgerOK = true        // step 3 (ledger identifier)
    var raw: [UInt8]? = nil
    var shapeErr: String? = nil  // -03 §7.1 "Shape of the entry": `t`/`type`/`body` wrong or missing, extra member -> MALFORMED (step 4)
}

struct Failure: Error { let reason: String; let at: Int64?; var receipt: String? = nil }

struct CheckpointIn {
    var seq: Int64?            // nil = last entry (abstract)
    var head: String
    var root: [UInt8]?
    var sigOK = true
    var ledgerOK = true
    var anchorDigestMatches: Bool? = nil   // nil = no anchor
    var anchorStatus: String = "none"
}

/// -03 §10 step 9 result for one receipt a tool reports as accepted: nil = included and the ledger RECORDS a decision that
/// lets a tool execute; otherwise NO_INCLUSION / INCLUSION_INVALID / OFFLOG_RECEIPT (computed by the runner).
struct Presented {
    var id: String
    var code: String?
}

// MARK: -02 §7.1 entry body shapes. Returns nil if the body matches, else the code.
func hashLike(_ v: V?, real: Bool) -> Bool { real ? v?.bytes != nil : (v?.bytes != nil || v?.str != nil) }
func optSignedBy(_ b: V) -> Bool { guard let x = b["signed_by"] else { return true }; return x.isNull || x.str != nil }
/// `cose`: absent is NOT a shape error (the specific rule of §7.1/§10 step 4 makes it MANDATE_KEY in real mode, and it
/// is absent by design in abstract mode); present and not a bstr is a shape error. AMBIGUITY-C2-2.
func coseShape(_ b: V) -> Bool { guard let c = b["cose"] else { return true }; return c.bytes != nil }
func bodyShape(_ e: Entry, real: Bool) -> String? {
    let b = e.body
    guard b.isMap else { return e.type == "CEILING" ? "CEILING_MALFORMED" : (e.type == "MANDATE" ? "MALFORMED" : "MALFORMED") }
    switch e.type {
    case "MANDATE":
        guard let m = b["mandate"] else { return "MALFORMED" }
        if !coseShape(b) || !optSignedBy(b) { return "MALFORMED" }
        if let pin = b["pin"] { guard pin.isMap, pin["source"]?.str != nil, pin["principal"]?.str != nil else { return "MALFORMED" } }
        if !mandateMatchesCDDL(m) { return "MANDATE_MALFORMED" }
    case "CEILING":
        guard b["id"]?.str != nil, isUint(b["amount"]), b["currency"]?.str != nil, isUint(b["window_s"]),
              (b["window_s"]?.int ?? 0) >= 1, coseShape(b), optSignedBy(b) else { return "CEILING_MALFORMED" }
    case "REVOCATION":
        guard b["mandate"]?.str != nil, coseShape(b), optSignedBy(b) else { return "MALFORMED" }
    case "RECEIPT":
        guard b["id"]?.str != nil, b["mandate"]?.str != nil, let a = b["action"], a.isMap,
              (a.mapPairs ?? []).allSatisfy({ $0.0.str != nil }),
              let v = b["verdict"]?.str, ["allow", "defer", "deny"].contains(v),
              let r = b["reason"]?.str, isUint(b["ttl"]) else { return "MALFORMED" }
        if let au = b["audience"] { if au.str == nil { return "MALFORMED" } }
        else if !(v == "deny" && r == "NO_MANDATE") { return "MALFORMED" }
    case "APPROVAL":
        guard b["receipt"]?.str != nil, b["approved"]?.boolean != nil, coseShape(b), optSignedBy(b) else { return "MALFORMED" }
    case "CONSUME":
        guard b["receipt"]?.str != nil else { return "MALFORMED" }
    case "RELEASE":
        guard b["receipt"]?.str != nil, b["cause"]?.str != nil else { return "MALFORMED" }
    case "REFUND":
        if let r = b["receipt"], r.str == nil { return "MALFORMED" }
        if let a = b["amount"], !isUint(a) { return "MALFORMED" }
    case "CHECKPOINT":
        guard isUint(b["seq"]), hashLike(b["head"], real: real), hashLike(b["root"], real: real),
              let cs = b["seq"]?.int, let own = e.seq, cs < own else { return "MALFORMED" }
    default:
        return "MALFORMED"                   // `type` outside the entry CDDL enumeration
    }
    return nil
}

/// principal-object check: returns (ok, mandateHash for MANDATE entries)
typealias PrincipalCheck = (Entry, LedgerState) -> (Bool, [UInt8]?)

struct VerifyResult {
    let ok: Bool; let reason: String?; let at: Int64?; let receipt: String?; let anchor: String
    var promise: Int? = nil              // -05 §10 step 11: index of the first PROMISE_BROKEN / PROMISE_LATE
    var promises: [String]? = nil        // -05 §10 step 11: outcome per presented promise (only when promises were presented)
}

/// -05 §9.5: one presented inclusion promise, already checked for signature (`sigOK` = COSE_Sign1 under the witness key
/// with typ application/aar-inclusion-promise+cbor; abstract: signed_by = witness key) and decoded.
struct PromiseIn { var sigOK: Bool; var payload: V? }

/// -05 §9.5 "Checking a promise (third party)", steps 1-5. `anchored` = seqs of the CHECKPOINT entries whose anchor
/// verified; `real` selects byte hashes (entry hash, ledger id) versus symbolic ones (abstract vectors).
func checkPromise(_ P: PromiseIn, entries: [Entry], anchored: Set<Int64>, now: Int64, real: Bool, ledgerId: [UInt8]?) -> String {
    // 1
    guard P.sigOK, let p = P.payload else { return "PROMISE_SIG" }
    let harness: Set<String> = real ? [] : ["signed_by"]                   // abstract signer name (App. A), not a member
    guard p.isMap, onlyKeys(p, Set(["v", "t", "ledger", "seq", "entry", "entry_t", "mmd"]).union(harness)),
          p["v"]?.str == "deus-aar-0.1", p["t"]?.str == "promise", isUint(p["seq"]), isUint(p["entry_t"]), isUint(p["mmd"]),
          hashLike(p["entry"], real: real) else { return "PROMISE_MALFORMED" }
    if real {
        guard let l = p["ledger"]?.bytes, l == ledgerId else { return "PROMISE_MALFORMED" }
    } else if let l = p["ledger"], !hashLike(l, real: false) { return "PROMISE_MALFORMED" }   // AMBIGUITY-05-3: abstract has no ledger id
    let seq = p["seq"]!.int!, et = p["entry_t"]!.int!, mmd = p["mmd"]!.int!
    if mmd > 3600 { return "PROMISE_MALFORMED" }
    // 2
    let D = et + mmd
    let C = entries.filter { $0.type == "CHECKPOINT" && $0.seq != nil && anchored.contains($0.seq!) && ($0.body["seq"]?.int ?? -1) >= seq }
    // 3
    if let e = entries.first(where: { $0.seq == seq }) {
        let same = real ? (e.hashBytes != nil && p["entry"]?.bytes == e.hashBytes) : (p["entry"]?.str == e.hash)
        if !same || e.t != et { return "PROMISE_BROKEN" }
        // 5
        if C.contains(where: { ($0.t ?? Int64.max) <= D }) { return "kept" }
        return (!C.isEmpty || now > D) ? "PROMISE_LATE" : "pending"
    }
    // 4
    return (!C.isEmpty || now > D) ? "PROMISE_BROKEN" : "pending"
}

func verifyLedger(independent: Bool, entries: [Entry], checkpoints published: [CheckpointIn], publishedAnchor: CheckpointIn?,
                  presented: [Presented], principalCheck: PrincipalCheck, merkle: Bool, ledgerPrincipal: String,
                  promises: [PromiseIn] = [], anchored: Set<Int64> = [], now checkNow: Int64 = 0, ledgerId: [UInt8]? = nil) -> VerifyResult {
    let real = merkle
    // step 1
    if !independent { return VerifyResult(ok: false, reason: "WITNESS_NOT_INDEPENDENT", at: nil, receipt: nil, anchor: "none") }
    var st = LedgerState()
    var prevEntry: Entry? = nil
    do {
        var prevT: Int64? = nil
        for (idx, e) in entries.enumerated() {
            // -04 §10 (C3-8): `at` = seq, or for an entry whose seq is missing/not an integer its index in the ledger
            let at: Int64? = e.seq ?? Int64(idx)
            // 2
            if !e.sigOK { throw Failure(reason: "WITNESS_SIG", at: at) }
            // 3
            if let p = prevEntry {
                guard let s = e.seq, let ps = p.seq, s == ps + 1, e.prev == p.hash else { throw Failure(reason: "CHAIN_BREAK", at: at) }
            } else {
                guard e.seq == 0, e.prev == nil else { throw Failure(reason: "CHAIN_BREAK", at: at) }
            }
            if !e.ledgerOK { throw Failure(reason: "CHAIN_BREAK", at: at) }
            // -04 §7.1 "Order of `t`", §10 step 3 (C3-1): t not less than the previous entry's t; compared only when this
            // entry's t is a non-negative integer (the previous entry passed step 4, so its t is one)
            let tOK = e.t != nil && e.t! >= 0
            if tOK, let pt = prevT, e.t! < pt { throw Failure(reason: "CHAIN_BREAK", at: at) }
            let now = e.t ?? 0
            // 7(a), evaluated directly after step 3 (-02 §10): an entry with t after the expires of a still-active
            // reservation, unless the entry is itself a RELEASE with cause `expired`. An entry without `t` cannot be
            // placed in time: it falls through to step 4 (MALFORMED). AMBIGUITY-C3-3.
            let exempt = e.type == "RELEASE" && e.body["cause"]?.str == "expired"
            if tOK && !exempt && !st.expiredActive(now: now).isEmpty { throw Failure(reason: "RELEASE_MISSING", at: at) }
            // 4 (entry CDDL, -03 §7.1 "Shape of the entry"), then body shape
            if let code = e.shapeErr { throw Failure(reason: code, at: at) }
            if e.t == nil || e.t! < 0 { throw Failure(reason: "MALFORMED", at: at) }
            if let code = bodyShape(e, real: real) { throw Failure(reason: code, at: at) }
            // 4 (consistency with the ledger, -03 §6.1/§6.3/§5.2): principal of a MANDATE = the ledger's; currency of a
            // MANDATE/CEILING = currency of the first MANDATE. Checked before the signature (order of step 4).
            if e.type == "MANDATE" {
                let m = e.body["mandate"]!
                if m["principal"]?.str != ledgerPrincipal { throw Failure(reason: "MANDATE_MALFORMED", at: at) }
                if let c = st.currency, m["currency"]?.str != c { throw Failure(reason: "MANDATE_MALFORMED", at: at) }
            }
            // -04 (C3-2): a CEILING before the first MANDATE has no ledger currency: CEILING_MALFORMED
            if e.type == "CEILING", st.currency == nil || e.body["currency"]?.str != st.currency { throw Failure(reason: "CEILING_MALFORMED", at: at) }
            switch e.type {
            case "MANDATE":
                let m = e.body["mandate"]!
                let (ok, h) = principalCheck(e, st)
                if !ok { throw Failure(reason: "MANDATE_KEY", at: at) }
                st.mandates[m["id"]!.str!] = (m, h)
                if st.currency == nil { st.currency = m["currency"]?.str }
            case "CEILING":
                let (ok, _) = principalCheck(e, st)
                if !ok { throw Failure(reason: "MANDATE_KEY", at: at) }
                st.ceiling = (e.body["amount"]!.int!, e.body["window_s"]!.int!)
            case "REVOCATION":
                let (ok, _) = principalCheck(e, st)
                if !ok { throw Failure(reason: "MANDATE_KEY", at: at) }
                st.revoked.insert(e.body["mandate"]!.str!)
            case "APPROVAL":
                // -03 §6.6 / §10 step 4 (C2-4): an APPROVAL of a receipt that is not, at the entry's t, an undecided and
                // unexpired `defer` RECEIPT earlier in the ledger is MANDATE_KEY
                let (ok, _) = principalCheck(e, st)
                guard ok, let rid = e.body["receipt"]?.str, var r = st.receipts[rid], r.verdict == "defer", !r.approved, !r.refused,
                      now <= r.expires, !st.revoked.contains(r.mandateId)    // -04 C3-9: mandate not revoked
                else { throw Failure(reason: "MANDATE_KEY", at: at) }
                if e.body["approved"]?.boolean == true { r.approved = true } else { r.refused = true }
                st.receipts[rid] = r
            case "RECEIPT":
                // 5, first part (-03, C2-3): a repeated RECEIPT id is DUPLICATE_RECEIPT_ID before recomputation
                let rid = e.body["id"]!.str!
                if st.receipts[rid] != nil { throw Failure(reason: "DUPLICATE_RECEIPT_ID", at: at) }
                let ttl = e.body["ttl"]!.int!
                let mid = e.body["mandate"]!.str!
                let action = e.body["action"]!
                let signedV = e.body["verdict"]!.str!, signedR = e.body["reason"]!.str!
                if let md = st.mandates[mid] {
                    let v = decide(mandate: md.m, mandateSigValid: true, action: action, now: now, state: st.view(mandate: mid, at: now))
                    if v.decision != signedV || signedR != v.reason { throw Failure(reason: "VERDICT_NOT_REPRODUCIBLE", at: at) }
                } else {
                    guard signedV == "deny", signedR == "NO_MANDATE" else { throw Failure(reason: "MANDATE_UNKNOWN", at: at) }
                }
                st.addReceipt(id: rid, mandateId: mid, action: action, verdict: Verdict(decision: signedV, reason: signedR),
                              t: now, ttl: ttl, seq: e.seq ?? 0)
            case "CONSUME":
                // 6
                guard let rid = e.body["receipt"]?.str, var r = st.receipts[rid], r.effectiveAllow, !r.consumed,
                      now <= r.expires, !r.monetary || r.res == .active
                else { throw Failure(reason: "CONSUME_INVALID", at: at) }
                r.consumed = true; if r.monetary { r.res = .consumed }
                st.receipts[rid] = r
            case "RELEASE":
                // 7(b) (RELEASE rules of §7.4)
                let causes: Set<String> = ["tool_not_executed", "expired", "refused", "revoked"]
                guard let rid = e.body["receipt"]?.str, var r = st.receipts[rid], r.res == .active,
                      let cause = e.body["cause"]?.str, causes.contains(cause) else { throw Failure(reason: "RELEASE_INVALID", at: at) }
                switch cause {
                case "expired": if !(now > r.expires) { throw Failure(reason: "RELEASE_INVALID", at: at) }
                case "revoked": if !st.revoked.contains(r.mandateId) { throw Failure(reason: "RELEASE_INVALID", at: at) }
                case "refused": if !r.refused { throw Failure(reason: "RELEASE_INVALID", at: at) }
                default: break
                }
                r.res = .released; st.receipts[rid] = r
            default:
                break      // REFUND (recorded, not interpreted), CHECKPOINT (step 8)
            }
            prevEntry = e
            prevT = e.t
        }
    } catch let f as Failure {
        return VerifyResult(ok: false, reason: f.reason, at: f.at, receipt: nil, anchor: "none")
    } catch { return VerifyResult(ok: false, reason: "INTERNAL", at: nil, receipt: nil, anchor: "none") }

    // 8 checkpoints: every CHECKPOINT entry (ledger order), then every published one (-02 §9.1, §10 step 8)
    var checkpoints: [CheckpointIn] = []
    for e in entries where e.type == "CHECKPOINT" {
        checkpoints.append(CheckpointIn(seq: e.body["seq"]?.int, head: e.body["head"]?.bytes.map(hex) ?? e.body["head"]?.str ?? "-",
                                        root: e.body["root"]?.bytes))
    }
    checkpoints += published
    for cp in checkpoints {
        if !cp.sigOK { return VerifyResult(ok: false, reason: "CHECKPOINT_SIG", at: nil, receipt: nil, anchor: "none") }
        let idx: Int? = cp.seq == nil ? entries.count - 1 : entries.firstIndex { $0.seq == cp.seq }
        guard let i = idx, i >= 0, entries[i].hash == cp.head, cp.ledgerOK else {
            return VerifyResult(ok: false, reason: "CHECKPOINT_HEAD", at: nil, receipt: nil, anchor: "none")
        }
        if merkle {
            let leaves = entries[0...i].map { $0.hashBytes ?? [] }
            if cp.root == nil || mth(ArraySlice(leaves)) != cp.root! {
                return VerifyResult(ok: false, reason: "CHECKPOINT_ROOT", at: nil, receipt: nil, anchor: "none")
            }
        }
        if cp.anchorDigestMatches == false { return VerifyResult(ok: false, reason: "ANCHOR_MISMATCH", at: nil, receipt: nil, anchor: "none") }
    }
    // 9 presented receipts
    for p in presented {
        if let c = p.code { return VerifyResult(ok: false, reason: c, at: nil, receipt: p.id, anchor: "none") }
    }
    // 11 (-05) inclusion promises, in the order presented; only BROKEN / LATE change the result
    let outs = promises.map { checkPromise($0, entries: entries, anchored: anchored, now: checkNow, real: real, ledgerId: ledgerId) }
    if let i = outs.firstIndex(where: { $0 == "PROMISE_BROKEN" || $0 == "PROMISE_LATE" }) {
        var r = VerifyResult(ok: false, reason: outs[i], at: nil, receipt: nil, anchor: "none"); r.promise = i; r.promises = outs
        return r
    }
    var r = VerifyResult(ok: true, reason: nil, at: nil, receipt: nil, anchor: publishedAnchor?.anchorStatus ?? "none")
    if !promises.isEmpty { r.promises = outs }
    return r
}
