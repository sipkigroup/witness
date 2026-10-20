// Byte-level vectors: tool acceptance (§8.4), COSE verify (§5.1/§8.4 check 2), mandate (§4.2), ledger (§10).
import Foundation

let TYP_RECEIPT = "application/aar-receipt+cbor"
let TYP_ENTRY = "application/aar-ledger-entry+cbor"
let TYP_CP = "application/aar-checkpoint+cbor"
let TYP_MANDATE = "application/aar-mandate+cbor"
let TYP_CEILING = "application/aar-ceiling+cbor"
let TYP_APPROVAL = "application/aar-approval+cbor"
let TYP_REVOCATION = "application/aar-revocation+cbor"

func cwtClaim(_ s: Sign1, _ k: UInt64) -> V? { s.cwt?.mapPairs?.first { $0.0 == .uint(k) }?.1 }

enum InclusionResult { case ok, noProof, invalidProof, wrongEntry, noApprovalForDefer }

/// -04 §8.4 check 8 / §10 step 9 (C3-3): the faults are reported in ONE order, the first failure wins:
/// (a) presence: no proof of the RECEIPT entry, or an AAR with `approved_by` and no APPROVAL proof -> .noProof;
/// (b) validity of EVERY proof given (signature, path, side labels, checkpoint seq below the entry) and, at a verifier,
///     an AAR that does not parse/verify (`aar == nil`, C3-6) -> .invalidProof;
/// (c) identity: the RECEIPT proof names this AAR (entry hash, seq, ledger, id, request) and, at a verifier, entry and
///     checkpoint are in the audited ledger (`inLedger`); for an approved AAR also the APPROVAL entry -> .wrongEntry;
/// (d) the decision the entry RECORDS: deny -> .wrongEntry; defer with an AAR without `approved_by`: tool .wrongEntry,
///     verifier .noApprovalForDefer (NO_INCLUSION) without an approval proof and .wrongEntry with one (C3-4); defer with
///     `approved_by`: the APPROVAL entry must approve this receipt and follow it; allow with `approved_by` -> .wrongEntry;
///     allow without `approved_by`: an approval proof given is ignored (C3-5);
/// (e) verifier: the AAR `verdict` is not allow -> .wrongEntry (the tool checks it as check 3).
/// Tool maps .invalidProof/.wrongEntry -> INCLUSION_INVALID; verifier .invalidProof -> INCLUSION_INVALID, .wrongEntry -> OFFLOG_RECEIPT.
func checkInclusion(aar: Sign1?, proof: V, witnessKeys: [PubKey], verifier: Bool = false,
                    inLedger: (([(hash: [UInt8], seq: Int64)], V) -> Bool)? = nil) -> InclusionResult {
    let ab = aar?.payload["mandate"]?["approved_by"].flatMap { $0.isNull ? nil : $0 }
    let apV = proof["approval"].flatMap { $0.isNull ? nil : $0 }
    // (a) presence
    if ab != nil && apV == nil { return .noProof }
    // (b) validity of every proof given
    guard let eh = proof["entry"]?.str, let eb = unhex(eh), let ch = proof["checkpoint"]?.str, let cb = unhex(ch),
          let path = proof["path"]?.arr else { return .invalidProof }
    guard case let .success(entry) = parseSign1(eb), checkSign1(entry, expectedTyp: TYP_ENTRY, keys: witnessKeys) == nil else { return .invalidProof }
    guard case let .success(cp) = parseSign1(cb), checkSign1(cp, expectedTyp: TYP_CP, keys: witnessKeys) == nil,
          let cpSeq = cp.payload["seq"]?.int, let root = cp.payload["root"]?.bytes else { return .invalidProof }
    func pathOK(_ entryBytes: [UInt8], _ seq: Int64?, _ pathV: [V]) -> Bool {
        guard let seq = seq, seq >= 0, cpSeq >= seq else { return false }
        var p: [(String, [UInt8])] = []
        for el in pathV {
            guard let a = el.arr, a.count == 2, let side = a[0].str, side == "L" || side == "R", let hh = a[1].str, let h = unhex(hh), h.count == 32 else { return false }
            p.append((side, h))
        }
        guard let r = rootFromPath(sha256(entryBytes), index: Int(seq), size: Int(cpSeq) + 1, path: p) else { return false }
        return r == root
    }
    let entrySeq = entry.payload["seq"]?.int
    guard pathOK(eb, entrySeq, path) else { return .invalidProof }
    var ae: Sign1? = nil, aeb: [UInt8] = []
    if let ap = apV {      // AMBIGUITY-C4-1: (b) "every proof given" -- also an approval proof that (d) will later ignore
        guard let aeh = ap["entry"]?.str, let b = unhex(aeh), let apath = ap["path"]?.arr,
              case let .success(x) = parseSign1(b), checkSign1(x, expectedTyp: TYP_ENTRY, keys: witnessKeys) == nil,
              pathOK(b, x.payload["seq"]?.int, apath) else { return .invalidProof }
        ae = x; aeb = b
    }
    guard let aar = aar else { return .invalidProof }     // -04 C3-6 (verifier): an AAR that cannot be read
    // (c) identity
    let chain = aar.payload["chain"]
    let entryHash = sha256(eb)
    let sub = cwtClaim(aar, 2)
    let bound: Bool = {
        guard let cEntry = chain?["entry"]?.bytes, cEntry == entryHash,
              let cSeq = chain?["seq"]?.int, entrySeq == cSeq,
              let cLedger = chain?["ledger"]?.bytes, entry.payload["ledger"]?.bytes == cLedger, cp.payload["ledger"]?.bytes == cLedger,
              entry.payload["type"]?.str == "RECEIPT",
              let sub = sub, entry.payload["body"]?["id"] == sub,
              let act = entry.payload["body"]?["action"],
              let brh = aar.payload["action"]?["binding_request_hash"]?.bytes, sha256(CBOREncoder.encode(act)) == brh else { return false }
        return true
    }()
    if !bound { return .wrongEntry }
    if let il = inLedger, !il([(entryHash, entrySeq!)], cp.payload) { return .wrongEntry }
    let approvalFits: Bool = {
        guard let ae = ae else { return false }
        return ae.payload["type"]?.str == "APPROVAL" && sub != nil && ae.payload["body"]?["receipt"] == sub! &&
            (ae.payload["seq"]?.int ?? -1) > (entrySeq ?? Int64.max) && ae.payload["ledger"]?.bytes == entry.payload["ledger"]?.bytes &&
            (ab == nil || ab!["digest"]?.bytes == sha256(aeb)) &&
            (inLedger == nil || inLedger!([(sha256(aeb), ae.payload["seq"]!.int!)], cp.payload))
    }()
    if ab != nil && !approvalFits { return .wrongEntry }
    // (d) the recorded decision
    switch entry.payload["body"]?["verdict"]?.str {
    case "allow":
        if ab != nil { return .wrongEntry }
    case "defer":
        if ab == nil { return verifier && apV == nil ? .noApprovalForDefer : .wrongEntry }
        if ae?.payload["body"]?["approved"]?.boolean != true { return .wrongEntry }
    default:
        return .wrongEntry
    }
    // (e) verifier: the AAR verdict
    if verifier && aar.payload["verdict"]?["decision"]?.str != "allow" { return .wrongEntry }
    return .ok
}

/// Tool acceptance, checks 1-8 (stateless tool; check 9 is the witness's at CONSUME).
func toolAccept(aarBytes: [UInt8]?, keys: [PubKey], toolId: String, request: V?, now: Int64, proof: V?, accepted: inout Set<[UInt8]>) -> [String: String] {
    func rej(_ r: String) -> [String: String] { ["result": "reject", "reason": r] }
    guard let ab = aarBytes else { return rej("NO_RECEIPT") }                                   // 1
    guard case let .success(aar) = parseSign1(ab) else { return rej("MALFORMED") }             // 2
    if let r = checkSign1(aar, expectedTyp: TYP_RECEIPT, keys: keys) { return rej(r) }
    guard aar.payload.isMap, let ind = aar.payload["independence"]?.str else { return rej("MALFORMED") }
    if ind == "none" { return rej("WITNESS_NOT_INDEPENDENT") }
    if aar.payload["verdict"]?["decision"]?.str != "allow" { return rej("NOT_ALLOWED") }        // 3
    if aar.payload["audience"]?.str != toolId { return rej("AUDIENCE") }                       // 4
    guard let req = request, let brh = aar.payload["action"]?["binding_request_hash"]?.bytes,
          sha256(CBOREncoder.encode(req)) == brh else { return rej("REQUEST_MISMATCH") }        // 5
    // -02 §8.4 check 6: replay identity = (iss, chain.ledger, sub), never the COSE bytes
    guard let iss = cwtClaim(aar, 1), let sub = cwtClaim(aar, 2), let cl = aar.payload["chain"]?["ledger"]?.bytes else { return rej("MALFORMED") }
    let rk = CBOREncoder.encode(.array([iss, .bytes(cl), sub]))
    if accepted.contains(rk) { return rej("REPLAY") }                                           // 6
    guard let exp = aar.payload["expires"]?.int else { return rej("MALFORMED") }
    if now > exp { return rej("RECEIPT_EXPIRED") }                                              // 7
    guard let pr = proof, !pr.isNull else { return rej("NO_INCLUSION") }                        // 8
    switch checkInclusion(aar: aar, proof: pr, witnessKeys: keys) {
    case .ok: break
    case .noProof: return rej("NO_INCLUSION")
    case .invalidProof, .wrongEntry, .noApprovalForDefer: return rej("INCLUSION_INVALID")      // a tool answers INCLUSION_INVALID for all
    }
    accepted.insert(rk)
    return ["result": "accept"]
}

func runCoseVerify(_ j: V) -> [String: String] {
    let keys = keysFrom(j["keys"])
    guard let b = unhex(j["cose_hex"]?.str ?? "") else { return ["result": "reject", "reason": "MALFORMED"] }
    guard case let .success(s) = parseSign1(b) else { return ["result": "reject", "reason": "MALFORMED"] }
    if let r = checkSign1(s, expectedTyp: j["typ"]?.str ?? TYP_RECEIPT, keys: keys) { return ["result": "reject", "reason": r] }
    if s.payload["independence"]?.str == "none" { return ["result": "reject", "reason": "WITNESS_NOT_INDEPENDENT"] }
    return ["result": "ok"]
}

func runCoseMandate(_ j: V) -> [String: String] {
    let keys = keysFrom(j["keys"])
    guard let b = unhex(j["cose_hex"]?.str ?? ""), case let .success(s) = parseSign1(b) else { return ["result": "reject", "reason": "MALFORMED"] }
    if s.typ != TYP_MANDATE { return ["result": "reject", "reason": "MANDATE_MALFORMED"] }
    // §4.2: a record signed by any other key under the principal identifier -> KEY_MISMATCH
    if checkSign1(s, expectedTyp: TYP_MANDATE, keys: keys) != nil { return ["result": "reject", "reason": "KEY_MISMATCH"] }
    if !mandateMatchesCDDL(s.payload) { return ["result": "reject", "reason": "MANDATE_MALFORMED"] }
    if let m = j["mandate"], !(m == s.payload) { return ["result": "reject", "reason": "MANDATE_KEY"] }
    return ["result": "ok"]
}

func runCoseTool(_ j: V) -> [String: String] {
    let keys = keysFrom(j["keys"])
    var accepted = Set<[UInt8]>()
    let toolId = j["tool_id"]?.str ?? ""
    let now = j["now"]?.int ?? 0
    let base = j["cose_hex"]?.str
    if let pres = j["presentations"]?.arr {
        var steps: [[String: String]] = []
        for p in pres {
            let h = p["cose_hex"]?.str ?? base
            steps.append(toolAccept(aarBytes: h.flatMap(unhex), keys: keys, toolId: toolId, request: p["request"] ?? j["request"],
                                    now: p["now"]?.int ?? now, proof: p["proof"] ?? j["proof"], accepted: &accepted))
        }
        return ["steps": steps.map { $0.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",") }.joined(separator: " | ")]
    }
    return toolAccept(aarBytes: base.flatMap(unhex), keys: keys, toolId: toolId, request: j["request"], now: now, proof: j["proof"], accepted: &accepted)
}

func runCoseLedger(_ j: V) -> VerifyResult {
    let wkeys = keysFrom(j["keys"])
    let principal = j["principal"]?.str ?? ""
    let pk: PubKey? = {
        guard let r = j["registry"]?["principals"]?[principal], let a = r["alg"]?.str, let alg = Alg(rawValue: a),
              let p = r["pub"]?.str, let pub = unhex(p) else { return nil }
        return PubKey(alg: alg, pub: pub)
    }()
    let witnessKid = wkeys.first?.thumbprint ?? []
    let ledgerId = sha256(Array("deus-aar/ledger/".utf8) + Array(principal.utf8) + witnessKid)
    var entries: [Entry] = []
    for (i, h) in (j["ledger_hex"]?.arr ?? []).enumerated() {
        let raw = unhex(h.str ?? "") ?? []
        var e = Entry(seq: Int64(i), prev: nil, hash: hex(sha256(raw)), hashBytes: sha256(raw), t: nil, type: "", body: .map([]), raw: raw)
        if case let .success(s) = parseSign1(raw), checkSign1(s, expectedTyp: TYP_ENTRY, keys: wkeys) == nil, s.payload.isMap {
            let p = s.payload
            e.seq = isUint(p["seq"]) ? p["seq"]?.int : nil
            e.t = isUint(p["t"]) ? p["t"]?.int : nil
            e.type = p["type"]?.str ?? ""; e.body = p["body"] ?? .null
            e.prev = p["prev"]?.bytes.map(hex)
            if p["prev"] == nil { e.prev = "<absent>" }                        // -03 §7.1: `prev` missing is CHAIN_BREAK
            if let pv = p["prev"], !pv.isNull, pv.bytes == nil { e.prev = "<non-bstr>" }
            e.ledgerOK = p["ledger"]?.bytes == ledgerId
            // -03 §7.1 "Shape of the entry" (C2-5): t/type/body wrong or missing, or a member not named -> MALFORMED (step 4)
            if !onlyKeys(p, ["ledger", "seq", "prev", "t", "type", "body"]) || p["type"]?.str == nil || p["body"] == nil {
                e.shapeErr = "MALFORMED"
            }
        } else { e.sigOK = false }
        entries.append(e)
    }
    func principalObj(_ e: Entry, typ: String) -> Sign1? {
        guard let pk = pk, let cb = e.body["cose"]?.bytes, case let .success(s) = parseSign1(cb),
              checkSign1(s, expectedTyp: typ, keys: [pk]) == nil else { return nil }
        return s
    }
    let check: PrincipalCheck = { e, st in
        if e.body["cose"] == nil { return (false, nil) }     // real mode: entry without `cose` is rejected (§7.1)
        switch e.type {
        case "MANDATE":
            guard let s = principalObj(e, typ: TYP_MANDATE), let m = e.body["mandate"], m == s.payload else { return (false, nil) }
            return (true, sha256(s.payloadBytes))
        case "CEILING":
            guard let s = principalObj(e, typ: TYP_CEILING) else { return (false, nil) }
            let rec: V = .map([(.text("v"), .text("deus-aar-0.1")), (.text("id"), e.body["id"] ?? .null), (.text("principal"), .text(principal)),
                               (.text("amount"), e.body["amount"] ?? .null), (.text("currency"), e.body["currency"] ?? .null),
                               (.text("window_s"), e.body["window_s"] ?? .null)])
            return (CBOREncoder.encode(rec) == s.payloadBytes, nil)
        case "APPROVAL":
            guard let s = principalObj(e, typ: TYP_APPROVAL), let rid = e.body["receipt"]?.str, let r = st.receipts[rid],
                  let mh = st.mandates[r.mandateId]?.hash else { return (false, nil) }
            let rec: V = .map([(.text("v"), .text("deus-aar-0.1")), (.text("t"), .text("approval")), (.text("receipt"), .text(rid)),
                               (.text("mandate"), .bytes(mh)), (.text("action"), .bytes(sha256(CBOREncoder.encode(r.action)))),
                               (.text("approved"), e.body["approved"] ?? .null)])
            return (CBOREncoder.encode(rec) == s.payloadBytes, nil)
        case "REVOCATION":
            guard let s = principalObj(e, typ: TYP_REVOCATION), let mid = e.body["mandate"]?.str, let mh = st.mandates[mid]?.hash else { return (false, nil) }
            let rec: V = .map([(.text("v"), .text("deus-aar-0.1")), (.text("t"), .text("revocation")), (.text("mandate"), .bytes(mh))])
            return (CBOREncoder.encode(rec) == s.payloadBytes, nil)
        default: return (false, nil)
        }
    }
    var cps: [CheckpointIn] = []
    var published: CheckpointIn? = nil
    if let ch = j["checkpoint_hex"]?.str, let cb = unhex(ch) {
        var c = CheckpointIn(seq: -1, head: "-", root: nil)
        if case let .success(s) = parseSign1(cb), checkSign1(s, expectedTyp: TYP_CP, keys: wkeys) == nil {
            c.seq = s.payload["seq"]?.int; c.head = s.payload["head"]?.bytes.map(hex) ?? "-"; c.root = s.payload["root"]?.bytes
            c.ledgerOK = s.payload["ledger"]?.bytes == ledgerId
        } else { c.sigOK = false }
        cps.append(c); published = c
    }
    var pres: [Presented] = []
    // in the audited ledger (§10 step 9 (c)): same ledger id, every proved entry at its seq, and the checkpoint root is
    // the root of THIS ledger at the checkpoint's seq (a checkpoint of a fork is OFFLOG_RECEIPT)
    let inLedger: ([(hash: [UInt8], seq: Int64)], V) -> Bool = { proved, cpP in
        var ok = cpP["ledger"]?.bytes == ledgerId && proved.allSatisfy { pe in entries.contains { $0.seq == pe.seq && $0.hashBytes == pe.hash } }
        if ok, let cs = cpP["seq"]?.int, let root = cpP["root"]?.bytes {
            if cs >= 0 && cs < Int64(entries.count) { ok = mth(ArraySlice(entries[0...Int(cs)].map { $0.hashBytes ?? [] })) == root } else { ok = false }
        }
        return ok
    }
    for p in j["presented"]?.arr ?? [] {
        var x = Presented(id: "?", code: "NO_INCLUSION")
        var aar: Sign1? = nil
        if let ab = unhex(p["aar_hex"]?.str ?? ""), case let .success(a) = parseSign1(ab),
           checkSign1(a, expectedTyp: TYP_RECEIPT, keys: wkeys) == nil, a.payload.isMap { aar = a }
        if let a = aar { x.id = cwtClaim(a, 2)?.str ?? "?" }
        if let pr = p["proof"], !pr.isNull {           // (a) no proof of the RECEIPT entry: NO_INCLUSION
            switch checkInclusion(aar: aar, proof: pr, witnessKeys: wkeys, verifier: true, inLedger: inLedger) {
            case .ok: x.code = nil
            case .noProof, .noApprovalForDefer: x.code = "NO_INCLUSION"
            case .invalidProof: x.code = "INCLUSION_INVALID"
            case .wrongEntry: x.code = "OFFLOG_RECEIPT"
            }
        }
        pres.append(x)
    }
    // -05 §9.5 / §10 step 11 (real mode): `promises_hex` = COSE_Sign1 promises (typ application/aar-inclusion-promise+cbor
    // under a witness key), `anchored` = seqs of CHECKPOINT entries whose anchor verified, `now`. No byte vector exists yet.
    let proms: [PromiseIn] = (j["promises_hex"]?.arr ?? []).map { h in
        guard let b = unhex(h.str ?? ""), case let .success(s) = parseSign1(b),
              checkSign1(s, expectedTyp: "application/aar-inclusion-promise+cbor", keys: wkeys) == nil else { return PromiseIn(sigOK: false, payload: nil) }
        return PromiseIn(sigOK: true, payload: s.payload)
    }
    return verifyLedger(independent: true, entries: entries, checkpoints: cps, publishedAnchor: published,
                        presented: pres, principalCheck: check, merkle: true, ledgerPrincipal: principal,
                        promises: proms, anchored: Set((j["anchored"]?.arr ?? []).compactMap { $0.int }), now: j["now"]?.int ?? 0, ledgerId: ledgerId)
}

// MARK: abstract verification vectors
func runAbstractVerification(_ j: V) -> VerifyResult {
    let i = j["input"]!
    let wk = i["witness_key"]?.str ?? ""
    let ops = (i["operator_keys"]?.arr ?? []).compactMap { $0.str }
    let pinned = i["pinned_principal_key"]?.str ?? ""
    var entries: [Entry] = []
    for e in i["entries"]?.arr ?? [] {
        entries.append(Entry(seq: e["seq"]?.int, prev: e["prev"]?.str, hash: e["hash"]?.str ?? "", t: e["t"]?.int,
                             type: e["type"]?.str ?? "", body: e["body"] ?? .null,
                             sigOK: e["witness_sig_valid"]?.boolean ?? true))
    }
    let check: PrincipalCheck = { e, _ in (e.body["signed_by"]?.str == pinned, nil) }
    var cps: [CheckpointIn] = []
    var published: CheckpointIn? = nil
    if let c = i["checkpoint"], c.isMap {
        var cp = CheckpointIn(seq: c["seq"]?.int, head: c["head"]?.str ?? "", root: nil)
        if let d = c["ots_digest"]?.str { cp.anchorDigestMatches = (d == cp.head); cp.anchorStatus = c["ots_status"]?.str ?? "none" }
        cps.append(cp); published = cp
    }
    var pres: [Presented] = []
    let cpSeq = published?.seq ?? entries.last?.seq ?? 0
    for p in i["presented"]?.arr ?? [] {
        let id = p["id"]?.str ?? ""
        var x = Presented(id: id, code: "NO_INCLUSION")
        // App. A convention (10): {"id", "inclusion": {"seq"}, "approval": {"seq"}?}; -03 §10 step 9 (C2-11)
        if let inc = p["inclusion"], !inc.isNull {
            // -04 §10 step 9 order: (b) checkpoint seq below the entry -> INCLUSION_INVALID; (c) identity -> OFFLOG_RECEIPT
            let apSeq = p["approval"].flatMap { $0.isNull ? nil : $0 }?["seq"]?.int
            x.code = "OFFLOG_RECEIPT"
            if let s = inc["seq"]?.int, s > cpSeq || (apSeq ?? 0) > cpSeq { x.code = "INCLUSION_INVALID" }
            else if let s = inc["seq"]?.int, let e = entries.first(where: { $0.seq == s }), e.type == "RECEIPT", e.body["id"]?.str == id {
                switch e.body["verdict"]?.str {
                case "allow": x.code = nil
                case "defer":
                    if let ap = p["approval"], !ap.isNull {
                        if let as_ = ap["seq"]?.int, as_ > s, let a = entries.first(where: { $0.seq == as_ }), a.type == "APPROVAL",
                           a.body["receipt"]?.str == id, a.body["approved"]?.boolean == true { x.code = nil }
                    } else { x.code = "NO_INCLUSION" }
                default: break
                }
            }
        }
        pres.append(x)
    }
    // -05 §9.5 / §10 step 11: presented promises (abstract: `signed_by` names the signer), `anchored`, `now`
    let proms: [PromiseIn] = (i["promises"]?.arr ?? []).map { PromiseIn(sigOK: $0["signed_by"]?.str == wk, payload: $0) }
    let anch = Set((i["anchored"]?.arr ?? []).compactMap { $0.int })
    return verifyLedger(independent: !ops.contains(wk), entries: entries, checkpoints: cps, publishedAnchor: published,
                        presented: pres, principalCheck: check, merkle: false, ledgerPrincipal: pinned,
                        promises: proms, anchored: anch, now: i["now"]?.int ?? 0)
}
