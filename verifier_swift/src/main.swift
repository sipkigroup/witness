// verifier_swift runner: runs every vector of draft-deus-aar-04 and prints a match table.
// usage: aarc [--vectors DIR] [--extra DIR] [--cddl-02-literal] [--md FILE] [--quiet]
import Foundation

var vecDir = "../spec/vectors"
var extraDir: String? = nil
var mdOut: String? = nil
var quiet = false
var args = Array(CommandLine.arguments.dropFirst())
while !args.isEmpty {
    let a = args.removeFirst()
    switch a {
    case "--vectors": vecDir = args.removeFirst()
    case "--extra": extraDir = args.removeFirst()
    case "--lenient-cddl": OPT.cddlLiteral = false          // -03 default; kept for old command lines
    case "--cddl-02-literal": OPT.cddlLiteral = true
    case "--md": mdOut = args.removeFirst()
    case "--quiet": quiet = true
    default: FileHandle.standardError.write("unknown arg \(a)\n".data(using: .utf8)!); exit(2)
    }
}

struct Row { let id: String; let kind: String; let cls: String; let expected: String; let got: String; let outcome: Bool; let full: Bool; let group: String }

func fmt(_ d: [String: String]) -> String { d.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",") }
func jsonStr(_ v: V) -> String {
    switch v {
    case let .text(s): return s
    case .null: return "null"
    case let .bool(b): return b ? "true" : "false"
    default: return diag(v)
    }
}
func expDict(_ e: V) -> [String: String] {
    var d: [String: String] = [:]
    for (k, v) in e.mapPairs ?? [] where k.str != "steps" { d[k.str!] = jsonStr(v) }
    return d
}
let OUTCOME_KEYS: Set<String> = ["result", "verdict"]
func compare(_ exp: [String: String], _ got: [String: String]) -> (Bool, Bool) {
    var outcome = true, full = true
    for (k, v) in exp {
        if got[k] != v { full = false; if OUTCOME_KEYS.contains(k) { outcome = false } }
    }
    // extra failure detail in `got` that expected does not list (e.g. reason on a valid result) is a mismatch too
    for (k, v) in got where exp[k] == nil && k != "anchor" && !(k == "result" && exp["verdict"] != nil) {
        if k == "reason" && (exp["result"] == "accept" || exp["result"] == "valid" || exp["result"] == "ok") { full = false; outcome = false }
        _ = v
    }
    return (outcome, full)
}
func vr(_ r: VerifyResult) -> [String: String] {
    if r.ok {
        var d = ["result": "valid", "anchor": r.anchor]
        if let ps = r.promises { d["promises"] = diag(.array(ps.map { .text($0) })) }   // -05 §10 step 11, per promise
        return d
    }
    var d = ["result": "invalid", "reason": r.reason ?? "?"]
    if let a = r.at { d["at"] = "\(a)" }
    if let rc = r.receipt { d["receipt"] = rc }
    if let pi = r.promise { d["promise"] = "\(pi)" }
    return d
}

func runVector(_ j: V, group: String) -> Row {
    let id = j["id"]?.str ?? "?", kind = j["kind"]?.str ?? "?", cls = j["class"]?.str ?? "?"
    let expected = j["expected"] ?? .map([])
    ABSTRACT_HASHES = ["decision", "sequence", "verification"].contains(kind)     // -05: symbolic toolmap_sha256 (App. A)
    switch kind {
    case "decision":
        let i = j["input"]!
        var s = LedgerView()
        if let ls = i["ledger_state"] {
            s.committedMandate = ls["mandate_committed"]?.int ?? 0
            s.committedPrincipal = ls["principal_committed"]?.int ?? 0
            s.ceiling = ls["ceiling"]?.int
            for (k, v) in ls["counts"]?.mapPairs ?? [] { if let c = k.str, let n = v.int { s.counts[c] = n } }   // -05 §7.3
        }
        let a = i["action"] ?? .map([])
        let now = i["now"]?.int ?? a["t"]?.int ?? 0                  // App. A: action.t = witness clock (harness)
        let v = decide(mandate: (i["mandate"]?.isNull ?? true) ? nil : i["mandate"], mandateSigValid: i["mandate_signature_valid"]?.boolean ?? true,
                       action: a, now: now, state: s)
        let got = ["verdict": v.decision, "reason": v.reason]
        let e = expDict(expected)
        let (o, f) = compare(e, got)
        return Row(id: id, kind: kind, cls: cls, expected: fmt(e), got: fmt(got), outcome: o, full: f, group: group)
    case "sequence":
        let i = j["input"]!
        let w = Witness(pinned: i["pinned_principal_key"]?.str ?? "")
        let ops = i["ops"]?.arr ?? []
        let exps = expected["steps"]?.arr ?? []
        var o = ops.count == exps.count, f = o
        var gotS: [String] = [], expS: [String] = []
        for (n, op) in ops.enumerated() {
            let g = w.step(op)
            let e = n < exps.count ? expDict(exps[n]) : [:]
            let (so, sf) = compare(e, g)
            o = o && so; f = f && sf
            gotS.append(fmt(g)); expS.append(fmt(e))
        }
        return Row(id: id, kind: kind, cls: cls, expected: expS.joined(separator: " | "), got: gotS.joined(separator: " | "), outcome: o, full: f, group: group)
    case "verification":
        let got = vr(runAbstractVerification(j))
        let e = expDict(expected)
        let (o, f) = compare(e, got)
        return Row(id: id, kind: kind, cls: cls, expected: fmt(e), got: fmt(got), outcome: o, full: f, group: group)
    case "cose-verify", "cose-mandate", "cose-tool", "cose-ledger":
        var got: [String: String]
        switch kind {
        case "cose-verify": got = runCoseVerify(j)
        case "cose-mandate": got = runCoseMandate(j)
        case "cose-tool": got = runCoseTool(j)
        default: got = vr(runCoseLedger(j))
        }
        if let steps = expected["steps"]?.arr {
            let e = steps.map { fmt(expDict($0)) }.joined(separator: " | ")
            let g = got["steps"] ?? fmt(got)
            let full = e == g
            // outcome: compare only result= parts
            func outc(_ s: String) -> String { s.split(separator: "|").map { $0.split(separator: ",").filter { $0.contains("result=") }.joined() }.joined(separator: "|") }
            return Row(id: id, kind: kind, cls: cls, expected: e, got: g, outcome: outc(e) == outc(g), full: full, group: group)
        }
        let e = expDict(expected)
        let (o, f) = compare(e, got)
        return Row(id: id, kind: kind, cls: cls, expected: fmt(e), got: fmt(got), outcome: o, full: f, group: group)
    default:
        return Row(id: id, kind: kind, cls: cls, expected: "?", got: "unsupported kind", outcome: false, full: false, group: group)
    }
}

func loadDir(_ d: String) -> [V] {
    let fm = FileManager.default
    guard let names = try? fm.contentsOfDirectory(atPath: d) else { return [] }
    return names.filter { $0.hasSuffix(".json") && $0 != "index.json" }.sorted().compactMap {
        guard let data = fm.contents(atPath: d + "/" + $0) else { return nil }
        do { return try JSONParser.parse(data) } catch { FileHandle.standardError.write("parse error \($0)\n".data(using: .utf8)!); return nil }
    }
}

var rows: [Row] = []
for v in loadDir(vecDir) { rows.append(runVector(v, group: "abstract")) }
for v in loadDir(vecDir + "/cose") { rows.append(runVector(v, group: "byte")) }
if let x = extraDir { for v in loadDir(x) { rows.append(runVector(v, group: "extra")) } }

var md = "| id | group | kind | class | outcome | outcome+code | expected | got |\n|---|---|---|---|---|---|---|---|\n"
for r in rows {
    let line = "| \(r.id) | \(r.group) | \(r.kind) | \(r.cls) | \(r.outcome ? "yes" : "NO") | \(r.full ? "yes" : "NO") | \(r.expected) | \(r.got) |"
    md += line + "\n"
    if !quiet || !r.full { print("\(r.full ? "OK  " : (r.outcome ? "CODE" : "FAIL")) \(r.id) [\(r.kind)] exp: \(r.expected)\n      got: \(r.got)") }
}
for g in ["abstract", "byte", "extra"] {
    let rs = rows.filter { $0.group == g }
    if rs.isEmpty { continue }
    let s = "\(g): outcome \(rs.filter { $0.outcome }.count)/\(rs.count), outcome+code \(rs.filter { $0.full }.count)/\(rs.count)"
    print(s); md += "\n" + s + "\n"
}
print("mode: cddl=\(OPT.cddlLiteral ? "02-literal" : "03 (null ok)")")
if let m = mdOut { try? md.write(toFile: m, atomically: true, encoding: .utf8) }
