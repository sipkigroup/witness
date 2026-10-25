// PROPOSAL-08-http (class `http`, 0.2.43): canonical form and matching of HTTP request targets and of the rules of
// permissions.http.allow (PH-4). Written from spec/PROPOSAL-08-http.md only; nothing is shared with the Python side.
// Every text is handled as ASCII bytes: any byte >= 0x80 anywhere in a target or a rule makes it unmatchable / non-canonical
// (method, host, port and the raw part of a path are ASCII by the grammar; non-ASCII appears only percent-encoded).
import Foundation

let HTTP_MAX_RULES = 200, HTTP_MAX_RULE_LEN = 512, HTTP_MAX_TARGET_LEN = 8192, HTTP_DEFAULT_PORT = 443

struct HttpTarget { let m: String; let host: String; let port: Int; let segs: [String] }
struct HttpRule { let m: String; let host: String; let port: Int; let segs: [String] }

private let UNRESERVED: Set<UInt8> = Set(Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".utf8))
private let PCHAR_RAW: Set<UInt8> = UNRESERVED.union(Array("!$&'()*+,;=:@".utf8))
private func hexVal(_ b: UInt8) -> UInt8? {
    switch b { case 48...57: return b - 48; case 65...70: return b - 55; case 97...102: return b - 87; default: return nil }
}
private func isDigit(_ b: UInt8) -> Bool { return b >= 48 && b <= 57 }
private func isAlpha(_ b: UInt8) -> Bool { return (b >= 65 && b <= 90) || (b >= 97 && b <= 122) }
private func str(_ b: ArraySlice<UInt8>) -> String { return String(decoding: b, as: UTF8.self) }
private func lowerAscii(_ b: UInt8) -> UInt8 { return (b >= 65 && b <= 90) ? b + 32 : b }

func httpCanonMethod(_ m: ArraySlice<UInt8>) -> String? {
    guard m.count >= 1, m.count <= 16, m.allSatisfy(isAlpha) else { return nil }
    return String(decoding: m.map { ($0 >= 97 && $0 <= 122) ? $0 - 32 : $0 }, as: UTF8.self)
}
private func httpPort(_ s: ArraySlice<UInt8>) -> Int? {
    guard s.count >= 1, s.count <= 5, s.allSatisfy(isDigit), s.first! != 48 else { return nil }
    let p = s.reduce(0) { $0 * 10 + Int($1 - 48) }
    return (p >= 1 && p <= 65535) ? p : nil
}
func httpCanonHost(_ raw: ArraySlice<UInt8>, wildcard: Bool = false) -> String? {
    guard !raw.isEmpty, raw.allSatisfy({ $0 < 128 }) else { return nil }
    var h = Array(raw.map(lowerAscii))
    if h.last == 46 { h.removeLast() }
    var star = false
    if wildcard && h.count >= 2 && h[0] == 42 && h[1] == 46 { star = true; h.removeFirst(2) }
    guard !h.isEmpty, h.count <= 253 else { return nil }
    let labels = h.split(separator: 46, omittingEmptySubsequences: false)
    for lb in labels {
        guard lb.count >= 1, lb.count <= 63, lb.allSatisfy({ ($0 >= 97 && $0 <= 122) || isDigit($0) || $0 == 45 || $0 == 95 }) else { return nil }
    }
    if labels.allSatisfy({ $0.allSatisfy(isDigit) }) {
        if star || labels.count != 4 { return nil }
        for lb in labels { if (lb.count > 1 && lb.first! == 48) || lb.reduce(0, { $0 * 10 + Int($1 - 48) }) > 255 { return nil } }
    } else if labels.last!.allSatisfy(isDigit) { return nil }
    if star && labels.count < 2 { return nil }
    return (star ? "*." : "") + str(h[...])
}

/// strict UTF-8 -> scalars (overlong forms, surrogates, > U+10FFFF, truncated sequences -> nil)
private func strictUTF8(_ b: [UInt8]) -> [Unicode.Scalar]? {
    var out: [Unicode.Scalar] = [], i = 0
    while i < b.count {
        let c = b[i]
        var need = 0, cp: UInt32 = 0, minv: UInt32 = 0
        if c < 0x80 { out.append(Unicode.Scalar(c)); i += 1; continue }
        else if c >= 0xC2 && c <= 0xDF { need = 1; cp = UInt32(c & 0x1F); minv = 0x80 }
        else if c >= 0xE0 && c <= 0xEF { need = 2; cp = UInt32(c & 0x0F); minv = 0x800 }
        else if c >= 0xF0 && c <= 0xF4 { need = 3; cp = UInt32(c & 0x07); minv = 0x10000 }
        else { return nil }
        for k in 1...need {
            guard i + k < b.count, b[i + k] & 0xC0 == 0x80 else { return nil }
            cp = (cp << 6) | UInt32(b[i + k] & 0x3F)
        }
        guard cp >= minv, cp <= 0x10FFFF, !(cp >= 0xD800 && cp <= 0xDFFF), let sc = Unicode.Scalar(cp) else { return nil }
        out.append(sc); i += need + 1
    }
    return out
}
private func badCategory(_ s: Unicode.Scalar) -> Bool {
    switch s.properties.generalCategory {
    case .control, .format, .surrogate, .privateUse, .unassigned, .lineSeparator, .paragraphSeparator: return true
    default: return false
    }
}
func httpCanonSegment(_ seg: ArraySlice<UInt8>) -> String? {
    var out: [UInt8] = [], raw: [UInt8] = []
    var i = seg.startIndex
    while i < seg.endIndex {
        let c = seg[i]
        if c == 37 {                                                   // %
            guard i + 2 < seg.endIndex, let h1 = hexVal(seg[i + 1]), let h2 = hexVal(seg[i + 2]) else { return nil }
            let b = h1 * 16 + h2
            if b == 0x2F || b == 0x5C || b == 0x25 || b == 0x7F || b < 0x20 { return nil }
            raw.append(b)
            if UNRESERVED.contains(b) { out.append(b) } else { out.append(37); out.append(seg[i + 1] >= 97 ? seg[i + 1] - 32 : seg[i + 1]); out.append(seg[i + 2] >= 97 ? seg[i + 2] - 32 : seg[i + 2]) }
            i += 3; continue
        }
        guard c < 128, PCHAR_RAW.contains(c) else { return nil }
        raw.append(c); out.append(c); i += 1
    }
    guard let scalars = strictUTF8(raw) else { return nil }
    var s = String.UnicodeScalarView(); s.append(contentsOf: scalars)
    let text = String(s)
    if Array(text.precomposedStringWithCompatibilityMapping.unicodeScalars) != scalars { return nil }       // NFKC-stable
    if scalars.contains(where: badCategory) { return nil }
    var head: [Unicode.Scalar] = []
    for sc in scalars { if sc == ";" { break }; head.append(sc) }
    if head == ["."] || head == [".", "."] { return nil }                                                   // dot segment, also "..;x"
    return str(out[...])
}
func httpCanonPath(_ path: ArraySlice<UInt8>) -> [String]? {
    guard path.first == 47, path.count <= HTTP_MAX_TARGET_LEN else { return nil }
    let segs = path.dropFirst().split(separator: 47, omittingEmptySubsequences: false)
    var out: [String] = []
    for (k, s) in segs.enumerated() {
        if s.isEmpty { if k != segs.count - 1 { return nil }; out.append(""); continue }
        guard let c = httpCanonSegment(s), !c.isEmpty else { return nil }
        out.append(c)
    }
    return out
}
func httpCanonTarget(_ t: String) -> HttpTarget? {
    let b = Array(t.utf8)
    guard b.count <= HTTP_MAX_TARGET_LEN, b.allSatisfy({ $0 < 128 }), let sp = b.firstIndex(of: 32), sp > 0 else { return nil }
    guard let m = httpCanonMethod(b[0..<sp]) else { return nil }
    let rest = b[(sp + 1)...]
    guard let sl = rest.firstIndex(of: 47), sl > rest.startIndex else { return nil }
    let auth = rest[rest.startIndex..<sl], path = rest[sl...]
    guard let colon = auth.lastIndex(of: 58) else { return nil }                    // no default port on the request side
    guard let host = httpCanonHost(auth[auth.startIndex..<colon]), let p = httpPort(auth[(colon + 1)...]), let segs = httpCanonPath(path) else { return nil }
    return HttpTarget(m: m, host: host, port: p, segs: segs)
}
func httpParseRule(_ r: String) -> HttpRule? {
    let b = Array(r.utf8)
    guard !b.isEmpty, b.count <= HTTP_MAX_RULE_LEN, b.allSatisfy({ $0 < 128 }), !b.contains(44), let sp = b.firstIndex(of: 32), sp > 0 else { return nil }
    let mt = b[0..<sp], rest = b[(sp + 1)...]
    let m: String? = (mt.count == 1 && mt.first! == 42) ? "*" : httpCanonMethod(mt)
    guard let mm = m, let sl = rest.firstIndex(of: 47), sl > rest.startIndex, !rest.contains(32) else { return nil }
    let auth = rest[rest.startIndex..<sl], path = rest[sl...]
    var hostBytes = auth, p: Int? = HTTP_DEFAULT_PORT
    if let colon = auth.lastIndex(of: 58) { hostBytes = auth[auth.startIndex..<colon]; p = httpPort(auth[(colon + 1)...]) }
    guard let host = httpCanonHost(hostBytes, wildcard: true), let port = p else { return nil }
    let segs = path.dropFirst().split(separator: 47, omittingEmptySubsequences: false)
    var out: [String] = []
    for (k, s) in segs.enumerated() {
        let last = k == segs.count - 1
        if s.count == 1 && s.first! == 42 { out.append("*") }
        else if s.count == 2 && s.first! == 42 && s.last! == 42 { if !last { return nil }; out.append("**") }
        else if s.isEmpty { if !last { return nil }; out.append("") }
        else { guard let c = httpCanonSegment(s), !c.contains("*") else { return nil }; out.append(c) }
    }
    return HttpRule(m: mm, host: host, port: port, segs: out)
}
func httpRuleText(_ p: HttpRule) -> String {
    return "\(p.m) \(p.host)\(p.port == HTTP_DEFAULT_PORT ? "" : ":\(p.port)")/\(p.segs.joined(separator: "/"))"
}
func httpIsCanonicalRule(_ r: String) -> Bool {
    guard let p = httpParseRule(r) else { return false }
    let t = httpRuleText(p)
    return t.utf8.count <= HTTP_MAX_RULE_LEN && Array(t.utf8) == Array(r.utf8)
}
private func httpHostOK(_ rh: String, _ h: String) -> Bool {
    if rh.hasPrefix("*.") { let suf = Array(rh.utf8.dropFirst()), hh = Array(h.utf8); return hh.count > suf.count && Array(hh.suffix(suf.count)) == suf }
    return Array(rh.utf8) == Array(h.utf8)
}
func httpRuleCovers(_ r: HttpRule, _ t: HttpTarget) -> Bool {
    if (r.m != "*" && r.m != t.m) || r.port != t.port || !httpHostOK(r.host, t.host) { return false }
    var pre = r.segs
    if r.segs.last == "**" { pre.removeLast(); if t.segs.count <= pre.count { return false } }
    else if t.segs.count != r.segs.count { return false }
    for (a, b) in zip(pre, t.segs) {
        if a == "*" { if b.isEmpty { return false } } else if a != b { return false }
    }
    return true
}
/// Does any CANONICAL rule cover the request target? A non-canonical entry never matches (fail closed).
func httpAllowed(_ rules: [String], _ target: String) -> Bool {
    guard let t = httpCanonTarget(target) else { return false }
    return rules.contains { httpIsCanonicalRule($0) && httpRuleCovers(httpParseRule($0)!, t) }
}
/// PH-3: permissions.http well formed? (null / false handled by the caller)
func httpPermWellFormed(_ v: V) -> Bool {
    guard v.isMap, onlyKeys(v, ["allow", "unlisted"]) else { return false }
    if let u = v["unlisted"], !u.isNull, u.str != "ask", u.str != "deny" { return false }
    guard let a = v["allow"], !a.isNull else { return true }
    guard let arr = a.arr, arr.count <= HTTP_MAX_RULES, arr.allSatisfy({ $0.str != nil }) else { return false }
    let rules = arr.map { $0.str! }
    return Set(rules.map { Array($0.utf8).map(String.init).joined(separator: ",") }).count == rules.count && rules.allSatisfy(httpIsCanonicalRule)
}
