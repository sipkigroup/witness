// Strict CBOR decoder (RFC 8949) that CHECKS Core Deterministic Encoding (§4.2.1),
// duplicate map keys, definite lengths; and a CDE encoder. Written from RFC 8949 only.
import Foundation

struct CBORError: Error, CustomStringConvertible {
    let kind: String   // "not-well-formed", "not-CDE", "duplicate-key", "invalid"
    let msg: String
    var description: String { "\(kind): \(msg)" }
}

struct CBORDecoder {
    let b: [UInt8]; var i = 0
    var depth = 0
    var cde = true   // false: only well-formedness + duplicate keys are checked

    /// Decode exactly one data item covering all bytes, enforcing CDE.
    static func decodeStrict(_ bytes: [UInt8], cde: Bool = true) throws -> V {
        var d = CBORDecoder(b: bytes); d.cde = cde
        let v = try d.item()
        if d.i != bytes.count { throw CBORError(kind: "not-well-formed", msg: "trailing bytes") }
        return v
    }

    mutating func byte() throws -> UInt8 {
        guard i < b.count else { throw CBORError(kind: "not-well-formed", msg: "truncated") }
        defer { i += 1 }; return b[i]
    }
    mutating func take(_ n: UInt64) throws -> [UInt8] {
        guard n <= UInt64(b.count - i) else { throw CBORError(kind: "not-well-formed", msg: "truncated") }
        defer { i += Int(n) }; return Array(b[i..<i+Int(n)])
    }
    /// argument with shortest-form check (preferred serialization)
    mutating func arg(_ ai: UInt8) throws -> UInt64 {
        switch ai {
        case 0...23: return UInt64(ai)
        case 24:
            let v = UInt64(try byte()); if v < 24 { if cde { throw CBORError(kind: "not-CDE", msg: "non-shortest int") } }; return v
        case 25:
            let x = try take(2); let v = UInt64(x[0]) << 8 | UInt64(x[1])
            if v <= 0xff { if cde { throw CBORError(kind: "not-CDE", msg: "non-shortest int") } }; return v
        case 26:
            let x = try take(4); var v: UInt64 = 0; for c in x { v = v << 8 | UInt64(c) }
            if v <= 0xffff { if cde { throw CBORError(kind: "not-CDE", msg: "non-shortest int") } }; return v
        case 27:
            let x = try take(8); var v: UInt64 = 0; for c in x { v = v << 8 | UInt64(c) }
            if v <= 0xffff_ffff { if cde { throw CBORError(kind: "not-CDE", msg: "non-shortest int") } }; return v
        case 31: throw CBORError(kind: "not-CDE", msg: "indefinite length")
        default: throw CBORError(kind: "not-well-formed", msg: "reserved additional info \(ai)")
        }
    }

    mutating func item() throws -> V {
        depth += 1; defer { depth -= 1 }
        if depth > 64 { throw CBORError(kind: "invalid", msg: "too deep") }
        let ib = try byte(); let mt = ib >> 5, ai = ib & 0x1f
        if ai == 31 && mt != 7 {
            if mt == 0 || mt == 1 || mt == 6 { throw CBORError(kind: "not-well-formed", msg: "indefinite on mt \(mt)") }
            throw CBORError(kind: "not-CDE", msg: "indefinite length")
        }
        switch mt {
        case 0: return .uint(try arg(ai))
        case 1: return .nint(try arg(ai))
        case 2: return .bytes(try take(try arg(ai)))
        case 3:
            let raw = try take(try arg(ai))
            guard let s = String(validating: raw, as: UTF8.self) else {
                throw CBORError(kind: "invalid", msg: "invalid UTF-8 in text")
            }
            return .text(s)
        case 4:
            let n = try arg(ai); var a = [V]()
            for _ in 0..<n { a.append(try item()) }
            return .array(a)
        case 5:
            let n = try arg(ai); var m = [(V, V)](); var prevKey: [UInt8]? = nil
            var seen = Set<[UInt8]>()
            for _ in 0..<n {
                let ks = i; let k = try item(); let kb = Array(b[ks..<i])
                if seen.contains(kb) { throw CBORError(kind: "duplicate-key", msg: "duplicate map key") }
                if cde, let p = prevKey, !lexLess(p, kb) { throw CBORError(kind: "not-CDE", msg: "map keys not in bytewise order") }
                seen.insert(kb); prevKey = kb
                let v = try item(); m.append((k, v))
            }
            return .map(m)
        case 6:
            let t = try arg(ai); return .tag(t, try item())
        default: // 7
            switch ai {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: return .undefined
            case 24:
                let v = try byte()
                if v < 32 { throw CBORError(kind: "not-well-formed", msg: "bad simple") }
                throw CBORError(kind: "invalid", msg: "unassigned simple value")
            case 25:
                let x = try take(2); let h = UInt16(x[0]) << 8 | UInt16(x[1])
                return .float(Double(Float16(bitPattern: h)))
            case 26:
                let x = try take(4); var v: UInt32 = 0; for c in x { v = v << 8 | UInt32(c) }
                let f = Float(bitPattern: v)
                if Double(Float16(f)) == Double(f) || f.isNaN { if cde { throw CBORError(kind: "not-CDE", msg: "float not shortest") } }
                return .float(Double(f))
            case 27:
                let x = try take(8); var v: UInt64 = 0; for c in x { v = v << 8 | UInt64(c) }
                let d = Double(bitPattern: v)
                if Double(Float(d)) == d || d.isNaN { if cde { throw CBORError(kind: "not-CDE", msg: "float not shortest") } }
                return .float(d)
            case 31: throw CBORError(kind: "not-well-formed", msg: "unexpected break")
            case 28, 29, 30: throw CBORError(kind: "not-well-formed", msg: "reserved")
            default: throw CBORError(kind: "invalid", msg: "unassigned simple value \(ai)")
            }
        }
    }
}

func lexLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    for (x, y) in zip(a, b) where x != y { return x < y }
    return a.count < b.count
}

// MARK: - CDE encoder
enum CBOREncoder {
    static func head(_ mt: UInt8, _ v: UInt64) -> [UInt8] {
        let m = mt << 5
        if v < 24 { return [m | UInt8(v)] }
        if v <= 0xff { return [m | 24, UInt8(v)] }
        if v <= 0xffff { return [m | 25, UInt8(v >> 8), UInt8(v & 0xff)] }
        if v <= 0xffff_ffff { return [m | 26] + (0..<4).reversed().map { UInt8((v >> (UInt64($0) * 8)) & 0xff) } }
        return [m | 27] + (0..<8).reversed().map { UInt8((v >> (UInt64($0) * 8)) & 0xff) }
    }
    static func encode(_ v: V) -> [UInt8] {
        switch v {
        case .null: return [0xf6]
        case .undefined: return [0xf7]
        case let .bool(b): return [b ? 0xf5 : 0xf4]
        case let .uint(u): return head(0, u)
        case let .nint(n): return head(1, n)
        case let .float(d):
            let h = Float16(d)
            if Double(h) == d || d.isNaN { let bits = (d.isNaN ? 0x7e00 : h.bitPattern); return [0xf9, UInt8(bits >> 8), UInt8(bits & 0xff)] }
            let f = Float(d)
            if Double(f) == d { let bits = f.bitPattern; return [0xfa] + (0..<4).reversed().map { UInt8((bits >> (UInt32($0) * 8)) & 0xff) } }
            let bits = d.bitPattern; return [0xfb] + (0..<8).reversed().map { UInt8((bits >> (UInt64($0) * 8)) & 0xff) }
        case let .text(s): let u = Array(s.utf8); return head(3, UInt64(u.count)) + u
        case let .bytes(b): return head(2, UInt64(b.count)) + b
        case let .array(a): return head(4, UInt64(a.count)) + a.flatMap { encode($0) }
        case let .map(m):
            let enc = m.map { (encode($0.0), encode($0.1)) }.sorted { lexLess($0.0, $1.0) }
            return head(5, UInt64(m.count)) + enc.flatMap { $0.0 + $0.1 }
        case let .tag(t, x): return head(6, t) + encode(x)
        }
    }
}

// MARK: - diagnostic printer (debug only)
func diag(_ v: V, _ ind: String = "") -> String {
    switch v {
    case .null: return "null"
    case .undefined: return "undefined"
    case let .bool(b): return b ? "true" : "false"
    case let .uint(u): return "\(u)"
    case let .nint(n): return "-\(n + 1)"
    case let .float(d): return "\(d)"
    case let .text(s): return "\"\(s)\""
    case let .bytes(b): return "h'\(hex(b))'"
    case let .array(a): return "[" + a.map { diag($0, ind) }.joined(separator: ", ") + "]"
    case let .map(m): return "{" + m.map { "\(diag($0.0)): \(diag($0.1, ind))" }.joined(separator: ", ") + "}"
    case let .tag(t, x): return "\(t)(\(diag(x, ind)))"
    }
}
