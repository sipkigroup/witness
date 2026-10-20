// verifier_swift — independent clean-room implementation of draft-deus-aar-01.
// Unified data model for JSON (vectors) and CBOR (COSE payloads).
import Foundation

indirect enum V: Equatable {
    case null
    case undefined
    case bool(Bool)
    case uint(UInt64)          // non-negative integer
    case nint(UInt64)          // negative integer: value = -1 - n
    case float(Double)         // any float (JSON number with fraction/exponent, CBOR float)
    case text(String)
    case bytes([UInt8])
    case array([V])
    case map([(V, V)])
    case tag(UInt64, V)

    static func == (a: V, b: V) -> Bool {
        switch (a, b) {
        case (.null, .null), (.undefined, .undefined): return true
        case let (.bool(x), .bool(y)): return x == y
        case let (.uint(x), .uint(y)): return x == y
        case let (.nint(x), .nint(y)): return x == y
        case let (.float(x), .float(y)): return x == y
        case let (.text(x), .text(y)): return Array(x.utf8) == Array(y.utf8)
        case let (.bytes(x), .bytes(y)): return x == y
        case let (.array(x), .array(y)): return x == y
        case let (.map(x), .map(y)):
            // order-insensitive comparison (maps compared as sets of pairs)
            if x.count != y.count { return false }
            for (k, v) in x {
                guard let w = y.first(where: { $0.0 == k })?.1, w == v else { return false }
            }
            return true
        case let (.tag(t1, v1), .tag(t2, v2)): return t1 == t2 && v1 == v2
        default: return false
        }
    }

    subscript(_ key: String) -> V? {
        if case let .map(m) = self {
            for (k, v) in m { if case let .text(s) = k, s == key { return v } }
        }
        return nil
    }
    func has(_ key: String) -> Bool { return self[key] != nil }

    var str: String? { if case let .text(s) = self { return s }; return nil }
    var bytes: [UInt8]? { if case let .bytes(b) = self { return b }; return nil }
    var arr: [V]? { if case let .array(a) = self { return a }; return nil }
    var isNull: Bool { if case .null = self { return true }; return false }
    var boolean: Bool? { if case let .bool(b) = self { return b }; return nil }
    /// integer value if it is an integer that fits Int64
    var int: Int64? {
        switch self {
        case let .uint(u): return u <= UInt64(Int64.max) ? Int64(u) : nil
        case let .nint(n): return n < UInt64(Int64.max) ? -1 - Int64(n) : nil
        default: return nil
        }
    }
    var isMap: Bool { if case .map = self { return true }; return false }
    var mapPairs: [(V, V)]? { if case let .map(m) = self { return m }; return nil }
    var keys: [String] { (mapPairs ?? []).compactMap { $0.0.str } }

    func setting(_ key: String, _ val: V?) -> V {
        guard case var .map(m) = self else { return self }
        m.removeAll { $0.0.str == key }
        if let val = val { m.append((.text(key), val)) }
        return .map(m)
    }

    static func i(_ x: Int64) -> V { return x >= 0 ? .uint(UInt64(x)) : .nint(UInt64(-1 - x)) }
}

/// Null-or-absent helper: JSON `null` and an absent member mean the same (§6.1).
func absentOrNull(_ v: V?) -> Bool { return v == nil || v!.isNull }

func hex(_ b: [UInt8]) -> String { return b.map { String(format: "%02x", $0) }.joined() }
func unhex(_ s: String) -> [UInt8]? {
    var out = [UInt8](); out.reserveCapacity(s.count / 2)
    var it = s.utf8.makeIterator()
    func nib(_ c: UInt8) -> UInt8? {
        switch c { case 48...57: return c - 48; case 97...102: return c - 87; case 65...70: return c - 55; default: return nil }
    }
    while let a = it.next() {
        guard let b = it.next(), let x = nib(a), let y = nib(b) else { return nil }
        out.append(x << 4 | y)
    }
    return out
}

// MARK: - JSON parser that keeps integer vs float (§5.2, App. A convention 4)

struct JSONError: Error { let msg: String }

struct JSONParser {
    let s: [UInt8]; var i = 0
    init(_ data: [UInt8]) { s = data }

    static func parse(_ data: Data) throws -> V {
        var p = JSONParser([UInt8](data))
        p.ws(); let v = try p.value(); p.ws()
        if p.i != p.s.count { throw JSONError(msg: "trailing") }
        return v
    }
    mutating func ws() { while i < s.count, [9, 10, 13, 32].contains(s[i]) { i += 1 } }
    mutating func value() throws -> V {
        guard i < s.count else { throw JSONError(msg: "eof") }
        switch s[i] {
        case UInt8(ascii: "{"):
            i += 1; ws(); var m = [(V, V)]()
            if s[i] == UInt8(ascii: "}") { i += 1; return .map(m) }
            while true {
                ws(); let k = try string(); ws()
                guard s[i] == UInt8(ascii: ":") else { throw JSONError(msg: ":") }
                i += 1; ws(); let v = try value(); ws()
                m.append((.text(k), v))
                if s[i] == UInt8(ascii: ",") { i += 1; continue }
                if s[i] == UInt8(ascii: "}") { i += 1; return .map(m) }
                throw JSONError(msg: "obj")
            }
        case UInt8(ascii: "["):
            i += 1; ws(); var a = [V]()
            if s[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
            while true {
                ws(); a.append(try value()); ws()
                if s[i] == UInt8(ascii: ",") { i += 1; continue }
                if s[i] == UInt8(ascii: "]") { i += 1; return .array(a) }
                throw JSONError(msg: "arr")
            }
        case UInt8(ascii: "\""): return .text(try string())
        case UInt8(ascii: "t"): i += 4; return .bool(true)
        case UInt8(ascii: "f"): i += 5; return .bool(false)
        case UInt8(ascii: "n"): i += 4; return .null
        default: return try number()
        }
    }
    mutating func number() throws -> V {
        let st = i; var isFloat = false
        if s[i] == UInt8(ascii: "-") { i += 1 }
        while i < s.count {
            let c = s[i]
            if c >= 48 && c <= 57 { i += 1 }
            else if c == UInt8(ascii: ".") || c == UInt8(ascii: "e") || c == UInt8(ascii: "E") || c == UInt8(ascii: "+") || c == UInt8(ascii: "-") { isFloat = true; i += 1 }
            else { break }
        }
        let lit = String(decoding: s[st..<i], as: UTF8.self)
        if isFloat { return .float(Double(lit) ?? .nan) }
        if lit.hasPrefix("-") {
            guard let u = UInt64(lit.dropFirst()) else { return .float(Double(lit) ?? .nan) }
            return u == 0 ? .uint(0) : .nint(u - 1)
        }
        guard let u = UInt64(lit) else { return .float(Double(lit) ?? .nan) }
        return .uint(u)
    }
    mutating func string() throws -> String {
        guard s[i] == UInt8(ascii: "\"") else { throw JSONError(msg: "str") }
        i += 1; var out = [UInt8]()
        while true {
            let c = s[i]; i += 1
            if c == UInt8(ascii: "\"") { break }
            if c == UInt8(ascii: "\\") {
                let e = s[i]; i += 1
                switch e {
                case UInt8(ascii: "n"): out.append(10)
                case UInt8(ascii: "t"): out.append(9)
                case UInt8(ascii: "r"): out.append(13)
                case UInt8(ascii: "b"): out.append(8)
                case UInt8(ascii: "f"): out.append(12)
                case UInt8(ascii: "u"):
                    var cp = UInt32(String(decoding: s[i..<i+4], as: UTF8.self), radix: 16)!; i += 4
                    if cp >= 0xD800 && cp < 0xDC00, s[i] == UInt8(ascii: "\\"), s[i+1] == UInt8(ascii: "u") {
                        let lo = UInt32(String(decoding: s[i+2..<i+6], as: UTF8.self), radix: 16)!; i += 6
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                    }
                    out.append(contentsOf: Array(String(Character(Unicode.Scalar(cp)!)).utf8))
                default: out.append(e)
                }
            } else { out.append(c) }
        }
        return String(decoding: out, as: UTF8.self)
    }
}
