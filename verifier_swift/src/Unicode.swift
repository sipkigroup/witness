// §5.4 recipient canonicalisation. toNFKC_Casefold is taken from the system ICU
// (unorm2_getNFKCCasefoldInstance), which implements the NFKC_CF property exactly.
import Foundation

private typealias GetInst = @convention(c) (UnsafeMutablePointer<Int32>) -> OpaquePointer?
private typealias Normalize = @convention(c) (OpaquePointer?, UnsafePointer<UInt16>, Int32, UnsafeMutablePointer<UInt16>, Int32, UnsafeMutablePointer<Int32>) -> Int32

private let icu: (GetInst, Normalize)? = {
    guard let h = dlopen("/usr/lib/libicucore.A.dylib", RTLD_NOW) else { return nil }
    guard let g = dlsym(h, "unorm2_getNFKCCasefoldInstance"), let n = dlsym(h, "unorm2_normalize") else { return nil }
    return (unsafeBitCast(g, to: GetInst.self), unsafeBitCast(n, to: Normalize.self))
}()

func nfkcCasefold(_ s: String) -> String {
    guard let (g, n) = icu else { fatalError("ICU NFKC_CF not available") }
    var err: Int32 = 0
    let inst = g(&err)
    let src = Array(s.utf16)
    var cap = max(16, src.count * 4 + 16)
    while true {
        var dst = [UInt16](repeating: 0, count: cap); err = 0
        let len = src.withUnsafeBufferPointer { sp in
            dst.withUnsafeMutableBufferPointer { dp in n(inst, sp.baseAddress!, Int32(src.count), dp.baseAddress!, Int32(cap), &err) }
        }
        if err == 15 /* U_BUFFER_OVERFLOW_ERROR */ { cap = Int(len) + 16; continue }
        if err > 0 { fatalError("ICU error \(err)") }
        return String(decoding: dst[0..<Int(len)], as: UTF16.self)
    }
}

func removeWhiteSpace(_ s: String) -> String {
    return String(String.UnicodeScalarView(s.unicodeScalars.filter { !$0.properties.isWhitespace }))
}

/// Returns nil if the recipient is invalid (§5.4 step 1).
func canonRecipient(_ r: String, angle: Bool = true) -> String? {
    var x = r
    if angle && (r.contains("<") || r.contains(">")) {
        let sc = Array(r.unicodeScalars)
        let lt = sc.indices.filter { sc[$0] == "<" }, gt = sc.indices.filter { sc[$0] == ">" }
        guard lt.count == 1, gt.count == 1, gt[0] > lt[0] + 1 else { return nil }
        x = String(String.UnicodeScalarView(sc[(lt[0] + 1)..<gt[0]]))
    }
    let c = removeWhiteSpace(nfkcCasefold(x))
    // ERRATA-04 E1 (new §5.4 step 4): the canonical form MUST be exactly one mailbox, else invalid.
    return isOneMailbox(c) ? c : nil
}

/// ERRATA-04 E1: one run of [^@,;:<>()\[\]"\\] (non-empty).
private let mailboxForbidden: Set<Unicode.Scalar> = ["@", ",", ";", ":", "<", ">", "(", ")", "[", "]", "\"", "\\"]
func isMailboxPart(_ s: Substring) -> Bool {
    return !s.isEmpty && !s.unicodeScalars.contains(where: { mailboxForbidden.contains($0) })
}
/// ERRATA-04 E1: the whole canonical form matches [^@,;:<>()\[\]"\\]+ @ [^@,;:<>()\[\]"\\]+
func isOneMailbox(_ c: String) -> Bool {
    let parts = c.split(separator: "@", omittingEmptySubsequences: false)
    return parts.count == 2 && isMailboxPart(parts[0]) && isMailboxPart(parts[1])
}
/// Domain entries of a mandate (§5.4 without step 1): canonicalised; per ERRATA-04 E1 an entry that cannot be the
/// domain part of a valid mailbox (empty, or containing a forbidden character incl. `@`) matches nothing (AMBIGUITY-E-1).
func canonDomain(_ r: String) -> String? {
    let c = removeWhiteSpace(nfkcCasefold(r))
    return isMailboxPart(Substring(c)) ? c : nil
}
