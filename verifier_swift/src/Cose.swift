// COSE_Sign1 (RFC 9052) checks per draft-deus-aar-02 §5.1, §6.1 (RFC 9679 kid), §8.1 (low-S), §8.4 check 2.
import Foundation
import CryptoKit

func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: Data(b))) }

enum Alg: String { case EdDSA, ES256 }
let ALG_EDDSA: Int64 = -8, ALG_ES256: Int64 = -7

struct PubKey {
    let alg: Alg
    let pub: [UInt8]       // Ed25519: 32 bytes; ES256: 65 bytes 04||x||y
    /// RFC 9679 COSE Key Thumbprint, SHA-256, required members only (§6.1)
    var thumbprint: [UInt8] {
        switch alg {
        case .EdDSA:
            let k: V = .map([(.uint(1), .uint(1)), (.nint(0), .uint(6)), (.nint(1), .bytes(pub))])
            return sha256(CBOREncoder.encode(k))
        case .ES256:
            let x = Array(pub[1..<33]), y = Array(pub[33..<65])
            let k: V = .map([(.uint(1), .uint(2)), (.nint(0), .uint(1)), (.nint(1), .bytes(x)), (.nint(2), .bytes(y))])
            return sha256(CBOREncoder.encode(k))
        }
    }
    var coseAlg: Int64 { alg == .EdDSA ? ALG_EDDSA : ALG_ES256 }

    func verify(_ sig: [UInt8], _ msg: [UInt8]) -> Bool {
        switch alg {
        case .EdDSA:
            guard let k = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
            return k.isValidSignature(Data(sig), for: Data(msg))
        case .ES256:
            guard sig.count == 64, isLowS(Array(sig[32..<64])) else { return false }   // §8.1: high-S is SIGNATURE_INVALID
            guard let k = try? P256.Signing.PublicKey(x963Representation: pub),
                  let s = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else { return false }
            return k.isValidSignature(s, for: Data(msg))
        }
    }
}

// n/2 for P-256 (floor)
let P256_HALF_N: [UInt8] = unhex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!
func isLowS(_ s: [UInt8]) -> Bool { return !lexLess(P256_HALF_N, s) || s == P256_HALF_N ? true : false }

struct Sign1 {
    let protectedBytes: [UInt8]
    let protected: V
    let unprotected: V
    let payloadBytes: [UInt8]
    let payload: V
    let signature: [UInt8]
    let raw: [UInt8]
    var alg: Int64? { protected.mapPairs?.first { $0.0 == .uint(1) }?.1.int }
    var kid: [UInt8]? { protected.mapPairs?.first { $0.0 == .uint(4) }?.1.bytes }
    var typ: String? { protected.mapPairs?.first { $0.0 == .uint(16) }?.1.str }
    var cwt: V? { protected.mapPairs?.first { $0.0 == .uint(15) }?.1 }
    var toBeSigned: [UInt8] {
        CBOREncoder.encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes([]), .bytes(payloadBytes)]))
    }
}

/// §5.1: parse and CHECK; any violation -> MALFORMED.
struct CodeErr: Error { let code: String }
func parseSign1(_ raw: [UInt8]) -> Result<Sign1, CodeErr> {
    let outer: V
    do { outer = try CBORDecoder.decodeStrict(raw, cde: false) } catch { return .failure(CodeErr(code: "MALFORMED")) }
    guard case let .tag(18, inner) = outer else { return .failure(CodeErr(code: "MALFORMED")) }       // (d) tag 18 mandatory
    guard case let .array(a) = inner, a.count == 4,
          case let .bytes(pb) = a[0], case .map = a[1], case let .bytes(sig) = a[3] else { return .failure(CodeErr(code: "MALFORMED")) }
    guard case let .bytes(payloadBytes) = a[2] else { return .failure(CodeErr(code: "MALFORMED")) }     // detached (nil) payload
    let prot: V, payload: V
    do { prot = try CBORDecoder.decodeStrict(pb) } catch { return .failure(CodeErr(code: "MALFORMED")) }
    do { payload = try CBORDecoder.decodeStrict(payloadBytes) } catch { return .failure(CodeErr(code: "MALFORMED")) }
    guard prot.isMap else { return .failure(CodeErr(code: "MALFORMED")) }
    let s = Sign1(protectedBytes: pb, protected: prot, unprotected: a[1], payloadBytes: payloadBytes,
                  payload: payload, signature: sig, raw: raw)
    // alg, kid, typ MUST be in the protected header; alg/kid only unprotected is MALFORMED
    if s.alg == nil || s.kid == nil || s.typ == nil { return .failure(CodeErr(code: "MALFORMED")) }
    return .success(s)
}

/// §8.4 check 2 (tool) / generic signature check. Returns nil if OK, else reason code.
func checkSign1(_ s: Sign1, expectedTyp: String, keys: [PubKey]) -> String? {
    if s.typ != expectedTyp { return "TYP_MISMATCH" }
    // -02 §8.4 check 2: select the key by kid first (KID_UNKNOWN), then alg must be supported and equal THAT key's (ALG_MISMATCH)
    guard let kid = s.kid, let key = keys.first(where: { $0.thumbprint == kid }) else { return "KID_UNKNOWN" }
    guard let alg = s.alg, alg == ALG_EDDSA || alg == ALG_ES256, key.coseAlg == alg else { return "ALG_MISMATCH" }
    if !key.verify(s.signature, s.toBeSigned) { return "SIGNATURE_INVALID" }
    return nil
}

func keysFrom(_ v: V?) -> [PubKey] {
    var out = [PubKey]()
    for (_, kv) in v?.mapPairs ?? [] {
        guard let a = kv["alg"]?.str, let alg = Alg(rawValue: a), let p = kv["pub"]?.str, let pub = unhex(p) else { continue }
        out.append(PubKey(alg: alg, pub: pub))
    }
    return out
}
