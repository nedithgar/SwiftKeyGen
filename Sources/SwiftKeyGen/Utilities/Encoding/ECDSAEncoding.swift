import Foundation

/// Helpers for ECDSA signature encoding/decoding normalization.
enum ECDSAEncoding {
    /// Build a CryptoKit-compatible raw signature (r||s) from SSH/mpint-encoded r and s.
    /// Pads each component to the fixed-width for the curve, trimming any extra leading 0x00.
    @inlinable
    static func rawSignature(r: Data, s: Data, componentLength: Int) -> Data {
        var out = Data()
        out.append(r.leftPaddedZero(to: componentLength))
        out.append(s.leftPaddedZero(to: componentLength))
        return out
    }
}

