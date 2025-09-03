// Shared helpers for reading multi-byte integer values from a Span<UInt8>
// Centralizes logic previously duplicated in Blowfish and BCrypt implementations.
// NOTE: All reads are big-endian to match OpenSSH / Blowfish expectations.
extension Span where Element == UInt8 {
    /// Reads 4 bytes from the span as a big-endian UInt32, advancing the passed
    /// offset. If the offset reaches the end of the span it wraps to the start
    /// (cyclic access) – this matches the behavior required by Blowfish key
    /// schedule and bcrypt_pbkdf expansion routines.
    /// - Parameter offset: Current read offset (will be advanced by 4, wrapping as needed)
    /// - Returns: 32-bit word constructed from 4 successive bytes (big-endian)
    @inlinable
    public func readUInt32Cyclic(offset: inout Int) -> UInt32 {
        var value: UInt32 = 0
        // Unroll fixed 4-byte accumulation for performance clarity
        for _ in 0..<4 {
            if offset >= count { offset = 0 }
            value = (value << 8) | UInt32(self[offset])
            offset += 1
        }
        return value
    }
}
