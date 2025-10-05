import Foundation

/// Shared helpers for reading multi‑byte integer values from a `Span<UInt8>`.
///
/// Centralizes logic previously duplicated in Blowfish and BCrypt implementations.
/// All reads are big‑endian to match OpenSSH and Blowfish expectations.
extension Span where Element == UInt8 {

    @inlinable
    func toData() -> Data {
        self.withUnsafeBufferPointer { Data(buffer: $0) }
    }

    /// Read 4 bytes as a big‑endian `UInt32`, advancing `offset` cyclically.
    ///
    /// The read consumes four successive bytes starting at `offset`, wrapping
    /// back to index `0` when the end of the span is reached (cyclic access).
    /// This behavior matches requirements of the Blowfish key schedule and
    /// `bcrypt_pbkdf` expansion routines.
    ///
    /// - Parameter offset: The current read position. Advanced by 4 with wrapping.
    /// - Returns: A 32‑bit word constructed from four bytes in big‑endian order.
    /// - Complexity: O(1).
    /// - Precondition: `count > 0`. The span must not be empty.
    /// - Note: When `count < 4`, bytes are reused via wrapping to complete the
    ///   4‑byte word.
    ///
    /// - Example:
    ///   ```swift
    ///   var i = 0
    ///   let s: Span<UInt8> = Span([0xAA, 0xBB, 0xCC])
    ///   let w0 = s.readUInt32Cyclic(offset: &i)
    ///   // bytes read: AA BB CC AA -> w0 == 0xAABBCCAA, i == 1
    ///   let w1 = s.readUInt32Cyclic(offset: &i)
    ///   // bytes read: BB CC AA BB -> w1 == 0xBBCCAABB, i == 2
    ///   ```
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

    /// Read 4 successive bytes starting at `index` as a big-endian `UInt32`.
    ///
    /// Unlike ``readUInt32Cyclic(offset:)`` this does not wrap; the caller must
    /// ensure that `index + 4 <= count`. This is a convenience for non-cyclic
    /// binary decoding (e.g. SSH length fields) to centralize the big-endian
    /// accumulation logic and keep call sites concise.
    ///
    /// - Parameter index: Starting byte index (must satisfy `index + 4 <= count`).
    /// - Returns: The big-endian 32-bit unsigned integer composed of 4 bytes.
    /// - Precondition: `index >= 0 && index + 4 <= count`.
    @inlinable
    public func readUInt32BigEndian(at index: Int) -> UInt32 {
        precondition(index >= 0 && index + 4 <= count, "Index out of range for 4-byte read")
        let b0 = UInt32(self[index])
        let b1 = UInt32(self[index + 1])
        let b2 = UInt32(self[index + 2])
        let b3 = UInt32(self[index + 3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }
}
