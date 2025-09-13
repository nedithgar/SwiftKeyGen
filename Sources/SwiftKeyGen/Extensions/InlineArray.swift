import Foundation

/// Utilities for bridging fixed‑size inline byte arrays to `Data`.
///
/// InlineArray provides inline, fixed‑capacity storage. This extension offers
/// a convenience to obtain an owned `Data` buffer when interoperability with
/// higher‑level APIs is required.
extension InlineArray where Element == UInt8 {
    /// Return a `Data` copy of the inline bytes.
    ///
    /// - Returns: A new `Data` value containing the same bytes in order.
    /// - Complexity: O(n) to copy `n` bytes.
    /// - Important: This performs a copy into heap‑backed storage. Prefer using
    ///   `Span` when a non‑owning view is sufficient to avoid allocations.
    /// - Example:
    ///   ```swift
    ///   // Assuming `bytes` is an InlineArray<UInt8>
    ///   let data: Data = bytes.toData()
    ///   ```
    @inlinable 
    func toData() -> Data {
        let count = self.span.count
        var dataBuffer = Data(count: count)
        for index in 0..<count { dataBuffer[index] = self[index] }
        return dataBuffer
    }
}
