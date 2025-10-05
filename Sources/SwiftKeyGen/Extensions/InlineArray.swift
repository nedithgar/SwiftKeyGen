import Foundation

/// Utilities for bridging fixed‑size inline byte arrays to `Data`.
///
/// InlineArray provides inline, fixed‑capacity storage. This extension offers
/// a convenience to obtain an owned `Data` buffer when interoperability with
/// higher‑level APIs is required.
extension InlineArray where Element == UInt8 {
    /// Returns a new `Data` value containing a copy of the bytes stored in this inline array.
    ///
    /// Use this helper when you need an owned, heap‑backed buffer for APIs that
    /// require `Data` instead of a lightweight `Span` view.
    ///
    /// ```swift
    /// let inline: InlineArray<UInt8> = /* ... */
    /// let data = inline.toData()
    /// // `data` is an independent copy; mutating it will not affect `inline`.
    /// ```
    ///
    /// - Returns: A freshly allocated `Data` instance containing the bytes in order.
    /// - Complexity: O(*n*) where *n* is the number of bytes (`count`).
    /// - Important: This allocates and copies. Prefer using the non‑owning `span`
    ///   (or passing that span onward) when you only need a transient view to
    ///   avoid unnecessary heap traffic.
    /// - SeeAlso: ``Span/toData()``
    @inlinable 
    func toData() -> Data {
        self.span.toData()
    }
}
