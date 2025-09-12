import Foundation

/// Convenience utilities for common string processing used across SwiftKeyGen.
///
/// - Important: Keep helpers here format‑agnostic and broadly reusable.
///   Prefer adding cross‑cutting extensions in `Sources/SwiftKeyGen/Extensions/`.
extension String {
    // MARK: - Line Wrapping
    /// Wrap this string into fixed‑width segments joined by `separator`.
    ///
    /// The operation respects `Character` boundaries and does not append a
    /// trailing separator after the final segment.
    ///
    /// - Parameters:
    ///   - count: Maximum number of characters per segment. Must be positive.
    ///   - separator: String inserted between segments. Defaults to a newline.
    /// - Returns: A new string composed of wrapped segments.
    /// - Complexity: O(n), where `n` is the number of characters.
    /// - Note: This wraps by characters, not bytes; multi‑scalar graphemes are preserved.
    ///
    /// - Example:
    ///   ```swift
    ///   let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ///   let wrapped = s.wrapped(every: 5)
    ///   // "ABCDE\nFGHIJ\nKLMNO\nPQRST\nUVWXY\nZ"
    ///   ```
    @inlinable
    func wrapped(every count: Int, separator: String = "\n") -> String {
        guard count > 0, !isEmpty else { return self }

        var result = String()
        result.reserveCapacity(self.count + self.count / count)

        var index = startIndex
        while index < endIndex {
            let end = self.index(index, offsetBy: count, limitedBy: endIndex) ?? endIndex
            result += self[index..<end]
            if end < endIndex { result += separator }
            index = end
        }
        return result
    }

    // MARK: - Marker Utilities
    /// Return the concatenated content between `beginMarker` and `endMarker` lines.
    ///
    /// The search is performed line‑by‑line. Once a line containing `beginMarker`
    /// is encountered, subsequent lines are concatenated until a line containing
    /// `endMarker` is found. When `skipEmpty` is `true`, empty lines are ignored.
    ///
    /// - Parameters:
    ///   - beginMarker: Text that identifies the start boundary (line containing it is not included).
    ///   - endMarker: Text that identifies the end boundary (line containing it is not included).
    ///   - skipEmpty: Whether to omit empty lines from the result. Defaults to `true`.
    /// - Returns: The concatenated body if any content was captured, otherwise `nil`.
    /// - Discussion: Useful for extracting base64 bodies from header/footer framed
    ///   formats such as PEM blocks or SSH key material.
    /// - SeeAlso: ``pemBody(type:)``
    ///
    /// - Example:
    ///   ```swift
    ///   let text = """
    ///   -----BEGIN SAMPLE-----
    ///   YmFzZTY0Cg==
    ///   Ym9keQ==
    ///   -----END SAMPLE-----
    ///   """
    ///   let body = text.concatenatedBody(between: "-----BEGIN SAMPLE-----",
    ///                                     and: "-----END SAMPLE-----")
    ///   // body == "YmFzZTY0Cg==Ym9keQ=="
    ///   ```
    @inlinable
    func concatenatedBody(between beginMarker: String, and endMarker: String, skipEmpty: Bool = true) -> String? {
        let lines = self.components(separatedBy: .newlines)
        var inBody = false
        var body = String()

        for line in lines {
            if !inBody {
                if line.contains(beginMarker) { inBody = true }
                continue
            }
            if line.contains(endMarker) { break }
            if skipEmpty && line.isEmpty { continue }
            body += line
        }

        return body.isEmpty ? nil : body
    }

    /// Extract the base64 payload inside a PEM block of the given `type`.
    ///
    /// - Parameter type: The PEM block type (e.g., "PRIVATE KEY", "PUBLIC KEY",
    ///   "RSA PRIVATE KEY"). The function looks for lines matching
    ///   `-----BEGIN <type>-----` and `-----END <type>-----`.
    /// - Returns: The concatenated base64 body without newlines, or `nil` if no
    ///   matching block is found.
    /// - SeeAlso: ``concatenatedBody(between:and:skipEmpty:)``
    ///
    /// - Example:
    ///   ```swift
    ///   let pem = """
    ///   -----BEGIN PUBLIC KEY-----
    ///   QUJD
    ///   Rkdo
    ///   -----END PUBLIC KEY-----
    ///   """
    ///   let body = pem.pemBody(type: "PUBLIC KEY")
    ///   // body == "QUJDRkdo"
    ///   ```
    @inlinable
    func pemBody(type: String) -> String? {
        let begin = "-----BEGIN \(type)-----"
        let end = "-----END \(type)-----"
        return concatenatedBody(between: begin, and: end, skipEmpty: true)
    }
}
