import Foundation

extension String {
    // MARK: - Line Wrapping
    /// Returns a new string wrapped at the given column width using the provided separator.
    /// Does not include a trailing separator after the last segment.
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
    /// Returns the concatenated lines between the provided begin and end markers.
    /// Empty lines can be skipped or preserved via `skipEmpty`.
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

    /// Convenience for PEM payloads: returns base64 body between PEM markers for the given type.
    /// Example type: "PRIVATE KEY", "PUBLIC KEY", "RSA PRIVATE KEY", etc.
    @inlinable
    func pemBody(type: String) -> String? {
        let begin = "-----BEGIN \(type)-----"
        let end = "-----END \(type)-----"
        return concatenatedBody(between: begin, and: end, skipEmpty: true)
    }
}

