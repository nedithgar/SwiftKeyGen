import Foundation

struct RFC4716Parser {
    // RFC4716 format constants
    private static let sshComPublicBegin = "---- BEGIN SSH2 PUBLIC KEY ----"
    private static let sshComPublicEnd = "---- END SSH2 PUBLIC KEY ----"

    static func isFormat(_ keyString: String) -> Bool {
        return keyString.contains(sshComPublicBegin) && keyString.contains(sshComPublicEnd)
    }

    /// Parse an RFC4716 format public key
    static func parse(_ rfc4716String: String) throws -> (type: KeyType, data: Data, comment: String?) {
        let lines = rfc4716String.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }

        // Find begin and end markers
        guard let beginIndex = lines.firstIndex(of: sshComPublicBegin),
              let endIndex = lines.firstIndex(of: sshComPublicEnd),
              beginIndex < endIndex else {
            throw SSHKeyError.invalidKeyData
        }

        var comment: String?
        var base64Lines: [String] = []

        // Process lines between markers
        for i in (beginIndex + 1)..<endIndex {
            let line = lines[i]

            // Handle headers
            if line.contains(":") && !line.hasPrefix(" ") {
                if line.hasPrefix("Comment:") {
                    // Extract comment, removing quotes if present
                    let commentPart = String(line.dropFirst("Comment:".count)).trimmingCharacters(in: .whitespaces)
                    comment = commentPart.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                }
                // Skip other headers
                continue
            }

            // Handle continuation lines (starting with space)
            if line.hasPrefix(" ") {
                if !base64Lines.isEmpty {
                    base64Lines[base64Lines.count - 1] += line.trimmingCharacters(in: .whitespaces)
                }
            } else {
                // Regular base64 line
                base64Lines.append(line)
            }
        }

        // Concatenate all base64 lines
        let base64String = base64Lines.joined()

        // Decode base64
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidKeyData
        }

        // Decode the key data to get the type
        var decoder = SSHDecoder(data: keyData)
        let keyTypeString = try decoder.decodeString()

        guard let keyType = KeyType.allCases.first(where: { $0.rawValue == keyTypeString }) else {
            throw SSHKeyError.unsupportedKeyType
        }

        // Validate the key data
        try PublicKeyParser.validatePublicKeyData(keyData, type: keyType)

        return (type: keyType, data: keyData, comment: comment)
    }
}

