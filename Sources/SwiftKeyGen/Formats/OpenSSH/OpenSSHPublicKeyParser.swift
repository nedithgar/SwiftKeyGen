import Foundation

struct OpenSSHPublicKeyParser {
    /// Detect the key type from an OpenSSH public key string
    static func detectKeyType(from publicKeyString: String) -> KeyType? {
        let components = publicKeyString.split(separator: " ", maxSplits: 2)
        guard components.count >= 2 else { return nil }

        let keyTypeString = String(components[0])
        return KeyType.allCases.first { $0.rawValue == keyTypeString }
    }

    /// Parse an OpenSSH public key string and extract its components
    static func parse(_ publicKeyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        let components = publicKeyString.split(separator: " ", maxSplits: 2).map(String.init)
        guard components.count >= 2 else {
            throw SSHKeyError.invalidKeyData
        }

        // Parse key type
        guard let keyType = KeyType.allCases.first(where: { $0.rawValue == components[0] }) else {
            throw SSHKeyError.unsupportedKeyType
        }

        // Decode base64 key data
        guard let keyData = Data(base64Encoded: components[1]) else {
            throw SSHKeyError.invalidKeyData
        }

        // Validate the key data
        try PublicKeyParser.validatePublicKeyData(keyData, type: keyType)

        // Extract comment if present
        let comment = components.count > 2 ? components[2] : nil

        return (type: keyType, data: keyData, comment: comment)
    }
}

