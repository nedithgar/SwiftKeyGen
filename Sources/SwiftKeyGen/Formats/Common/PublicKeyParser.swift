import Foundation
import Crypto

public struct PublicKeyParser {
    /// Detect if a string is in RFC4716 format
    public static func isRFC4716Format(_ keyString: String) -> Bool {
        return RFC4716Parser.isFormat(keyString)
    }

    /// Detect the key type from a public key string (OpenSSH or RFC4716)
    public static func detectKeyType(from publicKeyString: String) -> KeyType? {
        if isRFC4716Format(publicKeyString) {
            // Decode the RFC4716 block to extract the type
            if let parsed = try? RFC4716Parser.parse(publicKeyString) {
                return parsed.type
            }
            return nil
        } else {
            return OpenSSHPublicKeyParser.detectKeyType(from: publicKeyString)
        }
    }

    /// Parse an OpenSSH-format public key string
    public static func parsePublicKey(_ publicKeyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        return try OpenSSHPublicKeyParser.parse(publicKeyString)
    }

    /// Parse an RFC4716 format public key
    public static func parseRFC4716(_ rfc4716String: String) throws -> (type: KeyType, data: Data, comment: String?) {
        return try RFC4716Parser.parse(rfc4716String)
    }

    /// Parse a public key from any supported format
    public static func parseAnyFormat(_ keyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        if isRFC4716Format(keyString) {
            return try parseRFC4716(keyString)
        } else {
            return try parsePublicKey(keyString)
        }
    }

    /// Validate that public key data matches the expected SSH binary encoding for the type
    public static func validatePublicKeyData(_ data: Data, type: KeyType) throws {
        var decoder = SSHDecoder(data: data)

        // Verify key type in data matches
        let encodedType = try decoder.decodeString()
        guard encodedType == type.rawValue else {
            throw SSHKeyError.invalidKeyData
        }

        // Validate key-specific data
        switch type {
        case .ed25519:
            let publicKeyBytes = try decoder.decodeData()
            guard publicKeyBytes.count == 32 else {
                throw SSHKeyError.invalidKeyData
            }

        case .rsa:
            let exponent = try decoder.decodeData()
            let modulus = try decoder.decodeData()
            guard !exponent.isEmpty && !modulus.isEmpty else {
                throw SSHKeyError.invalidKeyData
            }

        case .ecdsa256, .ecdsa384, .ecdsa521:
            let curveIdentifier = try decoder.decodeString()
            let expectedCurve: String
            let expectedKeySize: Int

            switch type {
            case .ecdsa256:
                expectedCurve = "nistp256"
                expectedKeySize = 65 // 0x04 + 32 + 32
            case .ecdsa384:
                expectedCurve = "nistp384"
                expectedKeySize = 97 // 0x04 + 48 + 48
            case .ecdsa521:
                expectedCurve = "nistp521"
                expectedKeySize = 133 // 0x04 + 66 + 66
            default:
                throw SSHKeyError.invalidKeyData
            }

            guard curveIdentifier == expectedCurve else {
                throw SSHKeyError.invalidKeyData
            }

            let publicKeyBytes = try decoder.decodeData()
            guard publicKeyBytes.count == expectedKeySize else {
                throw SSHKeyError.invalidKeyData
            }
        }

        // Ensure no extra data
        guard !decoder.hasMoreData else {
            throw SSHKeyError.invalidKeyData
        }
    }

    /// Calculate fingerprint from a public key in either OpenSSH or RFC4716 format
    public static func fingerprint(from keyString: String, hash: HashFunction = .sha256) throws -> String {
        let (_, keyData, _) = try parseAnyFormat(keyString)

        switch hash {
        case .md5:
            let digest = Insecure.MD5.hash(data: keyData)
            return digest.map { String(format: "%02x", $0) }.joined(separator: ":")

        case .sha256:
            let digest = SHA256.hash(data: keyData)
            let base64 = Data(digest).base64EncodedString()
                .trimmingCharacters(in: CharacterSet(charactersIn: "="))
            return "SHA256:" + base64

        case .sha512:
            let digest = SHA512.hash(data: keyData)
            let base64 = Data(digest).base64EncodedString()
                .trimmingCharacters(in: CharacterSet(charactersIn: "="))
            return "SHA512:" + base64
        }
    }
}

