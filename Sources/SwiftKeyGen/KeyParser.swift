import Foundation
import Crypto

public struct KeyParser {
    
    // RFC4716 format constants
    private static let SSH_COM_PUBLIC_BEGIN = "---- BEGIN SSH2 PUBLIC KEY ----"
    private static let SSH_COM_PUBLIC_END = "---- END SSH2 PUBLIC KEY ----"
    
    /// Detect the key type from a public key string
    public static func detectKeyType(from publicKeyString: String) -> KeyType? {
        let components = publicKeyString.split(separator: " ", maxSplits: 2)
        guard components.count >= 2 else { return nil }
        
        let keyTypeString = String(components[0])
        return KeyType.allCases.first { $0.rawValue == keyTypeString }
    }
    
    /// Parse a public key string and extract its components
    public static func parsePublicKey(_ publicKeyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
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
        try validatePublicKeyData(keyData, type: keyType)
        
        // Extract comment if present
        let comment = components.count > 2 ? components[2] : nil
        
        return (type: keyType, data: keyData, comment: comment)
    }
    
    /// Validate that public key data matches the expected format
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
            guard exponent.count > 0 && modulus.count > 0 else {
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
    
    /// Calculate fingerprint from a public key string
    public static func fingerprint(from publicKeyString: String, hash: HashFunction = .sha256) throws -> String {
        let (_, keyData, _) = try parsePublicKey(publicKeyString)
        
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
    
    /// Parse an RFC4716 format public key
    public static func parseRFC4716(_ rfc4716String: String) throws -> (type: KeyType, data: Data, comment: String?) {
        let lines = rfc4716String.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        
        // Find begin and end markers
        guard let beginIndex = lines.firstIndex(of: SSH_COM_PUBLIC_BEGIN),
              let endIndex = lines.firstIndex(of: SSH_COM_PUBLIC_END),
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
        try validatePublicKeyData(keyData, type: keyType)
        
        return (type: keyType, data: keyData, comment: comment)
    }
    
    /// Detect if a string is in RFC4716 format
    public static func isRFC4716Format(_ keyString: String) -> Bool {
        return keyString.contains(SSH_COM_PUBLIC_BEGIN) && keyString.contains(SSH_COM_PUBLIC_END)
    }
    
    /// Parse a public key from any supported format
    public static func parseAnyFormat(_ keyString: String) throws -> (type: KeyType, data: Data, comment: String?) {
        if isRFC4716Format(keyString) {
            return try parseRFC4716(keyString)
        } else {
            return try parsePublicKey(keyString)
        }
    }
}