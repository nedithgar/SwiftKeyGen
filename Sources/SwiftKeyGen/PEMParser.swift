import Foundation
import Crypto
import _CryptoExtras

/// Parser for PEM and PKCS#8 format keys
public struct PEMParser {
    
    // MARK: - RSA Key Parsing
    
    /// Parse an RSA public key from PEM format
    public static func parseRSAPublicKey(_ pemString: String) throws -> RSAPublicKey {
        // Use Swift Crypto's built-in PEM parser
        let publicKey = try _RSA.Signing.PublicKey(pemRepresentation: pemString)
        
        // Extract modulus and exponent from the public key's DER representation
        let (modulus, exponent) = try Insecure.RSA.extractPublicKeyComponents(from: publicKey.derRepresentation)
        
        return try RSAPublicKey(modulus: modulus, exponent: exponent)
    }
    
    // MARK: - ECDSA Key Parsing
    
    /// Parse an ECDSA public key from PEM format
    public static func parseECDSAPublicKey(_ pemString: String) throws -> ECDSAPublicKey {
        // First try the standard Swift Crypto PEM parser
        if let p256Key = try? P256.Signing.PublicKey(pemRepresentation: pemString) {
            return try ECDSAPublicKey(
                keyType: .ecdsa256,
                curveName: "nistp256",
                publicKeyPoint: p256Key.x963Representation
            )
        } else if let p384Key = try? P384.Signing.PublicKey(pemRepresentation: pemString) {
            return try ECDSAPublicKey(
                keyType: .ecdsa384,
                curveName: "nistp384",
                publicKeyPoint: p384Key.x963Representation
            )
        } else if let p521Key = try? P521.Signing.PublicKey(pemRepresentation: pemString) {
            return try ECDSAPublicKey(
                keyType: .ecdsa521,
                curveName: "nistp521",
                publicKeyPoint: p521Key.x963Representation
            )
        }
        
        // If standard parsing fails, try our improved PKCS#8 parsing approach
        return try parseECDSAPublicKeyFromPKCS8(pemString)
    }
    
    /// Parse ECDSA public key from PKCS#8 format using simplified approach
    private static func parseECDSAPublicKeyFromPKCS8(_ pemString: String) throws -> ECDSAPublicKey {
        // Extract DER data from PEM
        let base64Content = pemString
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard let derData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Find the curve OID by looking for the pattern: 06 <length> <oid_bytes>
        // after the ecPublicKey OID (2a8648ce3d0201)
        guard let curveOidInfo = findCurveOID(in: derData) else {
            throw SSHKeyError.invalidKeyData
        }
        
        let curveType = try determineCurveTypeFromOID(curveOidInfo.oid)
        
        // Extract raw key bytes based on curve type
        let rawKeyBytes = try extractRawKeyBytes(from: derData, forCurve: curveType)
        
        // Create the appropriate key type using rawRepresentation
        switch curveType {
        case .ecdsa256:
            let p256Key = try P256.Signing.PublicKey(rawRepresentation: rawKeyBytes)
            return try ECDSAPublicKey(
                keyType: .ecdsa256,
                curveName: "nistp256",
                publicKeyPoint: p256Key.x963Representation
            )
        case .ecdsa384:
            let p384Key = try P384.Signing.PublicKey(rawRepresentation: rawKeyBytes)
            return try ECDSAPublicKey(
                keyType: .ecdsa384,
                curveName: "nistp384",
                publicKeyPoint: p384Key.x963Representation
            )
        case .ecdsa521:
            let p521Key = try P521.Signing.PublicKey(rawRepresentation: rawKeyBytes)
            return try ECDSAPublicKey(
                keyType: .ecdsa521,
                curveName: "nistp521",
                publicKeyPoint: p521Key.x963Representation
            )
        default:
            throw SSHKeyError.unsupportedOperation("Unsupported ECDSA curve type")
        }
    }
    
    /// Find curve OID in DER data
    private static func findCurveOID(in derData: Data) -> (oid: Data, position: Int)? {
        // Look for the ecPublicKey OID first: 2a8648ce3d0201
        let ecPublicKeyOID = Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
        
        guard let ecPublicKeyPosition = derData.range(of: ecPublicKeyOID)?.upperBound else {
            return nil
        }
        
        // The curve OID should be the next OID after ecPublicKey
        var index = ecPublicKeyPosition
        
        // Skip any padding and look for the next OID tag (0x06)
        while index < derData.count && derData[index] != 0x06 {
            index += 1
        }
        
        guard index < derData.count && derData[index] == 0x06 else {
            return nil
        }
        
        index += 1  // Skip OID tag
        guard index < derData.count else {
            return nil
        }
        
        let oidLength = Int(derData[index])
        index += 1
        
        guard index + oidLength <= derData.count else {
            return nil
        }
        
        let oid = derData[index..<index + oidLength]
        return (Data(oid), index)
    }
    
    /// Extract raw key bytes for the specified curve
    private static func extractRawKeyBytes(from derData: Data, forCurve curve: KeyType) throws -> Data {
        // Different curves have different coordinate sizes:
        // P-256: 32 bytes * 2 = 64 bytes
        // P-384: 48 bytes * 2 = 96 bytes  
        // P-521: 66 bytes * 2 = 132 bytes
        
        let expectedRawSize: Int
        switch curve {
        case .ecdsa256:
            expectedRawSize = 64
        case .ecdsa384:
            expectedRawSize = 96
        case .ecdsa521:
            expectedRawSize = 132
        default:
            throw SSHKeyError.unsupportedOperation("Unsupported curve type")
        }
        
        // The raw key bytes should be at the end, after skipping the 0x04 prefix
        guard derData.count >= expectedRawSize + 1 else {
            throw SSHKeyError.invalidKeyData
        }
        
        return derData.suffix(expectedRawSize)
    }
    
    
    /// Determine curve type from OID
    private static func determineCurveTypeFromOID(_ oid: Data) throws -> KeyType {
        let oidHex = oid.map { String(format: "%02x", $0) }.joined()
        
        switch oidHex {
        case "2a8648ce3d030107":  // 1.2.840.10045.3.1.7 (secp256r1/P-256)
            return .ecdsa256
        case "2b81040022":        // 1.3.132.0.34 (secp384r1/P-384)
            return .ecdsa384
        case "2b81040023":        // 1.3.132.0.35 (secp521r1/P-521)
            return .ecdsa521
        default:
            throw SSHKeyError.unsupportedOperation("Unknown curve OID: \(oidHex)")
        }
    }
    
    // MARK: - Ed25519 Key Parsing
    
    /// Parse an Ed25519 public key from PEM format
    public static func parseEd25519PublicKey(_ pemString: String) throws -> Ed25519PublicKey {
        let publicKey = try Curve25519.Signing.PublicKey(pemRepresentation: pemString)
        return try Ed25519PublicKey(publicKeyData: publicKey.rawRepresentation)
    }
    
    /// Parse an RSA private key from PEM format
    public static func parseRSAPrivateKey(_ pemString: String, passphrase: String? = nil) throws -> RSAKey {
        // Note: Swift Crypto doesn't support encrypted PEM, so passphrase is ignored
        // In a real implementation, we'd need to decrypt first
        if passphrase != nil {
            throw SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")
        }
        
        let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: pemString)
        return RSAKey(privateKey: privateKey)
    }
    
    /// Parse an ECDSA private key from PEM format
    public static func parseECDSAPrivateKey(_ pemString: String, passphrase: String? = nil) throws -> ECDSAKey {
        // Note: Swift Crypto doesn't support encrypted PEM, so passphrase is ignored
        if passphrase != nil {
            throw SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")
        }
        
        // Try to parse as different curve types
        if let p256Key = try? P256.Signing.PrivateKey(pemRepresentation: pemString) {
            return ECDSAKey(p256Key: p256Key)
        } else if let p384Key = try? P384.Signing.PrivateKey(pemRepresentation: pemString) {
            return ECDSAKey(p384Key: p384Key)
        } else if let p521Key = try? P521.Signing.PrivateKey(pemRepresentation: pemString) {
            return ECDSAKey(p521Key: p521Key)
        } else {
            throw SSHKeyError.unsupportedOperation("Unable to parse ECDSA private key")
        }
    }
    
    /// Parse an Ed25519 private key from PEM format
    public static func parseEd25519PrivateKey(_ pemString: String, passphrase: String? = nil) throws -> Ed25519Key {
        // Note: Swift Crypto doesn't support encrypted PEM, so passphrase is ignored
        if passphrase != nil {
            throw SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")
        }
        
        let privateKey = try Curve25519.Signing.PrivateKey(pemRepresentation: pemString)
        return Ed25519Key(privateKey: privateKey)
    }
    
    /// Check if a string is in PEM format
    public static func isPEMFormat(_ keyString: String) -> Bool {
        return keyString.contains("-----BEGIN") && keyString.contains("-----END")
    }
    
    /// Detect PEM type from string
    public static func detectPEMType(_ pemString: String) -> String? {
        let lines = pemString.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") && line.hasSuffix("-----") {
                let startIdx = line.index(line.startIndex, offsetBy: 11) // "-----BEGIN ".count
                let endIdx = line.index(line.endIndex, offsetBy: -5) // "-----".count
                return String(line[startIdx..<endIdx])
            }
        }
        
        return nil
    }
    
    /// Check if PEM contains a private key
    public static func isPrivateKey(_ pemString: String) -> Bool {
        guard let pemType = detectPEMType(pemString) else { return false }
        return pemType.contains("PRIVATE")
    }
    
    /// Try to detect the key algorithm from PEM type
    public static func detectKeyAlgorithm(_ pemString: String) -> String? {
        guard let pemType = detectPEMType(pemString) else { return nil }
        
        if pemType.contains("RSA") {
            return "RSA"
        } else if pemType.contains("EC") && !pemType.contains("ENCRYPTED") {
            return "ECDSA"
        } else if pemType == "PRIVATE KEY" || pemType == "PUBLIC KEY" {
            // Need to try parsing to determine the algorithm
            return nil
        }
        
        return nil
    }
}