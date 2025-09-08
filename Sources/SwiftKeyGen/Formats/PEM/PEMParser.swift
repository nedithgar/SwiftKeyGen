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
    
    // RSA private key parsing is now implemented in RSA+PEM.swift
    
    /// Parse an ECDSA private key from PEM format
    public static func parseECDSAPrivateKey(_ pemString: String, passphrase: String? = nil) throws -> ECDSAKey {
        let trimmedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check if it's encrypted
        if isEncryptedPEM(trimmedPEM) {
            guard let passphrase = passphrase else {
                throw SSHKeyError.passphraseRequired
            }
            return try parseEncryptedECDSAPrivateKey(trimmedPEM, passphrase: passphrase)
        } else {
            // Unencrypted - try to parse as different curve types
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
    }
    
    /// Parse encrypted ECDSA private key
    private static func parseEncryptedECDSAPrivateKey(_ pemString: String, passphrase: String) throws -> ECDSAKey {
        // Extract headers and encrypted data
        let lines = pemString.components(separatedBy: "\n")
        
        var dekInfo: String?
        var base64Lines: [String] = []
        var inBody = false
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") {
                continue
            } else if line.hasPrefix("-----END") {
                break
            } else if line.hasPrefix("DEK-Info:") {
                dekInfo = line.replacingOccurrences(of: "DEK-Info:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.isEmpty {
                inBody = true
            } else if inBody {
                base64Lines.append(line)
            }
        }
        
        guard let dekInfoStr = dekInfo else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse DEK-Info: cipher,iv
        let dekParts = dekInfoStr.split(separator: ",").map { String($0) }
        guard dekParts.count == 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let cipherName = dekParts[0]
        let ivHex = dekParts[1]
        
        guard let cipher = PEMEncryption.PEMCipher(rawValue: cipherName) else {
            throw SSHKeyError.unsupportedCipher(cipherName)
        }
        
        guard let iv = Data(hexString: ivHex) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decode encrypted data
        let base64Content = base64Lines.joined()
        guard let encryptedData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decrypt
        let decryptedData = try PEMEncryption.decrypt(
            data: encryptedData,
            passphrase: passphrase,
            cipher: cipher,
            iv: iv
        )
        
        // Parse decrypted data as EC private key
        return try parseECDSAPrivateKeyFromDER(decryptedData)
    }
    
    /// Parse ECDSA private key from DER data (SEC1 or PKCS#8 format)
    private static func parseECDSAPrivateKeyFromDER(_ derData: Data) throws -> ECDSAKey {
        // First try to parse as SEC1 format (traditional EC private key)
        // If that fails, try PKCS#8 format
        
        var parser = ASN1Parser(data: derData)
        
        // Check the first tag
        guard parser.offset < derData.count else {
            throw SSHKeyError.invalidKeyData
        }
        
        let firstTag = derData[parser.offset]
        
        if firstTag == 0x30 {
            // SEQUENCE - could be either format
            parser.offset += 1
            _ = try parser.parseLength()
            
            // Look at the first element
            guard let firstElementData = try parser.parseInteger() else {
                throw SSHKeyError.invalidKeyData
            }
            
            if firstElementData.count == 1 && firstElementData[0] <= 1 {
                // Version field - likely SEC1 format
                return try parseECDSAPrivateKeyFromSEC1(derData)
            } else {
                // Likely PKCS#8 format
                return try parseECDSAPrivateKeyFromPKCS8(derData)
            }
        }
        
        throw SSHKeyError.invalidKeyData
    }
    
    /// Parse ECDSA private key from SEC1 format
    private static func parseECDSAPrivateKeyFromSEC1(_ derData: Data) throws -> ECDSAKey {
        // SEC1 format:
        // SEQUENCE {
        //   INTEGER version (1)
        //   OCTET STRING privateKey
        //   [0] OID curveOID OPTIONAL
        //   [1] BIT STRING publicKey OPTIONAL
        // }
        
        var parser = ASN1Parser(data: derData)
        
        // Skip SEQUENCE
        guard parser.offset < derData.count && derData[parser.offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        parser.offset += 1
        _ = try parser.parseLength()
        
        // Parse version (should be 1)
        guard let versionData = try parser.parseInteger(),
              versionData.count == 1 && versionData[0] == 1 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse private key OCTET STRING
        guard let privateKeyData = try parser.parseOctetString() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Try to find curve OID (tagged with [0])
        var curveType: KeyType?
        if parser.offset < derData.count && derData[parser.offset] == 0xa0 {
            parser.offset += 1
            let tagLength = try parser.parseLength()
            let tagEnd = parser.offset + tagLength
            
            // Parse the OID inside the tag
            if let oid = try parser.parseObjectIdentifier() {
                curveType = try determineCurveTypeFromOID(oid)
            }
            
            parser.offset = tagEnd
        }
        
        // If we couldn't determine curve from OID, try from key length
        if curveType == nil {
            switch privateKeyData.count {
            case 32:
                curveType = .ecdsa256
            case 48:
                curveType = .ecdsa384
            case 65, 66:
                curveType = .ecdsa521
            default:
                throw SSHKeyError.invalidKeyData
            }
        }
        
        // Create the appropriate key
        switch curveType! {
        case .ecdsa256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
            return ECDSAKey(p256Key: key)
        case .ecdsa384:
            let key = try P384.Signing.PrivateKey(rawRepresentation: privateKeyData)
            return ECDSAKey(p384Key: key)
        case .ecdsa521:
            let key = try P521.Signing.PrivateKey(rawRepresentation: privateKeyData)
            return ECDSAKey(p521Key: key)
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Parse ECDSA private key from PKCS#8 format
    private static func parseECDSAPrivateKeyFromPKCS8(_ derData: Data) throws -> ECDSAKey {
        // PKCS#8 format for EC:
        // SEQUENCE {
        //   INTEGER version (0)
        //   SEQUENCE {
        //     OBJECT IDENTIFIER ecPublicKey (1.2.840.10045.2.1)
        //     OBJECT IDENTIFIER curveOID
        //   }
        //   OCTET STRING privateKey {
        //     SEC1 private key structure
        //   }
        // }
        
        var parser = ASN1Parser(data: derData)
        
        // Skip outer SEQUENCE
        guard parser.offset < derData.count && derData[parser.offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        parser.offset += 1
        _ = try parser.parseLength()
        
        // Parse version (should be 0)
        guard let versionData = try parser.parseInteger(),
              versionData.count == 1 && versionData[0] == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse algorithm identifier SEQUENCE
        guard parser.offset < derData.count && derData[parser.offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        parser.offset += 1
        let algSeqLength = try parser.parseLength()
        let algSeqEnd = parser.offset + algSeqLength
        
        // Skip ecPublicKey OID
        _ = try parser.parseObjectIdentifier()
        
        // Parse curve OID
        guard let curveOID = try parser.parseObjectIdentifier() else {
            throw SSHKeyError.invalidKeyData
        }
        
        let curveType = try determineCurveTypeFromOID(curveOID)
        
        // Skip to end of algorithm sequence
        parser.offset = algSeqEnd
        
        // Parse OCTET STRING containing the private key
        guard let privateKeyOctet = try parser.parseOctetString() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // The OCTET STRING contains a SEC1 private key structure
        return try parseECDSAPrivateKeyFromSEC1(privateKeyOctet)
    }
    
    /// Parse an Ed25519 private key from PEM format
    public static func parseEd25519PrivateKey(_ pemString: String, passphrase: String? = nil) throws -> Ed25519Key {
        let trimmedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check if it's encrypted
        if isEncryptedPEM(trimmedPEM) {
            guard let passphrase = passphrase else {
                throw SSHKeyError.passphraseRequired
            }
            return try parseEncryptedEd25519PrivateKey(trimmedPEM, passphrase: passphrase)
        } else {
            // Unencrypted - use Swift Crypto directly
            let privateKey = try Curve25519.Signing.PrivateKey(pemRepresentation: pemString)
            return Ed25519Key(privateKey: privateKey)
        }
    }
    
    /// Check if PEM is encrypted
    private static func isEncryptedPEM(_ pemString: String) -> Bool {
        return pemString.contains("Proc-Type:") && pemString.contains("DEK-Info:")
    }
    
    /// Parse encrypted Ed25519 private key
    private static func parseEncryptedEd25519PrivateKey(_ pemString: String, passphrase: String) throws -> Ed25519Key {
        // Extract headers and encrypted data
        let lines = pemString.components(separatedBy: "\n")
        
        var dekInfo: String?
        var base64Lines: [String] = []
        var inBody = false
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") {
                continue
            } else if line.hasPrefix("-----END") {
                break
            } else if line.hasPrefix("DEK-Info:") {
                dekInfo = line.replacingOccurrences(of: "DEK-Info:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.isEmpty {
                inBody = true
            } else if inBody {
                base64Lines.append(line)
            }
        }
        
        guard let dekInfoStr = dekInfo else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse DEK-Info: cipher,iv
        let dekParts = dekInfoStr.split(separator: ",").map { String($0) }
        guard dekParts.count == 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let cipherName = dekParts[0]
        let ivHex = dekParts[1]
        
        guard let cipher = PEMEncryption.PEMCipher(rawValue: cipherName) else {
            throw SSHKeyError.unsupportedCipher(cipherName)
        }
        
        guard let iv = Data(hexString: ivHex) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decode encrypted data
        let base64Content = base64Lines.joined()
        guard let encryptedData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decrypt
        let decryptedData = try PEMEncryption.decrypt(
            data: encryptedData,
            passphrase: passphrase,
            cipher: cipher,
            iv: iv
        )
        
        // Parse decrypted data as PKCS#8
        let privateKey = try parseEd25519PrivateKeyFromPKCS8(decryptedData)
        return Ed25519Key(privateKey: privateKey)
    }
    
    /// Parse Ed25519 private key from PKCS#8 DER data
    private static func parseEd25519PrivateKeyFromPKCS8(_ derData: Data) throws -> Curve25519.Signing.PrivateKey {
        // PKCS#8 format for Ed25519:
        // SEQUENCE {
        //   INTEGER version (0)
        //   SEQUENCE {
        //     OBJECT IDENTIFIER algorithmIdentifier (1.3.101.112)
        //   }
        //   OCTET STRING privateKey {
        //     OCTET STRING actualPrivateKey[32]
        //   }
        // }
        
        var parser = ASN1Parser(data: derData)
        
        // Skip outer SEQUENCE
        guard parser.offset < derData.count && derData[parser.offset] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        parser.offset += 1
        _ = try parser.parseLength()
        
        // Parse version (should be 0)
        guard let versionData = try parser.parseInteger(),
              versionData.count == 1 && versionData[0] == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Skip algorithm identifier SEQUENCE
        try parser.skipSequence()
        
        // Parse OCTET STRING containing the private key
        guard let privateKeyOctet = try parser.parseOctetString() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // The OCTET STRING contains another OCTET STRING with the actual 32-byte key
        var innerParser = ASN1Parser(data: privateKeyOctet)
        guard let actualKeyData = try innerParser.parseOctetString() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Ed25519 private keys are 32 bytes
        guard actualKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        
        return try Curve25519.Signing.PrivateKey(rawRepresentation: actualKeyData)
    }
    
    /// Check if a string is in PEM format
    public static func isPEMFormat(_ keyString: String) -> Bool {
        return keyString.contains("-----BEGIN") && keyString.contains("-----END")
    }
    
    /// Detect PEM type from string
    public static func detectPEMType(_ pemString: String) -> String? {
        let lines = pemString.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") && line.hasSuffix("-----") {
                let startIdx = line.index(line.startIndex, offsetBy: 11) // "-----BEGIN ".count
                let endIdx = line.index(line.endIndex, offsetBy: -5) // "-----".count
                return String(line[startIdx..<endIdx])
            }
        }
        
        return nil
    }

    /// Parse a generic PEM block and return its declared type and decoded payload bytes.
    /// - Returns: Tuple of `(type, data)` where `type` is the header type between BEGIN/END markers,
    ///            and `data` is the base64-decoded payload between the markers (headers like Proc-Type/DEK-Info are skipped).
    public static func parsePEM(_ pemString: String) throws -> (type: String, data: Data) {
        guard let pemType = detectPEMType(pemString) else {
            throw SSHKeyError.invalidFormat
        }

        let lines = pemString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inBody = false

        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("-----BEGIN ") {
                inBody = true
                continue
            }
            if line.hasPrefix("-----END ") {
                break
            }
            guard inBody else { continue }
            if line.isEmpty { continue }
            // Skip OpenSSL PEM encryption headers
            if line.hasPrefix("Proc-Type:") { continue }
            if line.hasPrefix("DEK-Info:") { continue }
            base64Lines.append(line)
        }

        let base64Joined = base64Lines.joined()
        guard let data = Data(base64Encoded: base64Joined) else {
            throw SSHKeyError.invalidBase64
        }
        return (pemType, data)
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

// MARK: - Data Extensions

extension Data {
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
}
