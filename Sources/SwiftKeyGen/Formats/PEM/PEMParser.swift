import Foundation
import Crypto
import _CryptoExtras

/// High–level utilities for parsing cryptographic key material encoded in
/// PEM (Privacy Enhanced Mail) textual containers.
///
/// This parser focuses on SSH‑relevant algorithms (RSA, ECDSA curves P‑256 / P‑384 / P‑521,
/// and Ed25519) and supports both public and private key encodings in common
/// OpenSSL / PKCS#8 / SEC1 forms. It also understands legacy OpenSSL encrypted
/// private key headers (``Proc-Type`` / ``DEK-Info``) for ECDSA / Ed25519 keys.
///
/// All public parsing entry points return strongly typed key model instances
/// defined elsewhere in the library (e.g. ``RSAPublicKey`` / ``ECDSAPublicKey`` /
/// ``ECDSAKey`` / ``Ed25519Key``) to preserve invariant enforcement and reduce
/// the risk of mis‑use of raw key bytes.
///
/// Error handling:
/// - Throws ``SSHKeyError`` values for invalid formats, unsupported algorithms, missing passphrases, or decryption failures.
/// - Parsing attempts perform conservative validation; malformed or truncated data results in ``SSHKeyError.invalidKeyData``.
///
/// Thread safety:
/// All functions are pure and stateless; the type exposes only static helpers and is therefore thread‑safe.
public struct PEMParser {
    
    // MARK: - RSA Key Parsing
    
    /// Parses an RSA public key contained in a PEM block.
    ///
    /// Supported PEM headers:
    /// - `-----BEGIN RSA PUBLIC KEY-----`
    /// - `-----BEGIN PUBLIC KEY-----` (PKCS#8 SubjectPublicKeyInfo wrapping RSA)
    ///
    /// The implementation delegates to Swift Crypto to decode the public key,
    /// then extracts the modulus and exponent to build an internal ``RSAPublicKey``.
    ///
    /// - Parameter pemString: The full PEM text (including BEGIN/END lines).
    /// - Returns: A populated ``RSAPublicKey`` instance.
    /// - Throws: ``SSHKeyError.invalidKeyData`` if DER decoding fails, or other ``SSHKeyError`` / Crypto errors surfaced during parsing.
    public static func parseRSAPublicKey(_ pemString: String) throws -> RSAPublicKey {
        // Use Swift Crypto's built-in PEM parser
        let publicKey = try _RSA.Signing.PublicKey(pemRepresentation: pemString)
        
        // Extract modulus and exponent from the public key's DER representation
        let (modulus, exponent) = try Insecure.RSA.extractPublicKeyComponents(from: publicKey.derRepresentation)
        
        return try RSAPublicKey(modulus: modulus, exponent: exponent)
    }
    
    // MARK: - ECDSA Key Parsing
    
    /// Parses an ECDSA public key from a PEM representation.
    ///
    /// The method first attempts native curve parsing via Swift Crypto for
    /// P‑256 / P‑384 / P‑521 in standard SubjectPublicKeyInfo form. If those
    /// attempts fail, it falls back to a manual PKCS#8 structure examination
    /// to recover the curve OID and raw point.
    ///
    /// - Important: Only uncompressed EC points are supported (the OpenSSH / PKCS#8 default).
    /// - Parameter pemString: The PEM text for the public key.
    /// - Returns: An ``ECDSAPublicKey`` containing curve metadata and the x963 point.
    /// - Throws: ``SSHKeyError.invalidKeyData`` when the encoded data is malformed, or ``SSHKeyError.unsupportedOperation`` for unknown curves.
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
        let oidHex = oid.hexEncodedString()
        
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
    
    /// Parses an Ed25519 public key from a PEM block.
    ///
    /// - Parameter pemString: PEM text with BEGIN/END markers.
    /// - Returns: An ``Ed25519PublicKey`` wrapping the 32‑byte public key.
    /// - Throws: ``SSHKeyError.invalidKeyData`` if the key cannot be decoded.
    public static func parseEd25519PublicKey(_ pemString: String) throws -> Ed25519PublicKey {
        let publicKey = try Curve25519.Signing.PublicKey(pemRepresentation: pemString)
        return try Ed25519PublicKey(publicKeyData: publicKey.rawRepresentation)
    }
    
    // RSA private key parsing is now implemented in RSA+PEM.swift
    
    /// Parses an ECDSA private key from PEM text (unencrypted or legacy OpenSSL encrypted).
    ///
    /// The function detects encryption headers (`Proc-Type`, `DEK-Info`). If encrypted,
    /// a passphrase must be supplied to decrypt the payload prior to decoding either a
    /// SEC1 (traditional EC) or PKCS#8 wrapper.
    ///
    /// - Parameters:
    ///   - pemString: Complete PEM string including header/footer lines.
    ///   - passphrase: Optional passphrase for legacy OpenSSL PEM encryption (not PKCS#8 PBES2).
    /// - Returns: A strongly typed ``ECDSAKey`` instance corresponding to the discovered curve.
    /// - Throws: ``SSHKeyError.passphraseRequired`` if encrypted but no passphrase is supplied, or ``SSHKeyError.invalidKeyData`` / ``SSHKeyError.unsupportedOperation`` for malformed or unsupported keys.
    public static func parseECDSAPrivateKey(_ pemString: String, passphrase: String? = nil) throws -> ECDSAKey {
        let trimmedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check if it's encrypted
        if isEncryptedPEM(trimmedPEM) {
            guard let passphrase = passphrase else {
                throw SSHKeyError.passphraseRequired
            }
            return try parseEncryptedECDSAPrivateKey(trimmedPEM, passphrase: passphrase)
        } else if trimmedPEM.contains("BEGIN ENCRYPTED PRIVATE KEY") {
            // PBES2 (PKCS#8) encrypted ECDSA path
            guard let passphrase = passphrase else { throw SSHKeyError.passphraseRequired }
            return try parseEncryptedPKCS8ECDSAPrivateKey(trimmedPEM, passphrase: passphrase)
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

    /// Parse ECDSA key from encrypted PKCS#8 (PBES2) ENCRYPTED PRIVATE KEY PEM.
    /// Decrypts PBES2 envelope then decodes inner PrivateKeyInfo + SEC1.
    private static func parseEncryptedPKCS8ECDSAPrivateKey(_ pemString: String, passphrase: String) throws -> ECDSAKey {
        // Reuse PKCS8Parser to extract parameters and ciphertext
        let info = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pemString)
        let decrypted = try PKCS8Parser.decrypt(info: info, passphrase: passphrase)
        // decrypted is DER of PrivateKeyInfo (PKCS#8). Reuse existing path.
        return try parseECDSAPrivateKeyFromPKCS8(decrypted)
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
        
        // Validate the curve OID without retaining the value; parsing of the
        // embedded SEC1 structure will independently derive the curve.
        _ = try determineCurveTypeFromOID(curveOID)
        
        // Skip to end of algorithm sequence
        parser.offset = algSeqEnd
        
        // Parse OCTET STRING containing the private key
        guard let privateKeyOctet = try parser.parseOctetString() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // The OCTET STRING contains a SEC1 private key structure
        return try parseECDSAPrivateKeyFromSEC1(privateKeyOctet)
    }
    
    /// Parses an Ed25519 private key from PEM text (unencrypted or legacy OpenSSL encrypted).
    ///
    /// For encrypted PEM (OpenSSL traditional style) a passphrase is required. The
    /// decrypted payload is expected in PKCS#8 form and the inner 32‑byte seed is
    /// extracted to construct the Swift Crypto private key.
    ///
    /// - Parameters:
    ///   - pemString: The full PEM string (BEGIN/END + body).
    ///   - passphrase: Passphrase for legacy OpenSSL encryption if present.
    /// - Returns: An ``Ed25519Key`` containing the private key material.
    /// - Throws: ``SSHKeyError.passphraseRequired`` if needed but absent, or ``SSHKeyError.invalidKeyData`` for malformed content.
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
    
    /// Returns a Boolean indicating whether the provided string appears to contain a PEM block.
    ///
    /// Detection is heuristic and simply checks for the presence of both `-----BEGIN` and `-----END` markers.
    ///
    /// - Parameter keyString: Arbitrary textual input.
    /// - Returns: `true` if the string likely contains at least one PEM block; otherwise `false`.
    public static func isPEMFormat(_ keyString: String) -> Bool {
        return keyString.contains("-----BEGIN") && keyString.contains("-----END")
    }
    
    /// Determines the declared PEM type (the token between `BEGIN` / `END`) of the first block in the string.
    ///
    /// Example: for a header `-----BEGIN EC PRIVATE KEY-----` this returns `EC PRIVATE KEY`.
    ///
    /// - Parameter pemString: The PEM text.
    /// - Returns: The type token or `nil` if no PEM header was found.
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

    /// Parses a generic PEM block and returns its declared type and decoded payload bytes.
    ///
    /// This routine strips legacy OpenSSL encryption headers (`Proc-Type`, `DEK-Info`) but does **not** decrypt the body.
    /// It is suitable as a low‑level primitive for higher‑level format detection or additional ASN.1 decoding.
    ///
    /// - Parameter pemString: PEM text containing exactly (or at least) one block.
    /// - Returns: A tuple `(type: String, data: Data)` where `type` is the header token and `data` is the raw DER / binary content.
    /// - Throws: ``SSHKeyError.invalidFormat`` if the PEM markers are missing or ``SSHKeyError.invalidBase64`` if decoding fails.
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
    
    /// Heuristically determines if the first PEM block appears to represent a private key.
    ///
    /// Detection is string based (`PRIVATE` substring in the type token) and does not inspect ASN.1 structure.
    ///
    /// - Parameter pemString: The PEM text to inspect.
    /// - Returns: `true` when the PEM type token contains `PRIVATE`; otherwise `false`.
    public static func isPrivateKey(_ pemString: String) -> Bool {
        guard let pemType = detectPEMType(pemString) else { return false }
        return pemType.contains("PRIVATE")
    }
    
    /// Attempts to infer the key algorithm family from the PEM type header without parsing ASN.1 content.
    ///
    /// - Note: Returns `nil` for generic `PUBLIC KEY` / `PRIVATE KEY` containers where algorithm identification requires ASN.1 inspection.
    /// - Parameter pemString: PEM text to analyze.
    /// - Returns: A string identifier (e.g. `RSA`, `ECDSA`) or `nil` if the algorithm cannot be determined heuristically.
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

    // MARK: - ECDSA SEC1 (EC PRIVATE KEY) Parsing

    /// Parse a SEC1/RFC5915 ECDSA "EC PRIVATE KEY" PEM (unencrypted or legacy OpenSSL encrypted).
    /// Supports nistp256, nistp384, nistp521 curves. For encrypted keys the legacy Proc-Type / DEK-Info
    /// header scheme (AES-128-CBC / AES-256-CBC) is supported via `PEMEncryption`.
    /// - Parameters:
    ///   - pemString: Full PEM string.
    ///   - passphrase: Optional passphrase for encrypted keys.
    ///   - comment: Optional comment to attach (SEC1 does not embed comments).
    /// - Returns: ECDSAKey instance.
    public static func parseECPrivateKey(_ pemString: String, passphrase: String? = nil, comment: String? = nil) throws -> ECDSAKey {
        let trimmed = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.contains("-----BEGIN EC PRIVATE KEY-----"), trimmed.contains("-----END EC PRIVATE KEY-----") else {
            throw SSHKeyError.invalidKeyData
        }

        let isEncrypted = trimmed.contains("Proc-Type:") && trimmed.contains("DEK-Info:")
        let derData: Data
        if isEncrypted {
            guard let passphrase else { throw SSHKeyError.passphraseRequired }
            var dekInfo: String?
            var base64Lines: [String] = []
            var inBody = false
            for line in trimmed.components(separatedBy: "\n") {
                if line.hasPrefix("-----BEGIN") { continue }
                else if line.hasPrefix("-----END") { break }
                else if line.hasPrefix("Proc-Type:") { continue }
                else if line.hasPrefix("DEK-Info:") { dekInfo = line.replacingOccurrences(of: "DEK-Info:", with: "").trimmingCharacters(in: .whitespaces) }
                else if line.isEmpty { inBody = true }
                else if inBody { base64Lines.append(line) }
            }
            guard let dekInfoStr = dekInfo else { throw SSHKeyError.invalidKeyData }
            let parts = dekInfoStr.split(separator: ",").map { String($0) }
            guard parts.count == 2 else { throw SSHKeyError.invalidKeyData }
            let cipherName = parts[0]
            let ivHex = parts[1]
            guard let cipher = PEMEncryption.PEMCipher(rawValue: cipherName), let iv = Data(hexString: ivHex) else {
                throw SSHKeyError.unsupportedCipher(cipherName)
            }
            let b64 = base64Lines.joined()
            guard let encrypted = Data(base64Encoded: b64) else { throw SSHKeyError.invalidKeyData }
            derData = try PEMEncryption.decrypt(data: encrypted, passphrase: passphrase, cipher: cipher, iv: iv)
        } else {
            guard let body = trimmed.pemBody(type: "EC PRIVATE KEY"), let d = Data(base64Encoded: body) else {
                throw SSHKeyError.invalidKeyData
            }
            derData = d
        }

        // Parse minimal ASN.1: SEQUENCE { INTEGER 1, OCTET STRING priv, [0] OID params, [1] BIT STRING pub }
        var offset = 0
        func read(_ data: Data, _ count: Int) throws -> Data { guard offset+count <= data.count else { throw SSHKeyError.invalidKeyData }; let slice = data[offset..<offset+count]; offset += count; return Data(slice) }
        func readLength(_ data: Data) throws -> Int { let first = try read(data,1)[0]; if first < 0x80 { return Int(first) } else if first == 0x81 { return Int(try read(data,1)[0]) } else if first == 0x82 { let bytes = try read(data,2); return (Int(bytes[0]) << 8) | Int(bytes[1]) } else { throw SSHKeyError.invalidKeyData } }
        guard offset < derData.count, derData[offset] == 0x30 else { throw SSHKeyError.invalidKeyData } // SEQUENCE
        offset += 1; _ = try readLength(derData)
        guard offset < derData.count, derData[offset] == 0x02 else { throw SSHKeyError.invalidKeyData } // INTEGER
        offset += 1; let verLen = try readLength(derData); _ = try read(derData, verLen)
        guard offset < derData.count, derData[offset] == 0x04 else { throw SSHKeyError.invalidKeyData } // OCTET STRING
        offset += 1; let privLen = try readLength(derData); let privData = try read(derData, privLen)
        guard offset < derData.count, derData[offset] == 0xA0 else { throw SSHKeyError.invalidKeyData } // [0]
        offset += 1; let paramsLen = try readLength(derData); let paramsData = try read(derData, paramsLen)
        guard paramsData.first == 0x06 else { throw SSHKeyError.invalidKeyData }
        let oidLen = Int(paramsData[1]); let oid = Data(paramsData[2..<(2+oidLen)])

        let curve: KeyType
        switch Array(oid) {
            case [0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07]: curve = .ecdsa256
            case [0x2B,0x81,0x04,0x00,0x22]: curve = .ecdsa384
            case [0x2B,0x81,0x04,0x00,0x23]: curve = .ecdsa521
            default: throw SSHKeyError.unsupportedKeyType
        }

        switch curve {
        case .ecdsa256:
            let k = try P256.Signing.PrivateKey(rawRepresentation: privData)
            return ECDSAKey(p256Key: k, comment: comment)
        case .ecdsa384:
            let k = try P384.Signing.PrivateKey(rawRepresentation: privData)
            return ECDSAKey(p384Key: k, comment: comment)
        case .ecdsa521:
            let k = try P521.Signing.PrivateKey(rawRepresentation: privData)
            return ECDSAKey(p521Key: k, comment: comment)
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }

    /// Convenience alias for `parseECPrivateKey` matching naming used elsewhere (`parseRSAPrivateKey`).
    public static func parseECDSAPrivateKey(_ pemString: String, passphrase: String? = nil, comment: String? = nil) throws -> ECDSAKey {
        return try parseECPrivateKey(pemString, passphrase: passphrase, comment: comment)
    }
}