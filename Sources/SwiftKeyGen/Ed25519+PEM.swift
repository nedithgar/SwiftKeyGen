import Foundation
import Crypto

// MARK: - Constants

/// Ed25519 OID: 1.3.101.112
private let ed25519OID = Data([0x2B, 0x65, 0x70])

/// Ed25519 Algorithm Identifier for PKCS#8 and SPKI
private let ed25519AlgorithmIdentifier = Data([
    0x30, 0x05,  // SEQUENCE (5 bytes)
    0x06, 0x03,  // OID (3 bytes)
    0x2B, 0x65, 0x70  // id-Ed25519: 1.3.101.112
])

// MARK: - ASN.1 Helpers

private enum ASN1 {
    static func lengthField(of length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length < 256 {
            return Data([0x81, UInt8(length)])
        } else if length < 65536 {
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        } else {
            fatalError("Length too large for ASN.1 encoding")
        }
    }
    
    static func wrapInSequence(_ data: Data) -> Data {
        var result = Data([0x30])  // SEQUENCE tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func wrapInOctetString(_ data: Data) -> Data {
        var result = Data([0x04])  // OCTET STRING tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func wrapInBitString(_ data: Data) -> Data {
        var result = Data([0x03])  // BIT STRING tag
        let dataWithPadding = Data([0x00]) + data  // No padding bits
        result.append(lengthField(of: dataWithPadding.count))
        result.append(dataWithPadding)
        return result
    }
    
    static func integer(_ value: Int) -> Data {
        var result = Data([0x02])  // INTEGER tag
        let bytes = value == 0 ? Data([0x00]) : Data([UInt8(value)])
        result.append(lengthField(of: bytes.count))
        result.append(bytes)
        return result
    }
}

// MARK: - Ed25519 Private Key PEM Support

extension Curve25519.Signing.PrivateKey {
    
    /// The PKCS#8 DER representation of the private key
    public var pkcs8DERRepresentation: Data {
        // PKCS#8 structure:
        // PrivateKeyInfo ::= SEQUENCE {
        //   version         INTEGER {v1(0)} (v1,...),
        //   privateKeyAlgorithm AlgorithmIdentifier,
        //   privateKey      OCTET STRING,
        //   attributes      [0] Attributes OPTIONAL
        // }
        
        // The private key is wrapped in an OCTET STRING containing the 32-byte seed
        let privateKeyOctetString = ASN1.wrapInOctetString(rawRepresentation)
        
        // Build the PKCS#8 structure
        var pkcs8Data = Data()
        pkcs8Data.append(ASN1.integer(0))  // version
        pkcs8Data.append(ed25519AlgorithmIdentifier)  // algorithm
        pkcs8Data.append(ASN1.wrapInOctetString(privateKeyOctetString))  // privateKey
        
        return ASN1.wrapInSequence(pkcs8Data)
    }
    
    /// Initialize a private key from PKCS#8 DER representation
    public init(pkcs8DERRepresentation: Data) throws {
        // Basic validation
        guard pkcs8DERRepresentation.count > 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        
        // Parse PKCS#8 structure
        var index = 0
        
        // Check SEQUENCE tag
        guard index < pkcs8DERRepresentation.count,
              pkcs8DERRepresentation[index] == 0x30 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Skip length field
        if pkcs8DERRepresentation[index] & 0x80 != 0 {
            let lengthBytes = Int(pkcs8DERRepresentation[index] & 0x7F)
            index += 1 + lengthBytes
        } else {
            index += 1
        }
        
        // Skip version (INTEGER)
        guard index + 2 < pkcs8DERRepresentation.count,
              pkcs8DERRepresentation[index] == 0x02 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        let versionLength = Int(pkcs8DERRepresentation[index])
        index += 1 + versionLength
        
        // Check algorithm identifier
        guard index + ed25519AlgorithmIdentifier.count <= pkcs8DERRepresentation.count else {
            throw CryptoKitError.incorrectParameterSize
        }
        let algorithmRange = index..<(index + ed25519AlgorithmIdentifier.count)
        guard pkcs8DERRepresentation[algorithmRange] == ed25519AlgorithmIdentifier else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += ed25519AlgorithmIdentifier.count
        
        // Parse privateKey OCTET STRING
        guard index + 1 < pkcs8DERRepresentation.count,
              pkcs8DERRepresentation[index] == 0x04 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Skip length of outer OCTET STRING
        if pkcs8DERRepresentation[index] & 0x80 != 0 {
            let lengthBytes = Int(pkcs8DERRepresentation[index] & 0x7F)
            index += 1
            guard lengthBytes == 1, index < pkcs8DERRepresentation.count else {
                throw CryptoKitError.incorrectParameterSize
            }
            index += 1  // Skip the length value
        } else {
            index += 1  // Skip single-byte length
        }
        
        // Parse inner OCTET STRING (contains the actual private key)
        guard index + 1 < pkcs8DERRepresentation.count,
              pkcs8DERRepresentation[index] == 0x04 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Get length of inner OCTET STRING
        guard index < pkcs8DERRepresentation.count,
              pkcs8DERRepresentation[index] == 0x20 else {  // Ed25519 private key is always 32 bytes
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Extract the 32-byte private key
        guard index + 32 <= pkcs8DERRepresentation.count else {
            throw CryptoKitError.incorrectParameterSize
        }
        let privateKeyData = pkcs8DERRepresentation[index..<(index + 32)]
        
        try self.init(rawRepresentation: privateKeyData)
    }
    
    /// The PEM representation of the private key
    public var pemRepresentation: String {
        let derData = pkcs8DERRepresentation
        let base64 = derData.base64EncodedString()
        
        // Format base64 with 64-character lines
        var formattedBase64 = ""
        var index = base64.startIndex
        while index < base64.endIndex {
            let endIndex = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            formattedBase64 += base64[index..<endIndex]
            if endIndex < base64.endIndex {
                formattedBase64 += "\n"
            }
            index = endIndex
        }
        
        return "-----BEGIN PRIVATE KEY-----\n\(formattedBase64)\n-----END PRIVATE KEY-----"
    }
    
    /// Initialize a private key from PEM representation
    public init(pemRepresentation: String) throws {
        let lines = pemRepresentation.components(separatedBy: .newlines)
        
        // Find the base64 content between the PEM boundaries
        var base64Content = ""
        var inKey = false
        
        for line in lines {
            if line.contains("BEGIN") && line.contains("PRIVATE KEY") {
                inKey = true
                continue
            }
            if line.contains("END") && line.contains("PRIVATE KEY") {
                break
            }
            if inKey && !line.isEmpty {
                base64Content += line
            }
        }
        
        guard !base64Content.isEmpty,
              let derData = Data(base64Encoded: base64Content) else {
            throw CryptoKitError.incorrectParameterSize
        }
        
        try self.init(pkcs8DERRepresentation: derData)
    }
}

// MARK: - Ed25519 Public Key PEM Support

extension Curve25519.Signing.PublicKey {
    
    /// The Subject Public Key Info (SPKI) DER representation of the public key
    public var spkiDERRepresentation: Data {
        // SubjectPublicKeyInfo ::= SEQUENCE {
        //   algorithm       AlgorithmIdentifier,
        //   subjectPublicKey BIT STRING
        // }
        
        let publicKeyBitString = ASN1.wrapInBitString(rawRepresentation)
        
        var spkiData = Data()
        spkiData.append(ed25519AlgorithmIdentifier)
        spkiData.append(publicKeyBitString)
        
        return ASN1.wrapInSequence(spkiData)
    }
    
    /// Initialize a public key from SPKI DER representation
    public init(spkiDERRepresentation: Data) throws {
        // Basic validation
        guard spkiDERRepresentation.count > 32 else {
            throw CryptoKitError.incorrectKeySize
        }
        
        // Parse SPKI structure
        var index = 0
        
        // Check SEQUENCE tag
        guard index < spkiDERRepresentation.count,
              spkiDERRepresentation[index] == 0x30 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Skip length field
        if spkiDERRepresentation[index] & 0x80 != 0 {
            let lengthBytes = Int(spkiDERRepresentation[index] & 0x7F)
            index += 1 + lengthBytes
        } else {
            index += 1
        }
        
        // Check algorithm identifier
        guard index + ed25519AlgorithmIdentifier.count <= spkiDERRepresentation.count else {
            throw CryptoKitError.incorrectParameterSize
        }
        let algorithmRange = index..<(index + ed25519AlgorithmIdentifier.count)
        guard spkiDERRepresentation[algorithmRange] == ed25519AlgorithmIdentifier else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += ed25519AlgorithmIdentifier.count
        
        // Parse BIT STRING
        guard index + 1 < spkiDERRepresentation.count,
              spkiDERRepresentation[index] == 0x03 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Get length of BIT STRING
        guard index < spkiDERRepresentation.count,
              spkiDERRepresentation[index] == 0x21 else {  // 33 bytes: 1 padding byte + 32 key bytes
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Skip padding byte
        guard index < spkiDERRepresentation.count,
              spkiDERRepresentation[index] == 0x00 else {
            throw CryptoKitError.incorrectParameterSize
        }
        index += 1
        
        // Extract the 32-byte public key
        guard index + 32 <= spkiDERRepresentation.count else {
            throw CryptoKitError.incorrectParameterSize
        }
        let publicKeyData = spkiDERRepresentation[index..<(index + 32)]
        
        try self.init(rawRepresentation: publicKeyData)
    }
    
    /// The PEM representation of the public key
    public var pemRepresentation: String {
        let derData = spkiDERRepresentation
        let base64 = derData.base64EncodedString()
        
        // Format base64 with 64-character lines
        var formattedBase64 = ""
        var index = base64.startIndex
        while index < base64.endIndex {
            let endIndex = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            formattedBase64 += base64[index..<endIndex]
            if endIndex < base64.endIndex {
                formattedBase64 += "\n"
            }
            index = endIndex
        }
        
        return "-----BEGIN PUBLIC KEY-----\n\(formattedBase64)\n-----END PUBLIC KEY-----"
    }
    
    /// Initialize a public key from PEM representation
    public init(pemRepresentation: String) throws {
        let lines = pemRepresentation.components(separatedBy: .newlines)
        
        // Find the base64 content between the PEM boundaries
        var base64Content = ""
        var inKey = false
        
        for line in lines {
            if line.contains("BEGIN") && line.contains("PUBLIC KEY") {
                inKey = true
                continue
            }
            if line.contains("END") && line.contains("PUBLIC KEY") {
                break
            }
            if inKey && !line.isEmpty {
                base64Content += line
            }
        }
        
        guard !base64Content.isEmpty,
              let derData = Data(base64Encoded: base64Content) else {
            throw CryptoKitError.incorrectParameterSize
        }
        
        try self.init(spkiDERRepresentation: derData)
    }
}