import Foundation
import Crypto

// MARK: - SEC1/RFC5915 Support for ECDSA Keys

extension P256.Signing.PrivateKey {
    /// SEC1/RFC5915 DER representation of the private key
    /// This format is used by OpenSSL's EC PRIVATE KEY format
    public var sec1DERRepresentation: Data {
        // SEC1 ECPrivateKey structure:
        // ECPrivateKey ::= SEQUENCE {
        //   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //   privateKey     OCTET STRING,
        //   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //   publicKey  [1] BIT STRING OPTIONAL
        // }
        
        var data = Data()
        
        // Version (1)
        data.append(ASN1.integer(1))
        
        // Private key as OCTET STRING
        data.append(ASN1.octetString(rawRepresentation))
        
        // Parameters [0] - P-256 OID
        let p256OID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) // 1.2.840.10045.3.1.7
        data.append(Data([0xA0])) // Context tag 0
        data.append(contentsOf: ASN1.lengthField(of: p256OID.count))
        data.append(p256OID)
        
        // Public key [1] - optional but we include it
        let publicKeyData = publicKey.x963Representation
        let bitStringData = ASN1.bitString(publicKeyData)
        
        data.append(Data([0xA1])) // Context tag 1
        data.append(contentsOf: ASN1.lengthField(of: bitStringData.count))
        data.append(bitStringData)
        
        return ASN1.sequence(data)
    }
    
    /// SEC1/RFC5915 PEM representation
    public var sec1PEMRepresentation: String {
        let derData = sec1DERRepresentation
        let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN EC PRIVATE KEY-----\n\(base64)\n-----END EC PRIVATE KEY-----"
    }
}

extension P384.Signing.PrivateKey {
    /// SEC1/RFC5915 DER representation of the private key
    public var sec1DERRepresentation: Data {
        var data = Data()
        
        // Version (1)
        data.append(ASN1.integer(1))
        
        // Private key as OCTET STRING
        data.append(ASN1.octetString(rawRepresentation))
        
        // Parameters [0] - P-384 OID
        let p384OID = Data([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]) // 1.3.132.0.34
        data.append(Data([0xA0])) // Context tag 0
        data.append(contentsOf: ASN1.lengthField(of: p384OID.count))
        data.append(p384OID)
        
        // Public key [1]
        let publicKeyData = publicKey.x963Representation
        let bitStringData = ASN1.bitString(publicKeyData)
        
        data.append(Data([0xA1])) // Context tag 1
        data.append(contentsOf: ASN1.lengthField(of: bitStringData.count))
        data.append(bitStringData)
        
        return ASN1.sequence(data)
    }
    
    /// SEC1/RFC5915 PEM representation
    public var sec1PEMRepresentation: String {
        let derData = sec1DERRepresentation
        let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN EC PRIVATE KEY-----\n\(base64)\n-----END EC PRIVATE KEY-----"
    }
}

extension P521.Signing.PrivateKey {
    /// SEC1/RFC5915 DER representation of the private key
    public var sec1DERRepresentation: Data {
        var data = Data()
        
        // Version (1)
        data.append(ASN1.integer(1))
        
        // Private key as OCTET STRING
        data.append(ASN1.octetString(rawRepresentation))
        
        // Parameters [0] - P-521 OID
        let p521OID = Data([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]) // 1.3.132.0.35
        data.append(Data([0xA0])) // Context tag 0
        data.append(contentsOf: ASN1.lengthField(of: p521OID.count))
        data.append(p521OID)
        
        // Public key [1]
        let publicKeyData = publicKey.x963Representation
        let bitStringData = ASN1.bitString(publicKeyData)
        
        data.append(Data([0xA1])) // Context tag 1
        data.append(contentsOf: ASN1.lengthField(of: bitStringData.count))
        data.append(bitStringData)
        
        return ASN1.sequence(data)
    }
    
    /// SEC1/RFC5915 PEM representation
    public var sec1PEMRepresentation: String {
        let derData = sec1DERRepresentation
        let base64 = derData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN EC PRIVATE KEY-----\n\(base64)\n-----END EC PRIVATE KEY-----"
    }
}

// MARK: - ASN.1 Helpers

private struct ASN1 {
    static func lengthField(of length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length < 256 {
            return Data([0x81, UInt8(length)])
        } else if length < 65536 {
            return Data([0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
        } else {
            fatalError("Length too large for ASN.1 encoding")
        }
    }
    
    static func sequence(_ data: Data) -> Data {
        var result = Data([0x30]) // SEQUENCE tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func octetString(_ data: Data) -> Data {
        var result = Data([0x04]) // OCTET STRING tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func bitString(_ data: Data) -> Data {
        var result = Data([0x03]) // BIT STRING tag
        let dataWithPadding = Data([0x00]) + data // No padding bits
        result.append(lengthField(of: dataWithPadding.count))
        result.append(dataWithPadding)
        return result
    }
    
    static func integer(_ value: Int) -> Data {
        var result = Data([0x02]) // INTEGER tag
        let bytes = value == 0 ? Data([0x00]) : Data([UInt8(value)])
        result.append(lengthField(of: bytes.count))
        result.append(bytes)
        return result
    }
}

// MARK: - ECDSAKey Extension

extension ECDSAKey {
    /// Get SEC1/RFC5915 PEM representation (EC PRIVATE KEY format)
    /// This matches ssh-keygen's -m PEM output
    public var sec1PEMRepresentation: String {
        switch privateKeyStorage {
        case .p256(let key):
            return key.sec1PEMRepresentation
        case .p384(let key):
            return key.sec1PEMRepresentation
        case .p521(let key):
            return key.sec1PEMRepresentation
        }
    }
    
    /// Get encrypted SEC1/RFC5915 PEM representation
    /// This matches ssh-keygen's -m PEM output with passphrase
    public func sec1PEMRepresentation(passphrase: String, cipher: PEMEncryption.PEMCipher = .aes128CBC) throws -> String {
        // Get DER data
        let derData: Data
        switch privateKeyStorage {
        case .p256(let key):
            derData = key.sec1DERRepresentation
        case .p384(let key):
            derData = key.sec1DERRepresentation
        case .p521(let key):
            derData = key.sec1DERRepresentation
        }
        
        // Encrypt the DER data
        let (encryptedData, iv) = try PEMEncryption.encrypt(
            data: derData,
            passphrase: passphrase,
            cipher: cipher
        )
        
        // Format as encrypted PEM
        return PEMEncryption.formatEncryptedPEM(
            type: "EC PRIVATE KEY",
            encryptedData: encryptedData,
            cipher: cipher,
            salt: iv  // PEM format uses IV in DEK-Info header
        )
    }
    
    /// Get PKCS#8 PEM representation (PRIVATE KEY format)
    /// This matches ssh-keygen's -m PKCS8 output
    public var pkcs8PEMRepresentation: String {
        return pemRepresentation
    }
    
    /// Get encrypted PKCS#8 PEM representation
    /// This matches ssh-keygen's -m PKCS8 output with passphrase
    public func pkcs8PEMRepresentation(passphrase: String, iterations: Int = PKCS8Encryption.defaultIterations) throws -> String {
        // Get PKCS#8 DER data
        let pkcs8DER: Data
        switch privateKeyStorage {
        case .p256(let key):
            // Swift Crypto's pemRepresentation gives us PEM, we need DER
            let pem = key.pemRepresentation
            guard let derData = extractDERFromPEM(pem) else {
                throw SSHKeyError.invalidKeyData
            }
            pkcs8DER = derData
        case .p384(let key):
            let pem = key.pemRepresentation
            guard let derData = extractDERFromPEM(pem) else {
                throw SSHKeyError.invalidKeyData
            }
            pkcs8DER = derData
        case .p521(let key):
            let pem = key.pemRepresentation
            guard let derData = extractDERFromPEM(pem) else {
                throw SSHKeyError.invalidKeyData
            }
            pkcs8DER = derData
        }
        
        // Encrypt using PBES2
        let (encryptedData, parameters) = try PKCS8Encryption.encryptPBES2(
            data: pkcs8DER,
            passphrase: passphrase,
            iterations: iterations
        )
        
        // Create algorithm identifier
        let algorithmIdentifier = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: parameters)
        
        // Encode as EncryptedPrivateKeyInfo
        let encryptedPrivateKeyInfo = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(
            algorithmIdentifier: algorithmIdentifier,
            encryptedData: encryptedData
        )
        
        // Format as PEM
        return PKCS8Encryption.formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: encryptedPrivateKeyInfo)
    }
    
    /// Extract DER data from PEM string
    private func extractDERFromPEM(_ pem: String) -> Data? {
        let lines = pem.components(separatedBy: .newlines)
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
        
        return Data(base64Encoded: base64Content)
    }
}