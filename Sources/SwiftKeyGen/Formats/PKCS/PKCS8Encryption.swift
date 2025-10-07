import Foundation
import CommonCrypto
import Crypto

/// High–level helpers for producing **encrypted PKCS#8 (``ENCRYPTED PRIVATE KEY``)** blobs
/// using the PBES2 scheme (Password‑Based Encryption Scheme 2) with PBKDF2 key
/// derivation and an AES‑128‑CBC content encryption algorithm.
///
/// This type focuses on the *encoding* side of PKCS#8 when a caller wants to wrap
/// an already assembled (unencrypted) `PrivateKeyInfo` (PKCS#8) structure in the
/// PBES2 envelope defined in RFC 8018. It intentionally mirrors OpenSSL's legacy
/// defaults (HMAC‑SHA1 PRF, AES‑128‑CBC, 2048 iterations) to maximize
/// interoperability with existing tools (`openssl pkcs8`, `ssh-keygen`, etc.).
///
/// ### Features
/// - PBKDF2 (HMAC‑SHA1) key derivation with configurable iteration count
/// - Random salt and IV generation using the project's secure RNG utilities
/// - PKCS#7 padding + AES‑128‑CBC encryption
/// - Assembly of the PBES2 `AlgorithmIdentifier` ASN.1 structure
/// - PEM formatting (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
///
/// ### Security Notes
/// - The historical OpenSSL default PRF (HMAC‑SHA1) is retained for compatibility.
///   Modern deployments SHOULD prefer HMAC‑SHA256+ and higher iteration counts or
///   memory‑hard KDFs (scrypt / Argon2). A future enhancement may add alternate
///   PRFs and ciphers; this API is deliberately scoped and currently internalizes
///   most implementation details pending broader format negotiation support.
/// - Iteration count 2048 is considered low by contemporary standards; callers
///   planning to store long‑term secrets SHOULD raise this (consider 100k+).
///
/// ### Usage Example
/// ```swift
/// let rawPrivateKeyInfo: Data = /* DER of PrivateKeyInfo (unencrypted PKCS#8) */
/// let (ciphertext, params) = try PKCS8Encryption.encryptPBES2(
///     data: rawPrivateKeyInfo,
///     passphrase: "correct horse battery staple",
///     iterations: PKCS8Encryption.defaultIterations
/// )
/// let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params)
/// let encryptedInfo = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(
///     algorithmIdentifier: algId,
///     encryptedData: ciphertext
/// )
/// let pem = PKCS8Encryption.formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: encryptedInfo)
/// print(pem)
/// ```
///
/// Only the `defaultIterations` constant is public today; the remaining helpers
/// are kept `internal` while the broader PKCS#8 parsing / generation surface is
/// stabilized. If you need additional capabilities, open an issue describing
/// the interoperability or security requirement.
public struct PKCS8Encryption {
    
    /// The default PBKDF2 iteration count (2048) chosen for parity with
    /// historical OpenSSL output. This value is intentionally conservative for
    /// compatibility, not security. Prefer supplying a larger iteration count
    /// (e.g. 100_000 or higher) when generating new encrypted key material in
    /// environments where increased derivation cost is acceptable.
    public static let defaultIterations = 2048
    static let defaultPRF = "hmacWithSHA1"  // OpenSSL default for PBES2
    static let defaultCipher = "aes-128-cbc"
    
    /// PBKDF2 key derivation
    static func pbkdf2(password: String, salt: Data, iterations: Int, keyLen: Int) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw SSHKeyError.invalidKeyData
        }
        
        var derivedKey = Data(count: keyLen)
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress!,
                        passwordData.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress!,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),  // OpenSSL default
                        UInt32(iterations),
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress!,
                        keyLen
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw SSHKeyError.keyDerivationFailed
        }
        
        return derivedKey
    }
    
    /// Encrypt data using PBES2 scheme
    static func encryptPBES2(data: Data, passphrase: String, iterations: Int = defaultIterations) throws -> (encrypted: Data, parameters: PBES2Parameters) {
        // Generate random salt (8 bytes minimum for PBKDF2)
        let salt = try PEMEncryption.generateSalt()
        
        // AES-128-CBC parameters
        let keySize = 16
        let ivSize = 16
        
        // Generate random IV
        let iv = try Data.generateSecureRandomBytes(count: ivSize)
        
        // Derive key using PBKDF2
        let key = try pbkdf2(
            password: passphrase,
            salt: salt,
            iterations: iterations,
            keyLen: keySize
        )
        
        // Pad data using PKCS#7
        let paddedData = PEMEncryption.pkcs7Pad(data: data, blockSize: 16)
        
        // Encrypt using AES-128-CBC
        let encryptedData = try AESCBC.encrypt(data: paddedData, key: key, iv: iv)
        
        let parameters = PBES2Parameters(
            salt: salt,
            iterations: iterations,
            iv: iv,
            keySize: keySize
        )
        
        return (encryptedData, parameters)
    }
    
    /// Structure to hold PBES2 parameters
    struct PBES2Parameters {
        let salt: Data
        let iterations: Int
        let iv: Data
        let keySize: Int
    }
    
    /// Create ASN.1 encoded PBES2 algorithm identifier
    static func createPBES2AlgorithmIdentifier(parameters: PBES2Parameters) -> Data {
        // This creates the AlgorithmIdentifier for PBES2
        // We'll use a simplified version that matches OpenSSL's output
        
        // PBES2 OID: 1.2.840.113549.1.5.13
        let pbes2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D])
        
        // PBKDF2 OID: 1.2.840.113549.1.5.12
        let pbkdf2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C])
        
        // hmacWithSHA1 OID: 1.2.840.113549.2.7
        let hmacSHA1OID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07])
        
        // AES-128-CBC OID: 2.16.840.1.101.3.4.1.2
        let aes128CBCOID = Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02])
        
        // Build PBKDF2 parameters
        var pbkdf2Params = Data()
        pbkdf2Params.append(ASN1.octetString(parameters.salt))  // salt
        pbkdf2Params.append(ASN1.integer(parameters.iterations)) // iteration count
        pbkdf2Params.append(ASN1.integer(parameters.keySize))    // key length
        pbkdf2Params.append(ASN1.sequence(hmacSHA1OID + Data([0x05, 0x00]))) // PRF AlgorithmIdentifier
        
        let pbkdf2AlgId = ASN1.sequence(pbkdf2OID + ASN1.sequence(pbkdf2Params))
        
        // Build encryption scheme parameters (AES-128-CBC with IV)
        let encryptionParams = ASN1.sequence(aes128CBCOID + ASN1.octetString(parameters.iv))
        
        // Build PBES2 parameters
        let pbes2Params = ASN1.sequence(pbkdf2AlgId + encryptionParams)
        
        // Return complete AlgorithmIdentifier
        return ASN1.sequence(pbes2OID + pbes2Params)
    }
    
    /// Encode encrypted private key info (PKCS#8)
    static func encodeEncryptedPrivateKeyInfo(algorithmIdentifier: Data, encryptedData: Data) -> Data {
        return ASN1.sequence(algorithmIdentifier + ASN1.octetString(encryptedData))
    }
    
    /// Format encrypted PKCS#8 as PEM
    static func formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: Data) -> String {
        var pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        let base64 = encryptedPrivateKeyInfo.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        pem += base64
        if !base64.hasSuffix("\n") {
            pem += "\n"
        }
        pem += "-----END ENCRYPTED PRIVATE KEY-----"
        return pem
    }
}

// MARK: - ASN.1 Helpers Extension

// ASN1 helper struct
private struct ASN1 {
    static func octetString(_ data: Data) -> Data {
        var result = Data([0x04]) // OCTET STRING tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func sequence(_ data: Data) -> Data {
        var result = Data([0x30]) // SEQUENCE tag
        result.append(lengthField(of: data.count))
        result.append(data)
        return result
    }
    
    static func integer(_ value: Int) -> Data {
        var result = Data([0x02]) // INTEGER tag
        
        // Convert integer to bytes (big-endian)
        var bytes = [UInt8]()
        var val = value
        
        if val == 0 {
            bytes = [0x00]
        } else {
            while val > 0 {
                bytes.insert(UInt8(val & 0xFF), at: 0)
                val >>= 8
            }
            
            // Add leading zero if high bit is set (to keep positive)
            if !bytes.isEmpty && bytes[0] & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
        }
        
        result.append(lengthField(of: bytes.count))
        result.append(Data(bytes))
        return result
    }
    
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
}

// MARK: - Error Extensions

extension SSHKeyError {
    static let keyDerivationFailed = SSHKeyError.invalidKeyData
}
