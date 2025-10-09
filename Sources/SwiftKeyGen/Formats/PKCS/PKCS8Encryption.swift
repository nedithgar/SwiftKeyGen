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

    /// Supported PBKDF2 PRFs for PBES2 emission.
    public enum PRF: String, CaseIterable {
        case hmacSHA1
        case hmacSHA256

        var oid: Data {
            switch self {
            case .hmacSHA1:
                return Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07]) // 1.2.840.113549.2.7
            case .hmacSHA256:
                return Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]) // 1.2.840.113549.2.9
            }
        }
    }

    /// Supported symmetric ciphers for PKCS#8 PBES2 AES-CBC content encryption.
    /// Only AES-128-CBC and AES-256-CBC are implemented to match OpenSSH/openssl common output.
    public enum Cipher: String, CaseIterable {
        case aes128cbc
        case aes256cbc

        var oid: Data {
            switch self {
            case .aes128cbc:
                return Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]) // 2.16.840.1.101.3.4.1.2
            case .aes256cbc:
                return Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]) // 2.16.840.1.101.3.4.1.42
            }
        }

        var keyAndIVSizes: (key: Int, iv: Int) {
            switch self {
            case .aes128cbc: return (16,16)
            case .aes256cbc: return (32,16)
            }
        }
    }
    
    /// PBKDF2 key derivation
    static func pbkdf2(password: String, salt: Data, iterations: Int, keyLen: Int, prf: PRF = .hmacSHA1) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw SSHKeyError.invalidKeyData
        }
        
        var derivedKey = Data(count: keyLen)
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    let alg = (prf == .hmacSHA1) ? CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1) : CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress!,
                        passwordData.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress!,
                        salt.count,
                        alg,
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
    public static func encryptPBES2(data: Data, passphrase: String, iterations: Int = defaultIterations, prf: PRF = .hmacSHA1, cipher: Cipher = .aes128cbc) throws -> (encrypted: Data, parameters: PBES2Parameters, prf: PRF, cipher: Cipher) {
        let salt = try PEMEncryption.generateSalt()
        let (keySize, ivSize) = cipher.keyAndIVSizes
        let iv = try Data.generateSecureRandomBytes(count: ivSize)
        let key = try pbkdf2(password: passphrase, salt: salt, iterations: iterations, keyLen: keySize, prf: prf)
        let paddedData = PEMEncryption.pkcs7Pad(data: data, blockSize: 16)
        let encryptedData = try AESCBC.encrypt(data: paddedData, key: key, iv: iv)
        let parameters = PBES2Parameters(
            salt: salt,
            iterations: iterations,
            iv: iv,
            keySize: keySize
        )
        return (encryptedData, parameters, prf, cipher)
    }
    
    /// Structure to hold PBES2 parameters
    /// Parameters used to construct a PBES2 AlgorithmIdentifier. Exposed so callers
    /// can serialize/re-emit the identifier after encryption.
    public struct PBES2Parameters {
        let salt: Data
        let iterations: Int
        let iv: Data
        let keySize: Int
    }
    
    /// Create ASN.1 encoded PBES2 algorithm identifier
    public static func createPBES2AlgorithmIdentifier(parameters: PBES2Parameters, prf: PRF = .hmacSHA1, cipher: Cipher = .aes128cbc) -> Data {
        // This creates the AlgorithmIdentifier for PBES2
        // We'll use a simplified version that matches OpenSSL's output
        
        // PBES2 OID: 1.2.840.113549.1.5.13
        let pbes2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D])
        
        // PBKDF2 OID: 1.2.840.113549.1.5.12
        let pbkdf2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C])
        
        // Use enum-provided OIDs
        
        // Build PBKDF2 parameters
        var pbkdf2Params = Data()
        pbkdf2Params.append(ASN1.octetString(parameters.salt))  // salt
        pbkdf2Params.append(ASN1.integer(parameters.iterations)) // iteration count
        pbkdf2Params.append(ASN1.integer(parameters.keySize))    // key length
        pbkdf2Params.append(ASN1.sequence(prf.oid + Data([0x05, 0x00])))
        
        let pbkdf2AlgId = ASN1.sequence(pbkdf2OID + ASN1.sequence(pbkdf2Params))
        
        // Build encryption scheme parameters (AES-128-CBC with IV)
        let encryptionParams = ASN1.sequence(cipher.oid + ASN1.octetString(parameters.iv))
        
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
