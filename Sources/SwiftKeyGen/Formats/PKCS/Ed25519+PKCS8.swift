import Foundation

// MARK: - Ed25519 PKCS#8 Support
// Implements unencrypted and encrypted PKCS#8 (PBES2) emission for Ed25519 keys
// according to RFC 8410 (id-Ed25519 OID 1.3.101.112, parameters MUST be absent).
//
// PrivateKeyInfo ::= SEQUENCE {
//   version                   INTEGER (0),
//   privateKeyAlgorithm       AlgorithmIdentifier { id-Ed25519 },
//   privateKey                OCTET STRING (32-byte seed),
//   attributes          [0]   IMPLICIT SET OPTIONAL
// }
//
// The privateKey OCTET STRING contains ONLY the 32‑octet seed per RFC 8410 §7.
// No public key field or oneAsymmetricKey v1 extension is used here.

fileprivate enum ASN1Ed25519 {
    static func lengthField(_ length: Int) -> Data {
        if length < 128 { return Data([UInt8(length)]) }
        var bytes: [UInt8] = []
        var value = length
        while value > 0 { bytes.insert(UInt8(value & 0xFF), at: 0); value >>= 8 }
        var result = Data([0x80 | UInt8(bytes.count)])
        result.append(contentsOf: bytes)
        return result
    }
    static func sequence(_ content: Data) -> Data { Data([0x30]) + lengthField(content.count) + content }
    static func octetString(_ content: Data) -> Data { Data([0x04]) + lengthField(content.count) + content }
    static func integer0() -> Data { Data([0x02, 0x01, 0x00]) }
}

extension Ed25519Key {
    /// Unencrypted PKCS#8 (PRIVATE KEY) PEM representation for this Ed25519 key.
    /// Mirrors CryptoKit style output but built manually to maintain canonical DER.
    public var pkcs8PEMRepresentation: String {
        let der = privateKeyInfoDER()
        let b64 = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        var out = "-----BEGIN PRIVATE KEY-----\n"
        out += b64
        if !b64.hasSuffix("\n") { out += "\n" }
        out += "-----END PRIVATE KEY-----"
        return out
    }

    /// Encrypted PKCS#8 (ENCRYPTED PRIVATE KEY) PEM using PBES2 (PBKDF2 + AES-CBC).
    /// - Parameters:
    ///   - passphrase: Passphrase for encryption.
    ///   - iterations: PBKDF2 iteration count.
    ///   - prf: PBKDF2 PRF (HMAC-SHA1 or HMAC-SHA256).
    ///   - cipher: AES-128-CBC or AES-256-CBC content encryption.
    public func pkcs8PEMRepresentation(passphrase: String,
                                       iterations: Int = PKCS8Encryption.defaultIterations,
                                       prf: PKCS8Encryption.PRF = .hmacSHA1,
                                       cipher: PKCS8Encryption.Cipher = .aes128cbc) throws -> String {
        let der = privateKeyInfoDER()
        let (encrypted, params, prfUsed, cipherUsed) = try PKCS8Encryption.encryptPBES2(
            data: der,
            passphrase: passphrase,
            iterations: iterations,
            prf: prf,
            cipher: cipher
        )
        let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params, prf: prfUsed, cipher: cipherUsed)
        let encryptedInfo = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(algorithmIdentifier: algId, encryptedData: encrypted)
        return PKCS8Encryption.formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: encryptedInfo)
    }

    /// Internal DER builder for PrivateKeyInfo (used by canonical tests).
    func privateKeyInfoDER() -> Data {
        let version = ASN1Ed25519.integer0()
        // id-Ed25519 OID 1.3.101.112 -> 06 03 2B 65 70; parameters MUST be absent
        let oid: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x70]
        let algId = ASN1Ed25519.sequence(Data(oid))
        let privOctet = ASN1Ed25519.octetString(privateKeyData())
        return ASN1Ed25519.sequence(version + algId + privOctet)
    }
}
