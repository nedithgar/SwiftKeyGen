import Foundation

// MARK: - RSA PKCS#8 (Encrypted) Support
// Provides encrypted PKCS#8 (PBES2) PEM generation for RSA keys to achieve
// parity with existing ECDSA implementation and ssh-keygen `-m PKCS8` output.
//
// We construct a PKCS#8 PrivateKeyInfo wrapping the PKCS#1 RSAPrivateKey
// and then pass it through the existing PBES2 (PBKDF2 + AES-128-CBC) pipeline.
//
// PrivateKeyInfo ::= SEQUENCE {
//   version                   INTEGER (0),
//   privateKeyAlgorithm       AlgorithmIdentifier,
//   privateKey                OCTET STRING (RSAPrivateKey DER),
//   attributes          [0]   IMPLICIT SET OPTIONAL
// }
//
// AlgorithmIdentifier for rsaEncryption:
//   OID 1.2.840.113549.1.1.1 + NULL parameters
//
// Encrypted output: ENCRYPTED PRIVATE KEY (PBES2 envelope)
//
// Security notes mirror those in `PKCS8Encryption` – default iteration count is
// intentionally conservative for interoperability; callers may request higher.

// Minimal ASN.1 helpers specific to RSA PKCS#8 assembly to avoid colliding with
// existing private ASN1 helpers in other format files.
fileprivate enum ASN1PKCS8 {
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
}

extension RSAKey {
    /// Generate an encrypted PKCS#8 (ENCRYPTED PRIVATE KEY) PEM.
    /// - Parameters:
    ///   - passphrase: Passphrase used for PBES2 (PBKDF2 + AES‑128‑CBC).
    ///   - iterations: PBKDF2 iteration count (defaults to `PKCS8Encryption.defaultIterations`).
    /// - Returns: PEM string beginning with `-----BEGIN ENCRYPTED PRIVATE KEY-----`.
    public func pkcs8PEMRepresentation(passphrase: String,
                                       iterations: Int = PKCS8Encryption.defaultIterations,
                                       prf: PKCS8Encryption.PRF = .hmacSHA1,
                                       cipher: PKCS8Encryption.Cipher = .aes128cbc) throws -> String {
        let pkcs1 = privateKeyData() // PKCS#1 DER (RSAPrivateKey)
        guard !pkcs1.isEmpty else { throw SSHKeyError.invalidKeyData }

        // Build PrivateKeyInfo
        // INTEGER 0
        let version = Data([0x02, 0x01, 0x00])
        // rsaEncryption OID + NULL params
    let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    let nullParam: [UInt8] = [0x05, 0x00]
    let algorithmIdentifier = ASN1PKCS8.sequence(Data(rsaOID + nullParam))
    let privateKeyOctet = ASN1PKCS8.octetString(pkcs1)
    let privateKeyInfo = ASN1PKCS8.sequence(version + algorithmIdentifier + privateKeyOctet)

        // Encrypt via PBES2
        let (encrypted, params, prfUsed, cipherUsed) = try PKCS8Encryption.encryptPBES2(
            data: privateKeyInfo,
            passphrase: passphrase,
            iterations: iterations,
            prf: prf,
            cipher: cipher
        )
        let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params, prf: prfUsed, cipher: cipherUsed)
        let encryptedInfo = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(
            algorithmIdentifier: algId,
            encryptedData: encrypted
        )
        return PKCS8Encryption.formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: encryptedInfo)
    }
}
