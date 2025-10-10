import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PKCS#8 Encryption Unit Tests", .tags(.unit))
struct PKCS8EncryptionUnitTests {

    @Test("PBKDF2 HMAC-SHA1 matches RFC 6070 vectors")
    func testPBKDF2Vectors() throws {
        // RFC 6070 test vectors for PBKDF2-HMAC-SHA1
        let password = "password"
        let salt = Data("salt".utf8)

        // c = 1, dkLen = 20
        let dk1 = try PKCS8Encryption.pbkdf2(password: password, salt: salt, iterations: 1, keyLen: 20)
        #expect(dk1.hexEncodedString() == "0c60c80f961f0e71f3a9b524af6012062fe037a6")

        // c = 2, dkLen = 20
        let dk2 = try PKCS8Encryption.pbkdf2(password: password, salt: salt, iterations: 2, keyLen: 20)
        #expect(dk2.hexEncodedString() == "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")

        // c = 4096, dkLen = 20
        let dk4096 = try PKCS8Encryption.pbkdf2(password: password, salt: salt, iterations: 4096, keyLen: 20)
        #expect(dk4096.hexEncodedString() == "4b007901b765489abead49d926f721d065a429c1")
    }

    // Additional differentiation check (consolidated from removed EncryptedPEMTests.swift)
    @Test("PBKDF2 different iteration counts yield different keys")
    func testPBKDF2IterationDifference() throws {
        let password = "password"
        let salt = Data("salt".utf8)
        let dk1 = try PKCS8Encryption.pbkdf2(password: password, salt: salt, iterations: 1, keyLen: 20)
        let dk2 = try PKCS8Encryption.pbkdf2(password: password, salt: salt, iterations: 2048, keyLen: 20)
        #expect(dk1.count == 20 && dk2.count == 20)
        #expect(dk1 != dk2)
    }

    @Test("PBES2 AES-128-CBC encrypt/decrypt round-trip")
    func testEncryptPBES2RoundTrip() throws {
        let passphrase = "test-passphrase"
        let plain = Data("hello pkcs8 secrets".utf8)

        let (ciphertext, params, _, _) = try PKCS8Encryption.encryptPBES2(data: plain, passphrase: passphrase, iterations: 2048)

        // Parameters sanity
        #expect(params.salt.count == 8)
        #expect(params.iterations == 2048)
        #expect(params.iv.count == 16)
        #expect(params.keySize == 16)
        #expect(ciphertext.count % 16 == 0)
        #expect(ciphertext.count >= plain.count)

        // Derive key and decrypt
        let key = try PKCS8Encryption.pbkdf2(password: passphrase, salt: params.salt, iterations: params.iterations, keyLen: params.keySize)
        let padded = try AESCBC.decrypt(data: ciphertext, key: key, iv: params.iv)
        let unpadded = try PEMEncryption.pkcs7Unpad(data: padded, blockSize: 16)
        #expect(unpadded == plain)

        // Wrong passphrase should not yield original plaintext
        let wrongKey = try PKCS8Encryption.pbkdf2(password: "wrong", salt: params.salt, iterations: params.iterations, keyLen: params.keySize)
        let wrongPadded = try AESCBC.decrypt(data: ciphertext, key: wrongKey, iv: params.iv)
        // Unpadding may or may not succeed by chance; compare content if it does
        if let maybeUnpadded = try? PEMEncryption.pkcs7Unpad(data: wrongPadded, blockSize: 16) {
            #expect(maybeUnpadded != plain)
        } else {
            // Unpadding failed as expected
            #expect(Bool(true))
        }
    }

    @Test("PBES2 AlgorithmIdentifier contains expected OIDs and parameters")
    func testCreatePBES2AlgorithmIdentifier() throws {
        // Deterministic parameters for inspection
        let salt = Data(hexString: "0102030405060708")!
        let iv = Data(hexString: "101112131415161718191a1b1c1d1e1f")!
        let params = PKCS8Encryption.PBES2Parameters(salt: salt, iterations: 2048, iv: iv, keySize: 16)

        let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params)
        #expect(algId.first == 0x30) // SEQUENCE

        // OIDs used
        let pbes2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D])
        let pbkdf2OID = Data([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C])
        let hmacSHA1OID = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07])
        let aes128CBCOID = Data([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02])

        #expect(algId.range(of: pbes2OID) != nil)
        #expect(algId.range(of: pbkdf2OID) != nil)
        #expect(algId.range(of: hmacSHA1OID) != nil)
        #expect(algId.range(of: aes128CBCOID) != nil)

        // Salt OCTET STRING (0x04 len salt)
        let saltTLV = Data([0x04, 0x08]) + salt
        #expect(algId.range(of: saltTLV) != nil)

        // Iterations INTEGER: 2048 -> 0x0800 => 02 02 08 00
        #expect(algId.range(of: Data([0x02, 0x02, 0x08, 0x00])) != nil)

        // Key length INTEGER: 16 -> 0x10 => 02 01 10
        #expect(algId.range(of: Data([0x02, 0x01, 0x10])) != nil)

        // IV OCTET STRING (16 bytes)
        let ivTLV = Data([0x04, 0x10]) + iv
        #expect(algId.range(of: ivTLV) != nil)

        // PRF AlgorithmIdentifier includes NULL params: 05 00
        #expect(algId.range(of: Data([0x05, 0x00])) != nil)
    }

    @Test("EncryptedPrivateKeyInfo wraps AlgorithmIdentifier and ciphertext")
    func testEncodeEncryptedPrivateKeyInfo() throws {
        let salt = Data(hexString: "0102030405060708")!
        let iv = Data(hexString: "101112131415161718191a1b1c1d1e1f")!
        let params = PKCS8Encryption.PBES2Parameters(salt: salt, iterations: 2048, iv: iv, keySize: 16)
        let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params)

        let encrypted = Data(repeating: 0xAA, count: 32)
        let info = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(algorithmIdentifier: algId, encryptedData: encrypted)

        #expect(info.first == 0x30) // SEQUENCE
        // Must contain the AlgorithmIdentifier bytes
        #expect(info.range(of: algId) != nil)
        // Must contain the encrypted OCTET STRING
        let encTLV = Data([0x04, 0x20]) + encrypted
        #expect(info.range(of: encTLV) != nil)
    }

    @Test("PEM formatting wraps base64 at 64 columns with proper headers")
    func testFormatEncryptedPKCS8PEM() throws {
        // Build a small-but-nontrivial EncryptedPrivateKeyInfo
        let salt = Data(hexString: "0102030405060708")!
        let iv = Data(hexString: "101112131415161718191a1b1c1d1e1f")!
        let params = PKCS8Encryption.PBES2Parameters(salt: salt, iterations: 2048, iv: iv, keySize: 16)
        let algId = PKCS8Encryption.createPBES2AlgorithmIdentifier(parameters: params)
        let encrypted = Data(repeating: 0xBB, count: 48)
        let info = PKCS8Encryption.encodeEncryptedPrivateKeyInfo(algorithmIdentifier: algId, encryptedData: encrypted)

        let pem = PKCS8Encryption.formatEncryptedPKCS8PEM(encryptedPrivateKeyInfo: info)
        #expect(pem.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"))
        #expect(pem.hasSuffix("-----END ENCRYPTED PRIVATE KEY-----"))

        // Extract base64 lines between headers
        let lines = pem.components(separatedBy: "\n")
        #expect(lines.first == "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        #expect(lines.last == "-----END ENCRYPTED PRIVATE KEY-----")
        let b64Lines = Array(lines.dropFirst().dropLast())
        #expect(!b64Lines.isEmpty)
        for l in b64Lines { #expect(!l.isEmpty && l.count <= 64) }
        // If multiple lines, the first should be exactly 64 chars when wrapping occurs
        if b64Lines.count > 1 { #expect(b64Lines[0].count == 64) }
    }
}

