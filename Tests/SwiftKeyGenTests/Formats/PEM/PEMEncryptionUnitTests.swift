import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PEM Encryption Unit Tests", .tags(.unit))
struct PEMEncryptionUnitTests {

    @Test("encrypt/decrypt round-trip for all ciphers")
    func testEncryptDecryptRoundTripAllCiphers() throws {
        let plaintexts: [Data] = [
            Data("".utf8),
            Data("hello pem encryption".utf8),
            Data("The quick brown fox jumps over the lazy dog".utf8)
        ]

        let passphrase = "p@ssw0rd"
        
        for cipher in PEMEncryption.PEMCipher.allCases {
            for plain in plaintexts {
                let (ciphertext, iv) = try PEMEncryption.encrypt(data: plain, passphrase: passphrase, cipher: cipher)

                // IV length and ciphertext shape
                #expect(iv.count == cipher.ivSize)
                #expect(ciphertext.count % cipher.blockSize == 0)
                #expect(ciphertext.count >= max(plain.count, cipher.blockSize))

                // Correct passphrase decrypts back to original
                let decrypted = try PEMEncryption.decrypt(data: ciphertext, passphrase: passphrase, cipher: cipher, iv: iv)
                #expect(decrypted == plain)

                // Wrong passphrase should not yield original plaintext
                do {
                    let wrong = try PEMEncryption.decrypt(data: ciphertext, passphrase: "wrong-pass", cipher: cipher, iv: iv)
                    #expect(wrong != plain)
                } catch let err as SSHKeyError {
                    // Most likely invalid padding due to wrong key
                    #expect(err == .invalidPadding)
                } catch {
                    // Any other error is also acceptable for a wrong key
                    #expect(Bool(true))
                }
            }
        }
    }

    // Consolidated from former EncryptedPEMTests.swift
    @Test("EVP_BytesToKey derives expected key/iv lengths")
    func testEVPBytesToKeyLengths() throws {
        let password = "test"
        let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        let (key128, iv128) = PEMEncryption.evpBytesToKey(password: password, salt: salt, keyLen: 16, ivLen: 16)
        #expect(key128.count == 16)
        #expect(iv128.count == 16)

        let (key256, iv256) = PEMEncryption.evpBytesToKey(password: password, salt: salt, keyLen: 32, ivLen: 16)
        #expect(key256.count == 32)
        #expect(iv256.count == 16)
        // Deterministic OpenSSL-compatible expansion: first 16 bytes identical
        #expect(key256.prefix(16) == key128)
    }

    @Test("PKCS#7 pad/unpad happy-path cases")
    func testPKCS7PadAndUnpad() throws {
        let cases: [(Data, Int, Int)] = [
            (Data([0x01, 0x02, 0x03]), 8, 5),                // partial block
            (Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]), 8, 8), // full block => full padding block
            (Data([0x01]), 16, 15),                          // minimal length
            (Data(repeating: 0x00, count: 16), 16, 16)       // exactly one block => full block padding
        ]
        for (plain, blockSize, expectedPad) in cases {
            let padded = PEMEncryption.pkcs7Pad(data: plain, blockSize: blockSize)
            #expect(padded.count % blockSize == 0)
            #expect(padded.count == plain.count + expectedPad)
            let padByte = padded.last!
            #expect(Int(padByte) == expectedPad)
            let unpadded = try PEMEncryption.pkcs7Unpad(data: padded, blockSize: blockSize)
            #expect(unpadded == plain)
        }
    }

    @Test("Encrypted SEC1 PEM headers emitted for default cipher (AES-128-CBC)")
    func testEncryptedSEC1PEMHeaders() throws {
        let key = try ECDSAKeyGenerator.generateP256(comment: "enc-hdrs")
        let pem = try key.sec1PEMRepresentation(passphrase: "secret123")
        #expect(pem.contains("-----BEGIN EC PRIVATE KEY-----"))
        #expect(pem.contains("-----END EC PRIVATE KEY-----"))
        #expect(pem.contains("Proc-Type: 4,ENCRYPTED"))
        #expect(pem.contains("DEK-Info: AES-128-CBC,"))
        // Salt/IV hex length for AES-128-CBC should be 32 chars (16 bytes)
        if let dekLine = pem.split(separator: "\n").first(where: { $0.hasPrefix("DEK-Info:") }) {
            let parts = dekLine.split(separator: ":")[1].trimmingCharacters(in: .whitespaces).split(separator: ",")
            if parts.count == 2 { #expect(parts[1].count == 32) }
        }
    }

    @Test("SEC1 PEM supports all configured ciphers")
    func testSEC1PEMAllCipherHeaders() throws {
        let key = try ECDSAKeyGenerator.generateP256()
        for cipher in PEMEncryption.PEMCipher.allCases {
            let pem = try key.sec1PEMRepresentation(passphrase: "ciphertest", cipher: cipher)
            #expect(pem.contains("DEK-Info: \(cipher.rawValue),"))
        }
    }

    @Test("PKCS#7 unpad rejects malformed inputs")
    func testPKCS7UnpadInvalidCases() {
        // Empty input
        #expect(throws: SSHKeyError.invalidPadding) {
            _ = try PEMEncryption.pkcs7Unpad(data: Data(), blockSize: 16)
        }

        // Padding length 0 (last byte = 0x00)
        #expect(throws: SSHKeyError.invalidPadding) {
            _ = try PEMEncryption.pkcs7Unpad(data: Data([0x01, 0x02, 0x03, 0x00]), blockSize: 4)
        }

        // Padding length > block size (0x11 > 16)
        #expect(throws: SSHKeyError.invalidPadding) {
            _ = try PEMEncryption.pkcs7Unpad(data: Data([0xAA, 0xBB, 0x11]), blockSize: 16)
        }

        // Data shorter than padding length (claims 5, but only 3 bytes total)
        #expect(throws: SSHKeyError.invalidPadding) {
            _ = try PEMEncryption.pkcs7Unpad(data: Data([0x00, 0x00, 0x05]), blockSize: 8)
        }

        // Non-uniform padding bytes (claims 4, but bytes differ)
        #expect(throws: SSHKeyError.invalidPadding) {
            _ = try PEMEncryption.pkcs7Unpad(
                data: Data([0x10, 0x20, 0x30, 0x01, 0x02, 0x03, 0x04, 0x04]),
                blockSize: 8
            )
        }
    }

    @Test("generateSalt returns 8 random bytes")
    func testGenerateSalt() throws {
        let s1 = try PEMEncryption.generateSalt()
        let s2 = try PEMEncryption.generateSalt()
        #expect(s1.count == 8)
        #expect(s2.count == 8)
        // Extremely unlikely to be equal; if equal, still length assertion holds
        #expect(s1 != s2)
    }

    @Test("formatEncryptedPEM emits correct headers and base64 wrapping (AES)")
    func testFormatEncryptedPEM_AES() throws {
        let type = "EC PRIVATE KEY"
        // 48 bytes ensures multi-line base64 with 64-char wrapping
        let encrypted = Data(repeating: 0xAA, count: 48)
        let iv = Data(hexString: "0102030405060708090A0B0C0D0E0F10")! // 16 bytes

        let pem = PEMEncryption.formatEncryptedPEM(type: type, encryptedData: encrypted, cipher: .aes256CBC, salt: iv)

        // Headers
        #expect(pem.contains("-----BEGIN EC PRIVATE KEY-----\n"))
        #expect(pem.contains("Proc-Type: 4,ENCRYPTED\n"))
        #expect(pem.contains("DEK-Info: AES-256-CBC,0102030405060708090A0B0C0D0E0F10\n"))
        #expect(pem.contains("-----END EC PRIVATE KEY-----"))

        // Base64 body lines are <= 64 chars, and first is exactly 64 if wrapped
        let lines = pem.components(separatedBy: "\n")
        #expect(lines.first == "-----BEGIN EC PRIVATE KEY-----")
        #expect(lines[1] == "Proc-Type: 4,ENCRYPTED")
        #expect(lines[2].hasPrefix("DEK-Info: AES-256-CBC,"))
        #expect(lines.last == "-----END EC PRIVATE KEY-----")

        let body = Array(lines.dropFirst(4).dropLast()) // skip BEGIN + 2 hdrs + blank line
        #expect(!body.isEmpty)
        for (i, line) in body.enumerated() {
            if i < body.count - 1 { #expect(line.count == 64) } else { #expect(line.count <= 64) }
        }
    }

    @Test("formatEncryptedPEM uses uppercase hex and 8-byte IV for 3DES")
    func testFormatEncryptedPEM_3DES() throws {
        let type = "RSA PRIVATE KEY"
        let encrypted = Data(repeating: 0xBB, count: 40) // arbitrary length
        let iv = Data(hexString: "a1b2c3d4e5f60708")! // 8 bytes

        let pem = PEMEncryption.formatEncryptedPEM(type: type, encryptedData: encrypted, cipher: .des3CBC, salt: iv)

        // Uppercase hex and correct cipher label
        #expect(pem.contains("DEK-Info: DES-EDE3-CBC,A1B2C3D4E5F60708"))
        #expect(pem.contains("-----BEGIN RSA PRIVATE KEY-----"))
        #expect(pem.contains("-----END RSA PRIVATE KEY-----"))
    }
}
