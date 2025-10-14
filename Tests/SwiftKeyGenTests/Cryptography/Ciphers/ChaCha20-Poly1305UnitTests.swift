import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("ChaCha20-Poly1305 Unit Tests", .tags(.unit))
struct ChaCha20Poly1305UnitTests {
    @Test("ChaCha20-Poly1305 basic functionality")
    func testChaCha20Poly1305Basic() throws {
        let key = Data(repeating: 0x42, count: 64) // 64-byte key for OpenSSH
        let plaintext = Data("Hello, World!".utf8)
        let iv = Data(count: 8) // Zero IV
        
        // Test encryption
        let encrypted = try ChaCha20Poly1305OpenSSH.encrypt(data: plaintext, key: key, iv: iv)
        #expect(encrypted.count == plaintext.count + 16)
        
        // Test decryption
        let decrypted = try ChaCha20Poly1305OpenSSH.decrypt(data: encrypted, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test("ChaCha20-Poly1305 empty data")
    func testChaCha20Poly1305EmptyData() throws {
        let key = Data(repeating: 0x42, count: 64)
        let plaintext = Data()
        let iv = Data(count: 8)
        
        let encrypted = try ChaCha20Poly1305OpenSSH.encrypt(data: plaintext, key: key, iv: iv)
        #expect(encrypted.count == 16) // Just the tag
        
        let decrypted = try ChaCha20Poly1305OpenSSH.decrypt(data: encrypted, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test("ChaCha20-Poly1305 encryption and decryption")
    func testChaCha20Poly1305() throws {
        let testData = Data(repeating: 0x41, count: 64) // 64 bytes
        let key = Data(repeating: 0x42, count: 64) // 64 bytes for ChaCha20-Poly1305
        let iv = Data() // No IV for OpenSSH ChaCha20-Poly1305
        
        let encrypted = try ChaCha20Poly1305OpenSSH.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try ChaCha20Poly1305OpenSSH.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }

    @Test("ChaCha20-Poly1305 worked example encryption")
    func testChaCha20Poly1305WorkedExampleEncryption() throws {
        guard let vectors = ChaCha20Poly1305Fixtures.workedExample else {
            Issue.record("Failed to load ChaCha20-Poly1305 worked example vectors")
            return
        }

        let encrypted = try ChaCha20Poly1305OpenSSH.encrypt(
            data: vectors.plaintext,
            key: vectors.key,
            iv: vectors.iv
        )

        #expect(encrypted.count == vectors.fullCiphertext.count)
        #expect(encrypted == vectors.fullCiphertext)
    }

    @Test("ChaCha20-Poly1305 worked example decryption")
    func testChaCha20Poly1305WorkedExampleDecryption() throws {
        guard let vectors = ChaCha20Poly1305Fixtures.workedExample else {
            Issue.record("Failed to load ChaCha20-Poly1305 worked example vectors")
            return
        }

        let decrypted = try ChaCha20Poly1305OpenSSH.decrypt(
            data: vectors.fullCiphertext,
            key: vectors.key,
            iv: vectors.iv
        )

        #expect(decrypted == vectors.plaintext)
    }
}

private enum ChaCha20Poly1305Fixtures {
    static let workedExample: Vectors? = {
        let keyParts = [
            "8b bf f6 85",
            "5f c1 02 33",
            "8c 37 3e 73",
            "aa c0 c9 14",
            "f0 76 a9 05",
            "b2 44 4a 32",
            "ee ca ff ea",
            "e2 2b ec c5",
            "e9 b7 a7 a5",
            "82 5a 82 49",
            "34 6e c1 c2",
            "83 01 cf 39",
            "45 43 fc 75",
            "69 88 7d 76",
            "e1 68 f3 75",
            "62 ac 07 40"
        ]
        let plaintextParts = [
            "00 00 00 48",
            "06 5e 00 00",
            "00 00 00 00",
            "00 38 4c 6f",
            "72 65 6d 20",
            "69 70 73 75",
            "6d 20 64 6f",
            "6c 6f 72 20",
            "73 69 74 20",
            "61 6d 65 74",
            "2c 20 63 6f",
            "6e 73 65 63",
            "74 65 74 75",
            "72 20 61 64",
            "69 70 69 73",
            "69 63 69 6e",
            "67 20 65 6c",
            "69 74 4e 43",
            "e8 04 dc 6c"
        ]
        let ciphertextParts = [
            "2c 3e cc e4",
            "a5 bc 05 89",
            "5b f0 7a 7b",
            "a9 56 b6 c6",
            "88 29 ac 7c",
            "83 b7 80 b7",
            "00 0e cd e7",
            "45 af c7 05",
            "bb c3 78 ce",
            "03 a2 80 23",
            "6b 87 b5 3b",
            "ed 58 39 66",
            "23 02 b1 64",
            "b6 28 6a 48",
            "cd 1e 09 71",
            "38 e3 cb 90",
            "9b 8b 2b 82",
            "9d d1 8d 2a",
            "35 ff 82 d9"
        ]
        let tagParts = [
            "95 34 9e 85",
            "5b f0 2c 29",
            "8e f7 75 f2",
            "d1 a7 e8 b8"
        ]

        guard
            let key = Data(hexString: keyParts.joined(separator: " ")),
            let iv = Data(hexString: "00 00 00 00 00 00 00 07"),
            let plaintext = Data(hexString: plaintextParts.joined(separator: " ")),
            let ciphertext = Data(hexString: ciphertextParts.joined(separator: " ")),
            let tag = Data(hexString: tagParts.joined(separator: " "))
        else {
            return nil
        }

        var fullCiphertext = ciphertext
        fullCiphertext.append(tag)

        return Vectors(
            key: key,
            iv: iv,
            plaintext: plaintext,
            ciphertext: ciphertext,
            tag: tag,
            fullCiphertext: fullCiphertext
        )
    }()

    struct Vectors {
        let key: Data
        let iv: Data
        let plaintext: Data
        let ciphertext: Data
        let tag: Data
        let fullCiphertext: Data
    }
}