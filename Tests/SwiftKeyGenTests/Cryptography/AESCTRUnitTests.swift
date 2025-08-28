import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("AES-CTR Unit Tests", .tags(.unit))
struct AESCTRUnitTests {
    
    @Test("AES-128-CTR encryption and decryption") func testAESCTR128() throws {
        try assertCTRBasic(keySize: 16)
    }
    
    @Test("AES-192-CTR encryption and decryption") func testAESCTR192() throws {
        try assertCTRBasic(keySize: 24)
    }

    @Test("AES-256-CTR encryption and decryption") func testAESCTR256() throws {
        try assertCTRBasic(keySize: 32)
    }

    /// Basic AES-CTR round-trip for a given key size using zero IV and two blocks of zero plaintext.
    /// Verifies ciphertext length and round-trip decryption.
    private func assertCTRBasic(keySize: Int) throws {
        let key = Data(repeating: 0x2b, count: keySize)
        let iv = Data(repeating: 0x00, count: 16)
        let plaintext = Data(repeating: 0x00, count: 32)
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        #expect(ciphertext.count == plaintext.count)
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }
    
    @Test("AES-128-CTR counter rollover encryption and decryption") func testAESCTR128CounterRolloverWrap() throws {
        try assertCTRCounterRollover(keySize: 16)
    }

    @Test("AES-192-CTR counter rollover encryption and decryption") func testAESCTR192CounterRolloverWrap() throws {
        try assertCTRCounterRollover(keySize: 24)
    }

    @Test("AES-256-CTR counter rollover encryption and decryption") func testAESCTR256CounterRolloverWrap() throws {
        try assertCTRCounterRollover(keySize: 32)
    }

    /// Helper to assert AES-CTR counter rollover correctness for a given key size.
    /// Exercises:
    ///  - Counter increment across last two values before wrap (..FFFE, ..FFFF)
    ///  - 128-bit rollover to 0x00..00
    ///  - Distinct keystream blocks for all-zero plaintext
    ///  - Streaming determinism (prefix stability when re-encrypting subset)
    private func assertCTRCounterRollover(keySize: Int) throws {
        let key = Data(repeating: 0x2b, count: keySize)
        let iv = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE])
        let plaintext = Data(repeating: 0x00, count: 48)
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        // ciphertext length should match plaintext length
        #expect(ciphertext.count == plaintext.count)
        let firstBlock = ciphertext[0..<16]
        let secondBlock = ciphertext[16..<32]
        let thirdBlock = ciphertext[32..<48]
        // Blocks should all differ (distinct keystream per counter value and after rollover)
        #expect(firstBlock != secondBlock)
        #expect(secondBlock != thirdBlock)
        #expect(firstBlock != thirdBlock)
        let firstTwoPlain = Data(repeating: 0x00, count: 32)
        let firstTwoCipher = try AESCTR.encrypt(data: firstTwoPlain, key: key, iv: iv)
        // Re-encrypting prefix should reproduce identical first two blocks
        #expect(firstTwoCipher == ciphertext.prefix(32))
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        // Round-trip integrity
        #expect(decrypted == plaintext)
    }

    @Test("AES-CTR invalid key lengths") func testInvalidKeySizes() throws {
        let plaintext = Data("test".utf8)
        let iv = Data(repeating: 0x00, count: 16)
        // All sizes that should be rejected (valid sizes: 16, 24, 32)
        let invalidSizes = [0, 1, 7, 8, 15, 17, 18, 23, 25, 31, 33, 48]
        for size in invalidSizes {
            let invalidKey = Data(repeating: 0x2b, count: size)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try AESCTR.encrypt(data: plaintext, key: invalidKey, iv: iv)
            }
        }
    }
    
    @Test("AES-CTR invalid IV lengths") func testInvalidIVSizes() throws {
        let plaintext = Data("test".utf8)
        let key = Data(repeating: 0x2b, count: 16)
        // All IV sizes that should be rejected (valid IV size: 16 bytes)
        let invalidIVLengths = [0, 1, 7, 8, 15, 17, 18, 24, 31, 32]
        for len in invalidIVLengths {
            let invalidIV = Data(repeating: 0x00, count: len)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try AESCTR.encrypt(data: plaintext, key: key, iv: invalidIV)
            }
        }
    }
}