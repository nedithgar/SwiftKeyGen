import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("AES-CTR Unit Tests", .tags(.unit))
struct AESCTRUnitTests {
    
    
    @Test("AES-128-CTR encryption and decryption") func testAESCTR128() throws {
        // Test with a simple known pattern
        let key = Data(repeating: 0x2b, count: 16) // AES-128 key
        let iv = Data(repeating: 0x00, count: 16)  // Zero IV
        let plaintext = Data(repeating: 0x00, count: 32) // 32 bytes of zeros
        
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        #expect(ciphertext.count == plaintext.count)
        
        // Decrypt should give us back the original
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }
    
    @Test("AES-192-CTR encryption and decryption") func testAESCTR192() throws {
        let key = Data(repeating: 0x2b, count: 24) // AES-192 key
        let iv = Data(repeating: 0x00, count: 16)  // Zero IV (same baseline as 128-bit test)
        let plaintext = Data(repeating: 0x00, count: 32)
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        #expect(ciphertext.count == plaintext.count)
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test("AES-256-CTR encryption and decryption") func testAESCTR256() throws {
        let key = Data(repeating: 0x2b, count: 32) // AES-256 key
        let iv = Data(repeating: 0x00, count: 16)  // Zero IV
        let plaintext = Data(repeating: 0x00, count: 32)
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        #expect(ciphertext.count == plaintext.count)
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }
    
    @Test("AES-128-CTR counter rollover encryption and decryption") func testAESCTR128CounterRolloverWrap() throws {
        let key = Data(repeating: 0x2b, count: 16)
        let iv = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE])

        let plaintext = Data(repeating: 0x00, count: 48) // 3 blocks
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)

        #expect(ciphertext.count == plaintext.count)

        // Block-level keystream distinctness checks
        let block0 = ciphertext[0..<16]
        let block1 = ciphertext[16..<32]
        let block2 = ciphertext[32..<48]
        #expect(block0 != block1)
        #expect(block1 != block2)
        #expect(block0 != block2)

        // Streaming determinism: re-encrypt first 32 bytes with same IV should reproduce prefix
        let firstTwoPlainBlocks = Data(repeating: 0x00, count: 32)
        let firstTwoCipher = try AESCTR.encrypt(data: firstTwoPlainBlocks, key: key, iv: iv)
        #expect(firstTwoCipher == ciphertext.prefix(32))

        // Round-trip correctness
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }
    
    @Test("AES-CTR invalid key length") func testInvalidKeySize() throws {
        let plaintext = Data("test".utf8)
        let iv = Data(repeating: 0x00, count: 16)
        let invalidKey = Data(repeating: 0x2b, count: 15) // Invalid size
        
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try AESCTR.encrypt(data: plaintext, key: invalidKey, iv: iv)
        }
    }
    
    @Test("AES-CTR invalid IV length") func testInvalidIVSize() throws {
        let plaintext = Data("test".utf8)
        let key = Data(repeating: 0x2b, count: 16)
        let invalidIV = Data(repeating: 0x00, count: 15) // Invalid size
        
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try AESCTR.encrypt(data: plaintext, key: key, iv: invalidIV)
        }
    }
}