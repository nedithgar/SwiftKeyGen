import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("AES-CTR Unit Tests", .tags(.unit))
struct AESCTRUnitTests {
    
    
    @Test("AES-128-CTR encryption and decryption") func testAESCTRBasic() throws {
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
    

    @Test("AES-128-CTR round-trip") func testAESCTR128RoundTrip() throws {
        try roundTripCTR(keySize: 16, description: "AES-128")
    }

    @Test("AES-192-CTR round-trip") func testAESCTR192RoundTrip() throws {
        try roundTripCTR(keySize: 24, description: "AES-192")
    }

    @Test("AES-256-CTR round-trip") func testAESCTR256RoundTrip() throws {
        try roundTripCTR(keySize: 32, description: "AES-256")
    }

    /// Shared helper for AES-CTR round-trip tests across key sizes.
    /// - Parameters:
    ///   - keySize: Size in bytes (16, 24, 32).
    ///   - description: Human readable label for expectation context.
    private func roundTripCTR(keySize: Int, description: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let plaintext = Data("Hello, World! This is a test message.".utf8)
        let iv = Data(repeating: 0x01, count: 16)
        let key = Data(repeating: 0x2b, count: keySize)
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        let decrypted = try AESCTR.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext, "Round-trip failed for \(description) (\(keySize * 8) bits)")
    }
    
    @Test("AES-128-CTR counter rollover encryption and decryption") func testCounterIncrement() throws {
        // Test that counter increments properly
        let key = Data(repeating: 0x2b, count: 16)
        let iv = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE])
        
        // Encrypt enough data to force counter rollover
        let plaintext = Data(repeating: 0x00, count: 48) // 3 blocks
        let ciphertext = try AESCTR.encrypt(data: plaintext, key: key, iv: iv)
        
        // Verify it encrypts without error
        #expect(ciphertext.count == plaintext.count)
        
        // Decrypt should work
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