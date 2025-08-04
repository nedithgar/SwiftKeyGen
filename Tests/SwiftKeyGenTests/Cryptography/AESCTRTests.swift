import Testing
import Foundation
@testable import SwiftKeyGen

struct AESCTRTests {
    
    @Test func testAESCTRBasic() throws {
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
    
    @Test func testAESCTRDifferentKeySizes() throws {
        let plaintext = Data("Hello, World! This is a test message.".utf8)
        let iv = Data(repeating: 0x01, count: 16)
        
        // Test AES-128
        let key128 = Data(repeating: 0x2b, count: 16)
        let cipher128 = try AESCTR.encrypt(data: plaintext, key: key128, iv: iv)
        let decrypted128 = try AESCTR.decrypt(data: cipher128, key: key128, iv: iv)
        #expect(decrypted128 == plaintext)
        
        // Test AES-192
        let key192 = Data(repeating: 0x2b, count: 24)
        let cipher192 = try AESCTR.encrypt(data: plaintext, key: key192, iv: iv)
        let decrypted192 = try AESCTR.decrypt(data: cipher192, key: key192, iv: iv)
        #expect(decrypted192 == plaintext)
        
        // Test AES-256
        let key256 = Data(repeating: 0x2b, count: 32)
        let cipher256 = try AESCTR.encrypt(data: plaintext, key: key256, iv: iv)
        let decrypted256 = try AESCTR.decrypt(data: cipher256, key: key256, iv: iv)
        #expect(decrypted256 == plaintext)
    }
    
    @Test func testCounterIncrement() throws {
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
    
    @Test func testInvalidKeySize() throws {
        let plaintext = Data("test".utf8)
        let iv = Data(repeating: 0x00, count: 16)
        let invalidKey = Data(repeating: 0x2b, count: 15) // Invalid size
        
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try AESCTR.encrypt(data: plaintext, key: invalidKey, iv: iv)
        }
    }
    
    @Test func testInvalidIVSize() throws {
        let plaintext = Data("test".utf8)
        let key = Data(repeating: 0x2b, count: 16)
        let invalidIV = Data(repeating: 0x00, count: 15) // Invalid size
        
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try AESCTR.encrypt(data: plaintext, key: key, iv: invalidIV)
        }
    }
}