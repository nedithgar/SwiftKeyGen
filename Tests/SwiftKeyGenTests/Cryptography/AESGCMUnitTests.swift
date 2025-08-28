import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("AES-GCM Unit Tests", .tags(.unit))
struct AESGCMUnitTests {
    
    @Test("AES-GCM encryption and decryption")
    func testAESGCMEncryptDecrypt() throws {
        // Test with different key sizes
        let keySizes = [16, 32] // 128-bit and 256-bit
        let plaintext = "Hello, AES-GCM encryption!"
        let plaintextData = Data(plaintext.utf8)
        
        for keySize in keySizes {
            // Generate random key and IV
            var key = Data(count: keySize)
            for i in 0..<keySize {
                key[i] = UInt8.random(in: 0...255)
            }
            
            var iv = Data(count: 16) // Will use first 12 bytes
            for i in 0..<16 {
                iv[i] = UInt8.random(in: 0...255)
            }
            
            // Encrypt
            let encrypted = try AESGCM.encrypt(data: plaintextData, key: key, iv: iv)
            
            // Verify tag is appended
            #expect(encrypted.count == plaintextData.count + 16)
            
            // Decrypt
            let decrypted = try AESGCM.decrypt(data: encrypted, key: key, iv: iv)
            
            // Verify
            #expect(decrypted == plaintextData)
            #expect(String(data: decrypted, encoding: .utf8) == plaintext)
        }
    }
    
    @Test("AES-GCM with empty data")
    func testAESGCMEmptyData() throws {
        let key = Data(repeating: 0x42, count: 32)
        let iv = Data(repeating: 0x12, count: 16)
        let emptyData = Data()
        
        // Encrypt empty data
        let encrypted = try AESGCM.encrypt(data: emptyData, key: key, iv: iv)
        
        // Should only have the tag
        #expect(encrypted.count == 16)
        
        // Decrypt
        let decrypted = try AESGCM.decrypt(data: encrypted, key: key, iv: iv)
        #expect(decrypted.isEmpty)
    }
    
    @Test("AES-GCM authentication failure")
    func testAESGCMAuthFailure() throws {
        let key = Data(repeating: 0x42, count: 32)
        let iv = Data(repeating: 0x12, count: 16)
        let plaintext = Data("Test data".utf8)
        
        // Encrypt
        var encrypted = try AESGCM.encrypt(data: plaintext, key: key, iv: iv)
        
        // Tamper with the ciphertext
        encrypted[0] ^= 0xFF
        
        // Decryption should fail
        #expect(throws: SSHKeyError.self) {
            _ = try AESGCM.decrypt(data: encrypted, key: key, iv: iv)
        }
    }
}