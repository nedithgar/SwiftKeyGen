import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("AES-GCM Unit Tests", .tags(.unit))
struct AESGCMUnitTests {
    
    // MARK: - Helper Methods
    
    /// Generates a random key of the specified size
    private func generateRandomKey(size: Int) -> Data {
        var key = Data(count: size)
        for index in 0..<size {
            key[index] = UInt8.random(in: 0...255)
        }
        return key
    }
    
    /// Generates a random IV (16 bytes, first 12 used for GCM)
    private func generateRandomIV() -> Data {
        var iv = Data(count: 16)
        for index in 0..<16 {
            iv[index] = UInt8.random(in: 0...255)
        }
        return iv
    }
    
    /// Helper to test encryption/decryption round-trip
    private func testEncryptDecryptRoundTrip(keySize: Int, plaintext: String) throws {
        let plaintextData = Data(plaintext.utf8)
        let key = generateRandomKey(size: keySize)
        let iv = generateRandomIV()
        
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
    
    // MARK: - Tests
    
    @Test("AES-128-GCM encryption and decryption")
    func testAES128GCMEncryptDecrypt() throws {
        let plaintext = "Hello, AES-GCM encryption!"
        try testEncryptDecryptRoundTrip(keySize: 16, plaintext: plaintext)
    }
    
    @Test("AES-256-GCM encryption and decryption")
    func testAES256GCMEncryptDecrypt() throws {
        let plaintext = "Hello, AES-GCM encryption!"
        try testEncryptDecryptRoundTrip(keySize: 32, plaintext: plaintext)
    }
    
    @Test("AES-128-GCM with empty data")
    func testAES128GCMEmptyData() throws {
        let key = Data(repeating: 0x42, count: 16)
        let iv = generateRandomIV()
        let emptyData = Data()
        
        // Encrypt empty data
        let encrypted = try AESGCM.encrypt(data: emptyData, key: key, iv: iv)
        
        // Should only have the tag
        #expect(encrypted.count == 16)
        
        // Decrypt
        let decrypted = try AESGCM.decrypt(data: encrypted, key: key, iv: iv)
        #expect(decrypted.isEmpty)
    }
    
    @Test("AES-256-GCM with empty data")
    func testAES256GCMEmptyData() throws {
        let key = Data(repeating: 0x42, count: 32)
        let iv = generateRandomIV()
        let emptyData = Data()
        
        // Encrypt empty data
        let encrypted = try AESGCM.encrypt(data: emptyData, key: key, iv: iv)
        
        // Should only have the tag
        #expect(encrypted.count == 16)
        
        // Decrypt
        let decrypted = try AESGCM.decrypt(data: encrypted, key: key, iv: iv)
        #expect(decrypted.isEmpty)
    }
    
    @Test("AES-128-GCM authentication failure")
    func testAES128GCMAuthFailure() throws {
        let key = Data(repeating: 0x42, count: 16)
        let iv = generateRandomIV()
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
    
    @Test("AES-256-GCM authentication failure")
    func testAES256GCMAuthFailure() throws {
        let key = Data(repeating: 0x42, count: 32)
        let iv = generateRandomIV()
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