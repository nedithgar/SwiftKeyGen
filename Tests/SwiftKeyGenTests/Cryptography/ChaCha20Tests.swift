import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("ChaCha20-Poly1305 Tests")
struct ChaCha20Poly1305Tests {
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
}