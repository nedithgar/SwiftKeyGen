import Testing
import Foundation
@testable import SwiftKeyGen

@Test func testChaCha20Poly1305Basic() throws {
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

@Test func testChaCha20Poly1305EmptyData() throws {
    let key = Data(repeating: 0x42, count: 64)
    let plaintext = Data()
    let iv = Data(count: 8)
    
    let encrypted = try ChaCha20Poly1305OpenSSH.encrypt(data: plaintext, key: key, iv: iv)
    #expect(encrypted.count == 16) // Just the tag
    
    let decrypted = try ChaCha20Poly1305OpenSSH.decrypt(data: encrypted, key: key, iv: iv)
    #expect(decrypted == plaintext)
}