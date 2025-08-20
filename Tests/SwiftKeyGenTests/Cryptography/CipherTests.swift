import Testing
import Foundation
@testable import SwiftKeyGen

@Test("3DES-CBC encryption and decryption")
func test3DESCBC() throws {
    let testData = Data(repeating: 0x41, count: 24) // 24 bytes
    let key = Data(repeating: 0x42, count: 24) // 24 bytes for 3DES
    let iv = Data(repeating: 0x43, count: 8) // 8 bytes IV for DES
    
    let encrypted = try TripleDESCBC.encrypt(data: testData, key: key, iv: iv)
    let decrypted = try TripleDESCBC.decrypt(data: encrypted, key: key, iv: iv)
    
    #expect(testData == decrypted)
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

@Test("Cipher manager encryption with CBC")
func testCipherManagerCBC() throws {
    let testData = Data(repeating: 0x41, count: 32)
    let key = Data(repeating: 0x42, count: 16)
    let iv = Data(repeating: 0x43, count: 16)
    
    let encrypted = try Cipher.encrypt(data: testData, cipher: "aes128-cbc", key: key, iv: iv)
    let decrypted = try Cipher.decrypt(data: encrypted, cipher: "aes128-cbc", key: key, iv: iv)
    
    #expect(testData == decrypted)
}