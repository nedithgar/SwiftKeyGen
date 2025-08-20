import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("AES-CBC Tests")
struct AESCBCTests {
    @Test("AES-128-CBC encryption and decryption")
    func testAES128CBC() throws {
        let testData = Data(repeating: 0x41, count: 32) // 32 bytes of 'A'
        let key = Data(repeating: 0x42, count: 16) // 16 bytes for AES-128
        let iv = Data(repeating: 0x43, count: 16) // 16 bytes IV
        
        let encrypted = try AESCBC.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try AESCBC.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }

    @Test("AES-192-CBC encryption and decryption")
    func testAES192CBC() throws {
        let testData = Data(repeating: 0x41, count: 48) // 48 bytes
        let key = Data(repeating: 0x42, count: 24) // 24 bytes for AES-192
        let iv = Data(repeating: 0x43, count: 16) // 16 bytes IV
        
        let encrypted = try AESCBC.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try AESCBC.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }

    @Test("AES-256-CBC encryption and decryption")
    func testAES256CBC() throws {
        let testData = Data(repeating: 0x41, count: 64) // 64 bytes
        let key = Data(repeating: 0x42, count: 32) // 32 bytes for AES-256
        let iv = Data(repeating: 0x43, count: 16) // 16 bytes IV
        
        let encrypted = try AESCBC.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try AESCBC.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }
}