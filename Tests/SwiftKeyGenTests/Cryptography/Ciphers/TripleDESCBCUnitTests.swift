import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("3DES-CBC Unit Tests", .tags(.unit))
struct TripleDESCBCUnitTests {
    @Test("3DES-CBC encryption and decryption")
    func test3DESCBC() throws {
        let testData = Data(repeating: 0x41, count: 24) // 24 bytes
        let key = Data(repeating: 0x42, count: 24) // 24 bytes for 3DES
        let iv = Data(repeating: 0x43, count: 8) // 8 bytes IV for DES
        
        let encrypted = try TripleDESCBC.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try TripleDESCBC.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }
}