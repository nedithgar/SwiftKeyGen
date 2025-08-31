import Testing
import Foundation
@testable import SwiftKeyGen

@Test("Cipher manager encryption with CBC")
func testCipherManagerCBC() throws {
    let testData = Data(repeating: 0x41, count: 32)
    let key = Data(repeating: 0x42, count: 16)
    let iv = Data(repeating: 0x43, count: 16)
    
    let encrypted = try Cipher.encrypt(data: testData, cipher: "aes128-cbc", key: key, iv: iv)
    let decrypted = try Cipher.decrypt(data: encrypted, cipher: "aes128-cbc", key: key, iv: iv)
    
    #expect(testData == decrypted)
}