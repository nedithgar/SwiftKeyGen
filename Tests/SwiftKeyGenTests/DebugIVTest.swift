import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Debug IV generation")
func debugIVGeneration() throws {
    let salt = Data([0x74, 0xE4, 0xE7, 0x92, 0xA4, 0x71, 0x7F, 0x3F])
    let (key, iv) = PEMEncryption.evpBytesToKey(
        password: "test123",
        salt: salt,
        keyLen: 16,
        ivLen: 16
    )
    
    print("Salt: \(salt.hexEncodedString())")
    print("Salt length: \(salt.count) bytes")
    print("Key: \(key.hexEncodedString())")
    print("Key length: \(key.count) bytes")
    print("IV: \(iv.hexEncodedString())")
    print("IV length: \(iv.count) bytes")
}