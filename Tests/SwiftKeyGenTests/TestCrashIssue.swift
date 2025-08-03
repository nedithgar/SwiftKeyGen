import Testing
import Foundation
@testable import SwiftKeyGen

struct TestCrashIssue {
    @Test("Simple key generation test")
    func testSimpleKeyGeneration() throws {
        // Test basic key generation
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        #expect(keyPair.privateKey.keyType == .ed25519)
    }
    
    @Test("Simple serialization test")
    func testSimpleSerialization() throws {
        // Generate a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        
        // Try to serialize without passphrase
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        #expect(keyData.count > 0)
    }
    
    @Test("Simple parsing test")
    func testSimpleParsing() throws {
        // Generate and serialize a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Try to parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: keyData, passphrase: nil)
        #expect(parsedKey.keyType == .ed25519)
    }
}