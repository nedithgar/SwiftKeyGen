import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("OpenSSH Parse Tests")
struct OpenSSHParseTests {
    
    @Test("Basic Ed25519 key serialize and parse")
    func testBasicEd25519SerializeAndParse() throws {
        // Generate a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        
        // Serialize it
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Convert to string to check format
        let serializedString = String(data: serializedData, encoding: .utf8)!
        #expect(serializedString.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(serializedString.contains("-----END OPENSSH PRIVATE KEY-----"))
        
        // Parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData)
        
        // Verify they match
        #expect(parsedKey.keyType == .ed25519)
        #expect(parsedKey.comment == "test@example.com")
        #expect(parsedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Ed25519 key with passphrase")
    func testEd25519WithPassphrase() throws {
        // Generate a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "encrypted@example.com") as! Ed25519Key
        let passphrase = "test-password"
        
        // Serialize with passphrase
        let serializedData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
        
        // Try to parse without passphrase - should fail
        #expect(throws: SSHKeyError.passphraseRequired) {
            _ = try OpenSSHPrivateKey.parse(data: serializedData)
        }
        
        // Parse with correct passphrase
        let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData, passphrase: passphrase)
        
        // Verify they match
        #expect(parsedKey.keyType == .ed25519)
        #expect(parsedKey.comment == "encrypted@example.com")
        #expect(parsedKey.publicKeyString() == key.publicKeyString())
    }
}