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

    @Test("ECDSA P-256 key serialize and parse")
    func testECDSAP256SerializeAndParse() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "test-p256@example.com") as! ECDSAKey
        let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
        let parsed = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey

        #expect(parsed.keyType == key.keyType)
        #expect(parsed.comment == key.comment)
        #expect(parsed.publicKeyData() == key.publicKeyData())

        let message = Data("Hello, ECDSA P256!".utf8)
        let sig = try parsed.sign(data: message)
        #expect(try parsed.verify(signature: sig, for: message))
        #expect(try key.verify(signature: sig, for: message))
    }

    @Test("ECDSA P-384 key serialize and parse")
    func testECDSAP384SerializeAndParse() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "test-p384@example.com") as! ECDSAKey
        let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
        let parsed = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey

        #expect(parsed.keyType == key.keyType)
        #expect(parsed.comment == key.comment)
        #expect(parsed.publicKeyData() == key.publicKeyData())

        let message = Data("Hello, ECDSA P384!".utf8)
        let sig = try parsed.sign(data: message)
        #expect(try parsed.verify(signature: sig, for: message))
        #expect(try key.verify(signature: sig, for: message))
    }

    @Test("ECDSA P-521 key serialize and parse")
    func testECDSAP521SerializeAndParse() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "test-p521@example.com") as! ECDSAKey
        let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
        let parsed = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey

        #expect(parsed.keyType == key.keyType)
        #expect(parsed.comment == key.comment)
        #expect(parsed.publicKeyData() == key.publicKeyData())

        let message = Data("Hello, ECDSA P521!".utf8)
        let sig = try parsed.sign(data: message)
        #expect(try parsed.verify(signature: sig, for: message))
        #expect(try key.verify(signature: sig, for: message))
    }

    @Test("RSA key serialize and parse (slow)", .disabled())
    func testRSASerializeAndParse() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "test@example.com") as! RSAKey
        let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
        let parsed = try OpenSSHPrivateKey.parse(data: serialized) as! RSAKey

        #expect(parsed.keyType == key.keyType)
        #expect(parsed.comment == key.comment)
        #expect(parsed.publicKeyData() == key.publicKeyData())

        let message = Data("Hello, RSA!".utf8)
        let sig = try parsed.sign(data: message)
        #expect(try parsed.verify(signature: sig, for: message))
        #expect(try key.verify(signature: sig, for: message))
    }
}
