import Testing
import Foundation
@testable import SwiftKeyGen

@Test("Generate and serialize Ed25519 key with CBC cipher")
func testEd25519WithCBC() throws {
    let key = try Ed25519KeyGenerator.generate(comment: "test@example.com")
    
    // Test with AES-128-CBC
    let serialized = try OpenSSHPrivateKey.serialize(
        key: key,
        passphrase: "testpass",
        comment: key.comment,
        cipher: "aes128-cbc"
    )
    
    // Try to parse it back
    let parsed = try OpenSSHPrivateKey.parse(data: serialized, passphrase: "testpass")
    
    #expect(parsed.keyType == key.keyType)
}

@Test("Generate and serialize Ed25519 key with 3DES-CBC")
func testEd25519With3DES() throws {
    let key = try Ed25519KeyGenerator.generate(comment: "test@example.com")
    
    // Test with 3DES-CBC
    let serialized = try OpenSSHPrivateKey.serialize(
        key: key,
        passphrase: "testpass",
        comment: key.comment,
        cipher: "3des-cbc"
    )
    
    // Try to parse it back
    let parsed = try OpenSSHPrivateKey.parse(data: serialized, passphrase: "testpass")
    
    #expect(parsed.keyType == key.keyType)
}

@Test("Generate and serialize Ed25519 key with ChaCha20-Poly1305")
func testEd25519WithChaCha() throws {
    let key = try Ed25519KeyGenerator.generate(comment: "test@example.com")
    
    // Test with ChaCha20-Poly1305
    let serialized = try OpenSSHPrivateKey.serialize(
        key: key,
        passphrase: "testpass",
        comment: key.comment,
        cipher: "chacha20-poly1305@openssh.com"
    )
    
    // Try to parse it back
    let parsed = try OpenSSHPrivateKey.parse(data: serialized, passphrase: "testpass")
    
    #expect(parsed.keyType == key.keyType)
}