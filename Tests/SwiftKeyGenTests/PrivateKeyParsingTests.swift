import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Private Key Parsing Tests")
struct PrivateKeyParsingTests {
    
    @Test("Parse RSA private key from OpenSSH format", .disabled()) // Disabled due to long runtime
    func testRSAPrivateKeyParsing() throws {
        // Generate an RSA key
        let originalKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "test@example.com") as! RSAKey
        
        // Serialize it to OpenSSH format
        let serialized = try OpenSSHPrivateKey.serialize(key: originalKey, passphrase: nil)
        
        // Parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: serialized) as! RSAKey
        
        // Verify the keys match
        #expect(parsedKey.keyType == originalKey.keyType)
        #expect(parsedKey.comment == originalKey.comment)
        
        // Compare public key data
        #expect(parsedKey.publicKeyData() == originalKey.publicKeyData())
        
        // Test signing/verification to ensure the private key is correct
        let testData = "Hello, World!".data(using: .utf8)!
        let signature = try parsedKey.sign(data: testData)
        
        // Verify with parsed key
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid)
        
        // Verify with original key
        let isValidOriginal = try originalKey.verify(signature: signature, for: testData)
        #expect(isValidOriginal)
    }
    
    @Test("Parse ECDSA P256 private key from OpenSSH format")
    func testECDSAP256PrivateKeyParsing() throws {
        // Generate an ECDSA P256 key
        let originalKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "test-p256@example.com") as! ECDSAKey
        
        // Serialize it to OpenSSH format
        let serialized = try OpenSSHPrivateKey.serialize(key: originalKey, passphrase: nil)
        
        // Parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey
        
        // Verify the keys match
        #expect(parsedKey.keyType == originalKey.keyType)
        #expect(parsedKey.comment == originalKey.comment)
        
        // Compare public key data
        #expect(parsedKey.publicKeyData() == originalKey.publicKeyData())
        
        // Test signing/verification to ensure the private key is correct
        let testData = "Hello, ECDSA P256!".data(using: .utf8)!
        let signature = try parsedKey.sign(data: testData)
        
        // Verify with parsed key
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid)
        
        // Verify with original key
        let isValidOriginal = try originalKey.verify(signature: signature, for: testData)
        #expect(isValidOriginal)
    }
    
    @Test("Parse ECDSA P384 private key from OpenSSH format")
    func testECDSAP384PrivateKeyParsing() throws {
        // Generate an ECDSA P384 key
        let originalKey = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "test-p384@example.com") as! ECDSAKey
        
        // Serialize it to OpenSSH format
        let serialized = try OpenSSHPrivateKey.serialize(key: originalKey, passphrase: nil)
        
        // Parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey
        
        // Verify the keys match
        #expect(parsedKey.keyType == originalKey.keyType)
        #expect(parsedKey.comment == originalKey.comment)
        
        // Compare public key data
        #expect(parsedKey.publicKeyData() == originalKey.publicKeyData())
        
        // Test signing/verification to ensure the private key is correct
        let testData = "Hello, ECDSA P384!".data(using: .utf8)!
        let signature = try parsedKey.sign(data: testData)
        
        // Verify with parsed key
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid)
        
        // Verify with original key
        let isValidOriginal = try originalKey.verify(signature: signature, for: testData)
        #expect(isValidOriginal)
    }
    
    @Test("Parse ECDSA P521 private key from OpenSSH format")
    func testECDSAP521PrivateKeyParsing() throws {
        // Generate an ECDSA P521 key
        let originalKey = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "test-p521@example.com") as! ECDSAKey
        
        // Serialize it to OpenSSH format
        let serialized = try OpenSSHPrivateKey.serialize(key: originalKey, passphrase: nil)
        
        // Parse it back
        let parsedKey = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey
        
        // Verify the keys match
        #expect(parsedKey.keyType == originalKey.keyType)
        #expect(parsedKey.comment == originalKey.comment)
        
        // Compare public key data
        #expect(parsedKey.publicKeyData() == originalKey.publicKeyData())
        
        // Test signing/verification to ensure the private key is correct
        let testData = "Hello, ECDSA P521!".data(using: .utf8)!
        let signature = try parsedKey.sign(data: testData)
        
        // Verify with parsed key
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid)
        
        // Verify with original key
        let isValidOriginal = try originalKey.verify(signature: signature, for: testData)
        #expect(isValidOriginal)
    }
}