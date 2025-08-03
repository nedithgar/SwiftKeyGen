import Testing
import Foundation
@testable import SwiftKeyGen

struct OpenSSHPrivateKeyTests {
    
    @Test func serializeEd25519WithoutPassphrase() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        
        let serialized = try OpenSSHPrivateKey.serialize(key: key)
        let serializedString = String(data: serialized, encoding: .utf8)!
        
        // Verify PEM format
        #expect(serializedString.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(serializedString.hasSuffix("-----END OPENSSH PRIVATE KEY-----\n"))
        
        // Verify base64 content exists
        let lines = serializedString.components(separatedBy: .newlines)
        #expect(lines.count >= 3) // At least BEGIN, content, END
    }
    
    @Test func serializeEd25519WithPassphrase() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "secure@example.com") as! Ed25519Key
        
        let serialized = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: "test-passphrase",
            rounds: 16  // Use fewer rounds for testing
        )
        
        let serializedString = String(data: serialized, encoding: .utf8)!
        
        // Verify PEM format
        #expect(serializedString.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(serializedString.hasSuffix("-----END OPENSSH PRIVATE KEY-----\n"))
        
        // The encrypted content should be different from unencrypted
        let unencrypted = try OpenSSHPrivateKey.serialize(key: key)
        #expect(serialized != unencrypted)
    }
    
    @Test func fileOutputWithPassphrase() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let privatePath = tempDir.appendingPathComponent("test_ed25519").path
        let publicPath = privatePath + ".pub"
        
        // Clean up any existing files
        try? FileManager.default.removeItem(atPath: privatePath)
        try? FileManager.default.removeItem(atPath: publicPath)
        
        // Generate with passphrase
        try KeyFileManager.generateKeyPairFiles(
            type: .ed25519,
            privatePath: privatePath,
            comment: "passphrase-test@example.com",
            passphrase: "my-secure-passphrase"
        )
        
        // Verify files exist
        #expect(FileManager.default.fileExists(atPath: privatePath))
        #expect(FileManager.default.fileExists(atPath: publicPath))
        
        // Read private key file
        let privateKeyData = try Data(contentsOf: URL(fileURLWithPath: privatePath))
        let privateKeyString = String(data: privateKeyData, encoding: .utf8)!
        
        // Verify OpenSSH format
        #expect(privateKeyString.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(privateKeyString.contains("-----END OPENSSH PRIVATE KEY-----"))
        
        // Clean up
        try? FileManager.default.removeItem(atPath: privatePath)
        try? FileManager.default.removeItem(atPath: publicPath)
    }
    
    @Test func differentPassphrasesProduceDifferentOutput() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let encrypted1 = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: "password1",
            rounds: 16
        )
        
        let encrypted2 = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: "password2",
            rounds: 16
        )
        
        // Different passphrases should produce different encrypted output
        #expect(encrypted1 != encrypted2)
    }
}