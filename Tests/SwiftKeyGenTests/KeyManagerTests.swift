import Testing
import Foundation
@testable import SwiftKeyGen

struct KeyManagerTests {
    
    func makeTestDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("swiftkeygen-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Set proper permissions
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        #endif
        return dir
    }
    
    @Test("Parse unencrypted Ed25519 key")
    func testParseUnencryptedEd25519Key() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate a test key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        
        // Serialize without passphrase
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Save to file
        let keyPath = testDirectory.appendingPathComponent("test_key").path
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Read and parse the key
        let parsedKey = try KeyManager.readPrivateKey(from: keyPath)
        
        #expect(parsedKey.keyType == .ed25519)
        #expect(parsedKey.comment == "test@example.com")
        #expect(parsedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Parse encrypted Ed25519 key")
    func testParseEncryptedEd25519Key() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate a test key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "encrypted@example.com")
        let key = keyPair.privateKey
        
        // Serialize with passphrase
        let passphrase = "test-passphrase-123"
        let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
        
        // Save to file
        let keyPath = testDirectory.appendingPathComponent("encrypted_key").path
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Try to read without passphrase - should fail
        #expect(throws: SSHKeyError.passphraseRequired) {
            _ = try KeyManager.readPrivateKey(from: keyPath)
        }
        
        // Try with wrong passphrase - should fail
        #expect(throws: SSHKeyError.invalidPassphrase) {
            _ = try KeyManager.readPrivateKey(from: keyPath, passphrase: "wrong-passphrase")
        }
        
        // Read with correct passphrase
        let parsedKey = try KeyManager.readPrivateKey(from: keyPath, passphrase: passphrase)
        
        #expect(parsedKey.keyType == .ed25519)
        #expect(parsedKey.comment == "encrypted@example.com")
        #expect(parsedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Change passphrase on key")
    func testChangePassphrase() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate and save an encrypted key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "passchange@example.com")
        let key = keyPair.privateKey
        let oldPassphrase = "old-passphrase"
        let newPassphrase = "new-passphrase"
        
        let keyPath = testDirectory.appendingPathComponent("passchange_key").path
        let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: oldPassphrase)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Change the passphrase
        try KeyManager.changePassphrase(
            keyPath: keyPath,
            oldPassphrase: oldPassphrase,
            newPassphrase: newPassphrase
        )
        
        // Verify old passphrase no longer works
        #expect(throws: SSHKeyError.invalidPassphrase) {
            _ = try KeyManager.readPrivateKey(from: keyPath, passphrase: oldPassphrase)
        }
        
        // Verify new passphrase works
        let updatedKey = try KeyManager.readPrivateKey(from: keyPath, passphrase: newPassphrase)
        #expect(updatedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Remove passphrase from key")
    func testRemovePassphrase() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate and save an encrypted key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        let key = keyPair.privateKey
        let passphrase = "remove-me"
        
        let keyPath = testDirectory.appendingPathComponent("remove_pass_key").path
        let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Remove the passphrase
        try KeyManager.removePassphrase(keyPath: keyPath, currentPassphrase: passphrase)
        
        // Verify key can be read without passphrase
        let updatedKey = try KeyManager.readPrivateKey(from: keyPath)
        #expect(updatedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Add passphrase to unencrypted key")
    func testAddPassphrase() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate and save an unencrypted key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        let key = keyPair.privateKey
        
        let keyPath = testDirectory.appendingPathComponent("add_pass_key").path
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Add a passphrase
        let newPassphrase = "new-secure-pass"
        try KeyManager.addPassphrase(keyPath: keyPath, newPassphrase: newPassphrase)
        
        // Verify key requires passphrase now
        #expect(throws: SSHKeyError.passphraseRequired) {
            _ = try KeyManager.readPrivateKey(from: keyPath)
        }
        
        // Verify passphrase works
        let updatedKey = try KeyManager.readPrivateKey(from: keyPath, passphrase: newPassphrase)
        #expect(updatedKey.publicKeyString() == key.publicKeyString())
    }
    
    @Test("Update key comment")
    func testUpdateComment() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate and save a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "old-comment")
        let key = keyPair.privateKey
        
        let keyPath = testDirectory.appendingPathComponent("comment_key").path
        let publicKeyPath = keyPath + ".pub"
        
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        try keyPair.publicKeyString.write(to: URL(fileURLWithPath: publicKeyPath), atomically: true, encoding: .utf8)
        
        // Update the comment
        let newComment = "new-comment@example.com"
        try KeyManager.updateComment(keyPath: keyPath, newComment: newComment)
        
        // Verify comment was updated
        let updatedKey = try KeyManager.readPrivateKey(from: keyPath)
        #expect(updatedKey.comment == newComment)
        
        // Verify public key file was also updated
        let publicKeyContent = try String(contentsOf: URL(fileURLWithPath: publicKeyPath))
        #expect(publicKeyContent.contains(newComment))
    }
    
    @Test("Verify passphrase")
    func testVerifyPassphrase() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Generate and save an encrypted key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        let key = keyPair.privateKey
        let passphrase = "correct-passphrase"
        
        let keyPath = testDirectory.appendingPathComponent("verify_key").path
        let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Test correct passphrase
        #expect(KeyManager.verifyPassphrase(keyPath: keyPath, passphrase: passphrase) == true)
        
        // Test wrong passphrase
        #expect(KeyManager.verifyPassphrase(keyPath: keyPath, passphrase: "wrong-passphrase") == false)
        
        // Test no passphrase on encrypted key
        #expect(KeyManager.verifyPassphrase(keyPath: keyPath, passphrase: nil) == false)
    }
    
    @Test("Get key info without decryption")
    func testGetKeyInfo() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        
        // Test with encrypted Ed25519 key
        let ed25519KeyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "info-test")
        let ed25519Key = ed25519KeyPair.privateKey
        let passphrase = "secret"
        
        let keyPath = testDirectory.appendingPathComponent("info_key").path
        let keyData = try OpenSSHPrivateKey.serialize(key: ed25519Key, passphrase: passphrase)
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        
        // Get key info
        let info = try KeyManager.getKeyInfo(keyPath: keyPath)
        
        #expect(info.keyType == .ed25519)
        #expect(info.isEncrypted == true)
        #expect(info.cipherName == "aes256-ctr")
        #expect(info.fingerprint.hasPrefix("SHA256:"))
        
        // Test with unencrypted key
        let unencryptedPath = testDirectory.appendingPathComponent("unencrypted_info_key").path
        let unencryptedData = try OpenSSHPrivateKey.serialize(key: ed25519Key)
        try unencryptedData.write(to: URL(fileURLWithPath: unencryptedPath))
        
        let unencryptedInfo = try KeyManager.getKeyInfo(keyPath: unencryptedPath)
        #expect(unencryptedInfo.isEncrypted == false)
        #expect(unencryptedInfo.cipherName == nil)
    }
}