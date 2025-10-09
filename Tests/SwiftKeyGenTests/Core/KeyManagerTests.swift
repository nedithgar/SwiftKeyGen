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
        let publicKeyContent = try String(contentsOf: URL(fileURLWithPath: publicKeyPath), encoding: .utf8)
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

    // MARK: - Additional Coverage

    @Test("Parse Ed25519 PKCS#8 (unencrypted) via KeyManager")
    func testParseEd25519PKCS8Unencrypted() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }

        // Generate Ed25519 key and export as PKCS#8 (unencrypted)
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "pkcs8-ed25519@example.com")
        let key = keyPair.privateKey as! Ed25519Key
        let pkcs8Data = try KeyConverter.toPKCS8(key: key) // returns PEM formatted data
        let pkcs8Path = testDirectory.appendingPathComponent("ed25519_pkcs8").path
        try pkcs8Data.write(to: URL(fileURLWithPath: pkcs8Path))

        // Read through KeyManager (exercise PKCS#8 detection fast path)
        let parsed = try KeyManager.readPrivateKey(from: pkcs8Path)
        #expect(parsed.keyType == .ed25519)
        // PKCS#8 unencrypted path currently discards comment; ensure either nil or original
        #expect(parsed.comment == nil || parsed.comment == "pkcs8-ed25519@example.com")
        // Public key string may omit comment; match prefix and key material
        let originalNoComment = key.publicKeyString().components(separatedBy: " ").prefix(2).joined(separator: " ")
        let parsedNoComment = parsed.publicKeyString().components(separatedBy: " ").prefix(2).joined(separator: " ")
        #expect(parsedNoComment == originalNoComment)
    }

    @Test("Parse RSA PKCS#1 (traditional PEM) via KeyManager")
    func testParseRSAPKCS1ViaKeyManager() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }

        // Generate a small RSA key (1024 bits to keep runtime small)
        let rsa = try SwiftKeyGen.generateKey(type: .rsa, bits: 1024, comment: "rsa-pkcs1") as! RSAKey
        let der = rsa.privateKeyData()
        let base64 = der.base64EncodedString().wrapped(every: 64) + "\n"
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n" + base64 + "-----END RSA PRIVATE KEY-----\n"
        let path = testDirectory.appendingPathComponent("rsa_pkcs1").path
        try pem.write(toFile: path, atomically: true, encoding: .utf8)

        let parsed = try KeyManager.readPrivateKey(from: path)
        #expect(parsed.keyType == .rsa)
        // Comments may be dropped during PKCS#1 parsing; compare key material only
        let rsaOriginalNoComment = rsa.publicKeyString().components(separatedBy: " ").prefix(2).joined(separator: " ")
        let rsaParsedNoComment = parsed.publicKeyString().components(separatedBy: " ").prefix(2).joined(separator: " ")
        #expect(rsaParsedNoComment == rsaOriginalNoComment)
    }

    @Test("Update comment on encrypted key and sync .pub")
    func testUpdateCommentOnEncryptedKey() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }

        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "enc-old")
        let pass = "change-me"
        let keyData = try OpenSSHPrivateKey.serialize(key: pair.privateKey, passphrase: pass)
        let keyPath = testDirectory.appendingPathComponent("encrypted_comment").path
        let pubPath = keyPath + ".pub"
        try keyData.write(to: URL(fileURLWithPath: keyPath))
        try pair.publicKeyString.write(toFile: pubPath, atomically: true, encoding: .utf8)

        let newComment = "enc-new@example.com"
        try KeyManager.updateComment(keyPath: keyPath, passphrase: pass, newComment: newComment)

        // Reading with correct passphrase should show new comment
        let updated = try KeyManager.readPrivateKey(from: keyPath, passphrase: pass)
        #expect(updated.comment == newComment)
        // Public key file updated
        let pubContents = try String(contentsOfFile: pubPath, encoding: .utf8)
        #expect(pubContents.hasSuffix(" " + newComment + "\n") || pubContents.hasSuffix(" " + newComment))
    }

    @Test("getKeyInfo invalid format errors")
    func testGetKeyInfoInvalidErrors() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }

        // Case 1: Not a PEM at all
        let randomPath = testDirectory.appendingPathComponent("random.bin").path
        try Data([0x01, 0x02, 0x03]).write(to: URL(fileURLWithPath: randomPath))
        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try KeyManager.getKeyInfo(keyPath: randomPath)
        }

        // Case 2: PEM but not OpenSSH private key
        let bogus = "-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n"
        let bogusPath = testDirectory.appendingPathComponent("bogus.pem").path
        try bogus.write(toFile: bogusPath, atomically: true, encoding: .utf8)
        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try KeyManager.getKeyInfo(keyPath: bogusPath)
        }
    }

    @Test("verifyPassphrase on unencrypted key path")
    func testVerifyPassphraseUnencryptedKey() throws {
        let testDirectory = try makeTestDirectory()
        defer { try? FileManager.default.removeItem(at: testDirectory) }
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        let keyData = try OpenSSHPrivateKey.serialize(key: pair.privateKey)
        let path = testDirectory.appendingPathComponent("plain_key").path
        try keyData.write(to: URL(fileURLWithPath: path))

        // Should succeed with nil passphrase
        #expect(KeyManager.verifyPassphrase(keyPath: path, passphrase: nil))
        // Passing an arbitrary passphrase for an unencrypted key should still succeed
        #expect(KeyManager.verifyPassphrase(keyPath: path, passphrase: "anything"))
    }
}