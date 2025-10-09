import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("Passphrase Integration Tests", .tags(.integration))
struct PassphraseIntegrationTests {
    
    // MARK: - ssh-keygen Modifies Our Keys
    
    @Test("ssh-keygen changes passphrase on our OpenSSH Ed25519 key")
    func testSSHKeygenChangesPassphraseOnOurEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with our implementation (with initial passphrase)
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "passphrase-change@example.com") as! Ed25519Key
            let oldPassphrase = "old-secret"
            let newPassphrase = "new-secret"
            
            let keyPath = tempDir.appendingPathComponent("our_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Change passphrase with ssh-keygen
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-P", oldPassphrase,  // Old passphrase
                "-N", newPassphrase   // New passphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our key")
            
            // Verify we can read with new passphrase
            let keyWithNewPass = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: newPassphrase)
            
            // Verify public key is unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(keyWithNewPass.publicKeyString())
            #expect(ourNorm == newNorm, "Public key should be unchanged after passphrase change")
            
            // Verify old passphrase no longer works
            #expect(throws: Error.self) {
                try KeyManager.readPrivateKey(from: keyPath.path, passphrase: oldPassphrase)
            }
        }
    }
    
    @Test("ssh-keygen removes passphrase from our OpenSSH Ed25519 key")
    func testSSHKeygenRemovesPassphraseFromOurKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "passphrase-remove@example.com") as! Ed25519Key
            let passphrase = "remove-me"
            
            let keyPath = tempDir.appendingPathComponent("our_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Remove passphrase with ssh-keygen
            let removeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-P", passphrase,  // Old passphrase
                "-N", ""          // Empty = no passphrase
            ])
            #expect(removeResult.succeeded, "ssh-keygen should remove passphrase from our key")
            
            // Verify we can read without passphrase
            let keyWithoutPass = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            
            // Verify public key is unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(keyWithoutPass.publicKeyString())
            #expect(ourNorm == newNorm, "Public key should be unchanged after removing passphrase")
        }
    }
    
    @Test("ssh-keygen adds passphrase to our unencrypted OpenSSH key")
    func testSSHKeygenAddsPassphraseToOurKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "passphrase-add@example.com") as! Ed25519Key
            let newPassphrase = "newly-added"
            
            // Write unencrypted key
            let keyPath = tempDir.appendingPathComponent("our_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Add passphrase with ssh-keygen
            let addResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-P", "",            // Old passphrase (empty)
                "-N", newPassphrase  // New passphrase
            ])
            #expect(addResult.succeeded, "ssh-keygen should add passphrase to our unencrypted key")
            
            // Verify we need passphrase to read
            #expect(throws: Error.self) {
                try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            }
            
            // Verify we can read with new passphrase
            let keyWithPass = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: newPassphrase)
            
            // Verify public key is unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(keyWithPass.publicKeyString())
            #expect(ourNorm == newNorm, "Public key should be unchanged after adding passphrase")
        }
    }
    
    @Test("ssh-keygen changes passphrase on our OpenSSH RSA key", .tags(.rsa))
    func testSSHKeygenChangesPassphraseOnOurRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-passphrase@example.com") as! RSAKey
            let oldPassphrase = "old-rsa-secret"
            let newPassphrase = "new-rsa-secret"
            
            let keyPath = tempDir.appendingPathComponent("our_rsa_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-P", oldPassphrase,
                "-N", newPassphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our RSA key")
            
            let keyWithNewPass = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: newPassphrase)
            
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(keyWithNewPass.publicKeyString())
            #expect(ourNorm == newNorm, "RSA public key should be unchanged")
        }
    }
    
    @Test("ssh-keygen changes passphrase on our OpenSSH ECDSA key")
    func testSSHKeygenChangesPassphraseOnOurECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-passphrase@example.com") as! ECDSAKey
            let oldPassphrase = "old-ecdsa-secret"
            let newPassphrase = "new-ecdsa-secret"
            
            let keyPath = tempDir.appendingPathComponent("our_ecdsa_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-P", oldPassphrase,
                "-N", newPassphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our ECDSA key")
            
            let keyWithNewPass = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: newPassphrase)
            
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(keyWithNewPass.publicKeyString())
            #expect(ourNorm == newNorm, "ECDSA public key should be unchanged")
        }
    }
    
    // MARK: - We Modify ssh-keygen Keys
    
    @Test("We change passphrase on ssh-keygen Ed25519 key")
    func testWeChangePassphraseOnSSHKeygenKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("ssh_key")
            let oldPassphrase = "ssh-old-pass"
            let newPassphrase = "our-new-pass"
            
            // Generate with ssh-keygen
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", oldPassphrase,
                "-C", "we-change-pass@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted key")
            
            // Read original public key
            let pubPath = tempDir.appendingPathComponent("ssh_key.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            // Change passphrase with our implementation
            try KeyManager.changePassphrase(
                keyPath: keyPath.path,
                oldPassphrase: oldPassphrase,
                newPassphrase: newPassphrase
            )
            
            // Verify ssh-keygen can read with new passphrase
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", newPassphrase
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read key with our new passphrase")
            
            // Verify public key is unchanged
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(origNorm == newNorm, "Public key should be unchanged")
        }
    }
    
    @Test("We remove passphrase from ssh-keygen key")
    func testWeRemovePassphraseFromSSHKeygenKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("ssh_key")
            let passphrase = "remove-this"
            
            // Generate with ssh-keygen
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", passphrase,
                "-C", "we-remove-pass@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted key")
            
            let pubPath = tempDir.appendingPathComponent("ssh_key.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            // Remove passphrase with our implementation
            try KeyManager.removePassphrase(
                keyPath: keyPath.path,
                currentPassphrase: passphrase
            )
            
            // Verify ssh-keygen can read without passphrase
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read key without passphrase")
            
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(origNorm == newNorm, "Public key should be unchanged")
        }
    }
    
    @Test("We change passphrase on ssh-keygen RSA key", .tags(.rsa))
    func testWeChangePassphraseOnSSHKeygenRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("ssh_rsa_key")
            let oldPassphrase = "ssh-rsa-old"
            let newPassphrase = "our-rsa-new"
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", oldPassphrase,
                "-C", "we-change-rsa-pass@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let pubPath = tempDir.appendingPathComponent("ssh_rsa_key.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            try KeyManager.changePassphrase(
                keyPath: keyPath.path,
                oldPassphrase: oldPassphrase,
                newPassphrase: newPassphrase
            )
            
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", newPassphrase
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read RSA key with our new passphrase")
            
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(origNorm == newNorm, "RSA public key should be unchanged")
        }
    }
    
    // MARK: - Passphrase Integrity Tests
    
    @Test("Passphrase change preserves key integrity")
    func testPassphraseChangePreservesIntegrity() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key and sign a message
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "integrity@example.com") as! Ed25519Key
            let message = "test message for signing".data(using: .utf8)!
            let signature = try key.sign(data: message)
            
            let keyPath = tempDir.appendingPathComponent("key")
            let oldPass = "old-integrity"
            let newPass = "new-integrity"
            
            // Save with passphrase
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: oldPass)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Change passphrase multiple times
            try KeyManager.changePassphrase(keyPath: keyPath.path, oldPassphrase: oldPass, newPassphrase: newPass)
            try KeyManager.changePassphrase(keyPath: keyPath.path, oldPassphrase: newPass, newPassphrase: oldPass)
            try KeyManager.changePassphrase(keyPath: keyPath.path, oldPassphrase: oldPass, newPassphrase: newPass)
            
            // Read key and verify signature still works
            let restoredKey = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: newPass) as! Ed25519Key
            
            let isValid = try restoredKey.verify(signature: signature, for: message)
            #expect(isValid, "Signature should still be valid after multiple passphrase changes")
            
            // Public keys should match exactly
            let origPub = key.publicKeyString()
            let restoredPub = restoredKey.publicKeyString()
            
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(origPub)
            let restoredNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(restoredPub)
            #expect(origNorm == restoredNorm, "Public keys should match exactly")
        }
    }
    
    @Test("Wrong passphrase fails consistently")
    func testWrongPassphraseFails() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "wrong-pass@example.com") as! Ed25519Key
            let correctPass = "correct-password"
            let wrongPass = "wrong-password"
            
            let keyPath = tempDir.appendingPathComponent("key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: correctPass)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Our implementation should reject wrong passphrase
            #expect(throws: Error.self) {
                try KeyManager.readPrivateKey(from: keyPath.path, passphrase: wrongPass)
            }
            
            // ssh-keygen should also reject wrong passphrase
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", wrongPass
            ])
            #expect(sshResult.failed, "ssh-keygen should reject wrong passphrase")
            
            // Correct passphrase should work for both
            _ = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: correctPass)
            
            let sshCorrectResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", correctPass
            ])
            #expect(sshCorrectResult.succeeded, "ssh-keygen should read key with correct passphrase")
        }
    }
    
    @Test("Empty passphrase is distinct from no passphrase")
    func testEmptyPassphraseHandling() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "empty-pass@example.com") as! Ed25519Key
            
            // Key with no encryption
            let unencryptedPath = tempDir.appendingPathComponent("unencrypted")
            let unencryptedData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(unencryptedData, to: unencryptedPath)
            
            // Key with empty string passphrase (should still be encrypted with empty passphrase)
            let emptyPassPath = tempDir.appendingPathComponent("empty_pass")
            let emptyPassData = try OpenSSHPrivateKey.serialize(key: key, passphrase: "")
            try IntegrationTestSupporter.write(emptyPassData, to: emptyPassPath)
            
            // Unencrypted should be readable without passphrase
            let unencryptedKey = try KeyManager.readPrivateKey(from: unencryptedPath.path, passphrase: nil)
            
            // Empty passphrase key should be readable with empty string
            let emptyPassKey = try KeyManager.readPrivateKey(from: emptyPassPath.path, passphrase: "")
            
            // Verify both have same public key
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let unencNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(unencryptedKey.publicKeyString())
            let emptyNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(emptyPassKey.publicKeyString())
            
            #expect(origNorm == unencNorm, "Unencrypted key should have same public key")
            #expect(origNorm == emptyNorm, "Empty-passphrase key should have same public key")
        }
    }
    
    // MARK: - PEM/PKCS8 Format Passphrase Operations
    
    @Test("ssh-keygen changes passphrase on our PEM key")
    func testSSHKeygenChangesPassphraseOnOurPEM() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate ECDSA key and export to SEC1 PEM with passphrase
            let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "pem-passphrase@example.com") as! ECDSAKey
            let oldPassphrase = "old-pem-secret"
            let newPassphrase = "new-pem-secret"
            
            let keyPath = tempDir.appendingPathComponent("our_key.pem")
            let pemData = try key.sec1PEMRepresentation(passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(pemData, to: keyPath)
            
            // Verify the PEM structure before passphrase change
            let originalPEM = try String(contentsOf: keyPath, encoding: .utf8)
            #expect(originalPEM.contains("BEGIN EC PRIVATE KEY"), "Should be SEC1 PEM format")
            #expect(originalPEM.contains("Proc-Type: 4,ENCRYPTED"), "Should be encrypted")
            
            // Change passphrase with ssh-keygen
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-m", "PEM",  // Keep PEM format
                "-P", oldPassphrase,
                "-N", newPassphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our PEM key")
            
            // Verify ssh-keygen can read with new passphrase
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", newPassphrase
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read PEM with new passphrase")
            
            // Verify public key is unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(ourNorm == newNorm, "Public key should be unchanged after PEM passphrase change")
            
            // Verify old passphrase no longer works
            let oldPassResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", oldPassphrase
            ])
            #expect(oldPassResult.failed, "ssh-keygen should reject old passphrase")
        }
    }

    @Test("ssh-keygen changes passphrase on our PKCS8 key")
    func testSSHKeygenChangesPassphraseOnOurPKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate ECDSA key and export to PKCS8 with passphrase
            // Note: Previously commented that RSA encrypted PKCS#8 was "not supported" –
            // that referred to missing convenience API. We now implement RSA PKCS#8
            // encryption internally; see `RSA+PKCS8.swift`.
            let key = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "pkcs8-passphrase@example.com") as! ECDSAKey
            let oldPassphrase = "old-pkcs8-secret"
            let newPassphrase = "new-pkcs8-secret"
            
            let keyPath = tempDir.appendingPathComponent("our_key.p8")
            let pkcs8Data = try key.pkcs8PEMRepresentation(passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(pkcs8Data, to: keyPath)
            
            // Verify the PKCS8 structure before passphrase change
            let originalPKCS8 = try String(contentsOf: keyPath, encoding: .utf8)
            #expect(originalPKCS8.contains("BEGIN ENCRYPTED PRIVATE KEY"), "Should be encrypted PKCS8 format")
            #expect(!originalPKCS8.contains("Proc-Type"), "PKCS8 should not have PEM-style encryption headers")
            
            // Change passphrase with ssh-keygen
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-m", "PKCS8",  // Keep PKCS8 format
                "-P", oldPassphrase,
                "-N", newPassphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our PKCS8 key")
            
            // Verify ssh-keygen can read with new passphrase
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", newPassphrase
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read PKCS8 with new passphrase")
            
            // Verify public key is unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(ourNorm == newNorm, "Public key should be unchanged after PKCS8 passphrase change")
            
            // Verify old passphrase no longer works
            let oldPassResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", oldPassphrase
            ])
            #expect(oldPassResult.failed, "ssh-keygen should reject old passphrase")
        }
    }

    @Test("ssh-keygen changes passphrase on our RSA PKCS8 key", .tags(.rsa))
    func testSSHKeygenChangesPassphraseOnOurRSAPKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate RSA key and export to PKCS8 with passphrase (encrypted)
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-pkcs8-passphrase@example.com") as! RSAKey
            let oldPassphrase = "old-rsa-pkcs8"
            let newPassphrase = "new-rsa-pkcs8"

            let keyPath = tempDir.appendingPathComponent("our_rsa_key.p8")
            let pkcs8Data = try key.pkcs8PEMRepresentation(passphrase: oldPassphrase)
            try IntegrationTestSupporter.write(pkcs8Data, to: keyPath)

            // Validate structure pre-change
            let original = try String(contentsOf: keyPath, encoding: .utf8)
            #expect(original.contains("BEGIN ENCRYPTED PRIVATE KEY"), "Should be encrypted PKCS8 format")

            // Change passphrase with ssh-keygen (retain PKCS8 format)
            let changeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-p",
                "-f", keyPath.path,
                "-m", "PKCS8",
                "-P", oldPassphrase,
                "-N", newPassphrase
            ])
            #expect(changeResult.succeeded, "ssh-keygen should change passphrase on our RSA PKCS8 key")

            // ssh-keygen should read with new passphrase
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", newPassphrase
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read RSA PKCS8 with new passphrase")

            // Public key unchanged
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let newNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractResult.stdout)
            #expect(ourNorm == newNorm, "Public key should be unchanged after RSA PKCS8 passphrase change")

            // Old passphrase rejected
            let oldPassResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y",
                "-f", keyPath.path,
                "-P", oldPassphrase
            ])
            #expect(oldPassResult.failed, "ssh-keygen should reject old RSA PKCS8 passphrase")
        }
    }
}
