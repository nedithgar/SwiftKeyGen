import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("OpenSSH Format Integration Tests", .tags(.integration))
struct OpenSSHFormatIntegrationTests {
    
    // MARK: - Parse ssh-keygen Generated Keys (Unencrypted)
    
    @Test("Parse ssh-keygen Ed25519 key (unencrypted)")
    func testParseSSHKeygenEd25519Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            
            // Generate key with ssh-keygen
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",  // No passphrase
                "-C", "test-ed25519@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate Ed25519 key")
            
            // Parse with our implementation
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            
            // Verify key type
            #expect(key is Ed25519Key, "Parsed key should be Ed25519Key")
            
            // Verify we can extract public key
            let publicKey = key.publicKeyString()
            #expect(publicKey.contains("ssh-ed25519"), "Public key should be Ed25519 format")
            #expect(publicKey.contains("test-ed25519@example.com"), "Comment should be preserved")
            
            // Verify public key matches ssh-keygen's
            let sshPubPath = tempDir.appendingPathComponent("id_ed25519.pub")
            let sshPublicKey = try String(contentsOf: sshPubPath, encoding: .utf8)
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(publicKey)
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(sshPublicKey)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("Parse ssh-keygen RSA 2048 key (unencrypted)")
    func testParseSSHKeygenRSA2048Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            
            // Generate key with ssh-keygen
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",  // No passphrase
                "-C", "test-rsa2048@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate RSA 2048 key")
            
            // Parse with our implementation
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            
            // Verify key type
            #expect(key is RSAKey, "Parsed key should be RSAKey")
            
            // Verify public key
            let publicKey = key.publicKeyString()
            #expect(publicKey.contains("ssh-rsa"), "Public key should be RSA format")
            #expect(publicKey.contains("test-rsa2048@example.com"), "Comment should be preserved")
            
            // Verify public key matches ssh-keygen's
            let sshPubPath = tempDir.appendingPathComponent("id_rsa.pub")
            let sshPublicKey = try String(contentsOf: sshPubPath, encoding: .utf8)
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(publicKey)
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(sshPublicKey)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("Parse ssh-keygen RSA 3072 key (unencrypted)", .tags(.slow))
    func testParseSSHKeygenRSA3072Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "3072",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test-rsa3072@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate RSA 3072 key")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            #expect(key is RSAKey, "Parsed key should be RSAKey")
        }
    }
    
    @Test("Parse ssh-keygen RSA 4096 key (unencrypted)", .tags(.slow))
    func testParseSSHKeygenRSA4096Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "4096",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test-rsa4096@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate RSA 4096 key")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            #expect(key is RSAKey, "Parsed key should be RSAKey")
        }
    }
    
    @Test("Parse ssh-keygen ECDSA P-256 key (unencrypted)")
    func testParseSSHKeygenECDSAP256Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test-ecdsa256@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA P-256 key")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            #expect(key is ECDSAKey, "Parsed key should be ECDSAKey")
            
            let publicKey = key.publicKeyString()
            #expect(publicKey.contains("ecdsa-sha2-nistp256"), "Public key should be ECDSA P-256 format")
        }
    }
    
    @Test("Parse ssh-keygen ECDSA P-384 key (unencrypted)")
    func testParseSSHKeygenECDSAP384Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "384",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test-ecdsa384@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA P-384 key")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            #expect(key is ECDSAKey, "Parsed key should be ECDSAKey")
            
            let publicKey = key.publicKeyString()
            #expect(publicKey.contains("ecdsa-sha2-nistp384"), "Public key should be ECDSA P-384 format")
        }
    }
    
    @Test("Parse ssh-keygen ECDSA P-521 key (unencrypted)")
    func testParseSSHKeygenECDSAP521Unencrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "521",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test-ecdsa521@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA P-521 key")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            #expect(key is ECDSAKey, "Parsed key should be ECDSAKey")
            
            let publicKey = key.publicKeyString()
            #expect(publicKey.contains("ecdsa-sha2-nistp521"), "Public key should be ECDSA P-521 format")
        }
    }
    
    // MARK: - Parse ssh-keygen Generated Keys (Encrypted)
    
    @Test("Parse ssh-keygen Ed25519 key (encrypted)", .tags(.slow))
    func testParseSSHKeygenEd25519Encrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let passphrase = "test-passphrase-ed25519"
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", passphrase,
                "-C", "encrypted-ed25519@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted Ed25519 key")
            
            // Verify we can't read without passphrase
            #expect(throws: Error.self) {
                try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            }
            
            // Parse with correct passphrase
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: passphrase)
            #expect(key is Ed25519Key, "Parsed key should be Ed25519Key")
            
            // Verify public key matches
            let sshPubPath = tempDir.appendingPathComponent("id_ed25519.pub")
            let sshPublicKey = try String(contentsOf: sshPubPath, encoding: .utf8)
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(sshPublicKey)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("Parse ssh-keygen RSA key (encrypted)", .tags(.rsa, .slow))
    func testParseSSHKeygenRSAEncrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let passphrase = "test-passphrase-rsa"
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", passphrase,
                "-C", "encrypted-rsa@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted RSA key")
            
            // Parse with correct passphrase
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: passphrase)
            #expect(key is RSAKey, "Parsed key should be RSAKey")
            
            // Verify public key matches
            let sshPubPath = tempDir.appendingPathComponent("id_rsa.pub")
            let sshPublicKey = try String(contentsOf: sshPubPath, encoding: .utf8)
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(sshPublicKey)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("Parse ssh-keygen ECDSA key (encrypted)", .tags(.slow))
    func testParseSSHKeygenECDSAEncrypted() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            let passphrase = "test-passphrase-ecdsa"
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", keyPath.path,
                "-N", passphrase,
                "-C", "encrypted-ecdsa@example.com"
            ])
            
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted ECDSA key")
            
            // Parse with correct passphrase
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: passphrase)
            #expect(key is ECDSAKey, "Parsed key should be ECDSAKey")
            
            // Verify public key matches
            let sshPubPath = tempDir.appendingPathComponent("id_ecdsa.pub")
            let sshPublicKey = try String(contentsOf: sshPubPath, encoding: .utf8)
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(sshPublicKey)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    // MARK: - ssh-keygen Reads Our OpenSSH Format
    
    @Test("ssh-keygen extracts public key from our Ed25519 OpenSSH format")
    func testSSHKeygenReadsOurEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with our implementation
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "our-ed25519@example.com") as! Ed25519Key
            
            // Write in OpenSSH format
            let keyPath = tempDir.appendingPathComponent("our_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Extract public key with ssh-keygen
            let result = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", keyPath.path
            ])
            
            #expect(result.succeeded, "ssh-keygen should extract public key from our OpenSSH format")
            #expect(result.stdout.contains("ssh-ed25519"), "Output should contain Ed25519 public key")
            
            // Compare public keys
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }

    @Test("ssh-keygen extracts public key from our RSA OpenSSH format", .tags(.rsa, .slow))
    func testSSHKeygenReadsOurRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with our implementation
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "our-rsa@example.com") as! RSAKey
            
            // Write in OpenSSH format
            let keyPath = tempDir.appendingPathComponent("our_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Extract public key with ssh-keygen
            let result = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", keyPath.path
            ])
            
            #expect(result.succeeded, "ssh-keygen should extract public key from our OpenSSH format")
            #expect(result.stdout.contains("ssh-rsa"), "Output should contain RSA public key")
            
            // Compare public keys
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("ssh-keygen extracts public key from our ECDSA OpenSSH format")
    func testSSHKeygenReadsOurECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Test all ECDSA curves
            let curves: [(KeyType, String)] = [
                (.ecdsa256, "nistp256"),
                (.ecdsa384, "nistp384"),
                (.ecdsa521, "nistp521")
            ]
            
            for (keyType, curveName) in curves {
                let key = try SwiftKeyGen.generateKey(type: keyType, comment: "our-ecdsa-\(curveName)@example.com") as! ECDSAKey
                
                let keyPath = tempDir.appendingPathComponent("our_key_\(curveName)")
                let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
                try IntegrationTestSupporter.write(keyData, to: keyPath)
                
                let result = try IntegrationTestSupporter.runSSHKeygen([
                    "-y", "-f", keyPath.path
                ])
                
                #expect(result.succeeded, "ssh-keygen should extract public key from our ECDSA \(curveName) OpenSSH format")
                #expect(result.stdout.contains("ecdsa-sha2-\(curveName)"), "Output should contain ECDSA \(curveName) public key")
                
                let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
                let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
                #expect(ourNormalized == theirNormalized, "Public keys should match for \(curveName)")
            }
        }
    }
    
    @Test("ssh-keygen decrypts our encrypted OpenSSH format Ed25519", .tags(.slow))
    func testSSHKeygenDecryptsOurEncryptedEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "encrypted-our-ed25519@example.com") as! Ed25519Key
            let passphrase = "our-secret-passphrase"
            
            let keyPath = tempDir.appendingPathComponent("our_encrypted_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            // Extract public key with ssh-keygen (providing passphrase)
            let result = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", keyPath.path, "-P", passphrase
            ])
            
            #expect(result.succeeded, "ssh-keygen should decrypt our encrypted OpenSSH format")
            #expect(result.stdout.contains("ssh-ed25519"), "Output should contain Ed25519 public key")
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    @Test("ssh-keygen decrypts our encrypted OpenSSH format RSA", .tags(.rsa, .slow))
    func testSSHKeygenDecryptsOurEncryptedRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "encrypted-our-rsa@example.com") as! RSAKey
            let passphrase = "our-secret-passphrase-rsa"
            
            let keyPath = tempDir.appendingPathComponent("our_encrypted_key")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: passphrase)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            
            let result = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", keyPath.path, "-P", passphrase
            ])
            
            #expect(result.succeeded, "ssh-keygen should decrypt our encrypted RSA OpenSSH format")
            #expect(result.stdout.contains("ssh-rsa"), "Output should contain RSA public key")
            
            let ourNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(key.publicKeyString())
            let theirNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
            #expect(ourNormalized == theirNormalized, "Public keys should match")
        }
    }
    
    // MARK: - Round-Trip Tests
    
    @Test("Round-trip Ed25519: ssh-keygen → us → export → ssh-keygen")
    func testRoundTripEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate with ssh-keygen
            let originalPath = tempDir.appendingPathComponent("original")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", originalPath.path,
                "-N", "",
                "-C", "roundtrip@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Parse with us
            let key = try KeyManager.readPrivateKey(from: originalPath.path, passphrase: nil)
            
            // Export with us
            let exportPath = tempDir.appendingPathComponent("exported")
            let exportData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(exportData, to: exportPath)
            
            // Verify ssh-keygen can read our export
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", exportPath.path
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read our exported key")
            
            // Compare all three public keys
            let originalPubPath = tempDir.appendingPathComponent("original.pub")
            let originalPub = try String(contentsOf: originalPubPath, encoding: .utf8)
            let ourPub = key.publicKeyString()
            let extractedPub = extractResult.stdout
            
            let originalNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourPub)
            let extractedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractedPub)
            
            #expect(originalNorm == ourNorm, "Our parsed public key should match original")
            #expect(ourNorm == extractedNorm, "ssh-keygen extracted public key should match ours")
        }
    }
    
    @Test("Round-trip ECDSA P-256: ssh-keygen → us → export → ssh-keygen")
    func testRoundTripECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let originalPath = tempDir.appendingPathComponent("original")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", originalPath.path,
                "-N", "",
                "-C", "roundtrip-ecdsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            let key = try KeyManager.readPrivateKey(from: originalPath.path, passphrase: nil)
            
            let exportPath = tempDir.appendingPathComponent("exported")
            let exportData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(exportData, to: exportPath)
            
            let extractResult = try IntegrationTestSupporter.runSSHKeygen([
                "-y", "-f", exportPath.path
            ])
            #expect(extractResult.succeeded, "ssh-keygen should read our exported ECDSA key")
            
            let originalPubPath = tempDir.appendingPathComponent("original.pub")
            let originalPub = try String(contentsOf: originalPubPath, encoding: .utf8)
            let ourPub = key.publicKeyString()
            let extractedPub = extractResult.stdout
            
            let originalNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourPub)
            let extractedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(extractedPub)
            
            #expect(originalNorm == ourNorm, "Our parsed public key should match original")
            #expect(ourNorm == extractedNorm, "ssh-keygen extracted public key should match ours")
        }
    }
}
