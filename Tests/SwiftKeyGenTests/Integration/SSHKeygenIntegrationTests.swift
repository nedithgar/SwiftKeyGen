import Testing
@testable import SwiftKeyGen
import Foundation

@Test("ssh-keygen compatibility - decrypt our encrypted PEM", .tags(.integration))
func testSSHKeygenCanDecryptOurPEM() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        // Generate a test key
        let key = try ECDSAKeyGenerator.generateP256(comment: "integration-test")
        let passphrase = "test123"
        
        // Export our encrypted PEM
        let ourKeyPath = tempDir.appendingPathComponent("our_key.pem")
        let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
        try IntegrationTestSupporter.write(encryptedPEM, to: ourKeyPath)
        
        // Use ssh-keygen to extract public key from our encrypted private key
        // This verifies ssh-keygen can decrypt and read our format
        let result = try IntegrationTestSupporter.runSSHKeygen([
            "-f", ourKeyPath.path,
            "-y",  // Extract public key
            "-P", passphrase  // Provide passphrase
        ])
        
        // Check exit status
        #expect(result.succeeded, "ssh-keygen should successfully decrypt our PEM file")
        
        // Verify output contains valid public key
        #expect(result.stdout.contains("ecdsa-sha2-nistp256"), "Output should contain ECDSA public key")
    }
}

@Test("ssh-keygen compatibility - decrypt our encrypted PKCS8", .tags(.integration))
func testSSHKeygenCanDecryptOurPKCS8() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        // Generate a test key
        let key = try ECDSAKeyGenerator.generateP384(comment: "pkcs8-test")
        let passphrase = "secret456"
        
        // Export our encrypted PKCS8
        let ourKeyPath = tempDir.appendingPathComponent("our_key.p8")
        let encryptedPKCS8 = try key.pkcs8PEMRepresentation(passphrase: passphrase)
        try IntegrationTestSupporter.write(encryptedPKCS8, to: ourKeyPath)
        
        // Use ssh-keygen to extract public key from our encrypted private key
        let result = try IntegrationTestSupporter.runSSHKeygen([
            "-f", ourKeyPath.path,
            "-y",  // Extract public key
            "-P", passphrase  // Provide passphrase
        ])
        
        // Check exit status
        #expect(result.succeeded, "ssh-keygen should successfully decrypt our PKCS8 file")
        
        // Verify output contains valid public key
        #expect(result.stdout.contains("ecdsa-sha2-nistp384"), "Output should contain ECDSA P-384 public key")
    }
}

@Test("Compare key formats with ssh-keygen", .tags(.integration))
func testCompareFormatsWithSSHKeygen() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        // Generate a key with ssh-keygen
        let sshKeyPath = tempDir.appendingPathComponent("ssh_key")
        let passphrase = "compare123"
        
        // Generate ECDSA key with ssh-keygen
        let genResult = try IntegrationTestSupporter.runSSHKeygen([
            "-t", "ecdsa",
            "-b", "256",
            "-f", sshKeyPath.path,
            "-N", passphrase,  // Passphrase
            "-C", "ssh-keygen-test"
        ], input: "y\n".data(using: .utf8))  // Overwrite if exists
        
        #expect(genResult.succeeded, "ssh-keygen should generate key successfully")
        
        // Create a copy of the key for PEM conversion
        let pemKeyPath = tempDir.appendingPathComponent("ssh_key.pem")
        try FileManager.default.copyItem(at: sshKeyPath, to: pemKeyPath)
        
        // Apply PEM conversion on the copy
        let pemResult = try IntegrationTestSupporter.runSSHKeygen([
            "-p",  // Change passphrase/format
            "-f", pemKeyPath.path,
            "-m", "PEM",
            "-P", passphrase,  // Old passphrase
            "-N", passphrase   // New passphrase (same)
        ])
        
        #expect(pemResult.succeeded, "ssh-keygen should convert to PEM format")
        
        // Read the PEM file and verify structure
        let pemContent = try String(contentsOf: pemKeyPath, encoding: .utf8)
        #expect(pemContent.contains("BEGIN EC PRIVATE KEY"), "ssh-keygen PEM should be SEC1 format")
        #expect(pemContent.contains("Proc-Type: 4,ENCRYPTED"), "ssh-keygen PEM should be encrypted")
        #expect(pemContent.contains("DEK-Info:"), "ssh-keygen PEM should have DEK-Info header")
        
        // Create a copy of the key for PKCS8 conversion
        let pkcs8KeyPath = tempDir.appendingPathComponent("ssh_key.pkcs8")
        try FileManager.default.copyItem(at: sshKeyPath, to: pkcs8KeyPath)
        
        // Apply PKCS8 conversion on the copy
        let pkcs8Result = try IntegrationTestSupporter.runSSHKeygen([
            "-p",  // Change passphrase/format
            "-f", pkcs8KeyPath.path,
            "-m", "PKCS8",
            "-P", passphrase,  // Old passphrase
            "-N", passphrase   // New passphrase (same)
        ])
        
        #expect(pkcs8Result.succeeded, "ssh-keygen should convert to PKCS8 format")
        
        // Read the PKCS8 file and verify structure
        let pkcs8Content = try String(contentsOf: pkcs8KeyPath, encoding: .utf8)
        #expect(pkcs8Content.contains("BEGIN ENCRYPTED PRIVATE KEY"), "ssh-keygen PKCS8 should be encrypted")
        #expect(!pkcs8Content.contains("Proc-Type"), "PKCS8 should not have PEM encryption headers")
    }
}

@Test("Test different cipher support", .tags(.integration))
func testDifferentCipherCompatibility() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        let key = try ECDSAKeyGenerator.generateP521(comment: "cipher-test")
        let passphrase = "cipherpass"
        
        // Test each cipher
        for cipher in PEMEncryption.PEMCipher.allCases {
            let keyPath = tempDir.appendingPathComponent("cipher_\(cipher.rawValue).pem")
            
            // Export with specific cipher
            let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase, cipher: cipher)
            try IntegrationTestSupporter.write(encryptedPEM, to: keyPath)
            
            // Verify ssh-keygen can decrypt
            let result = try IntegrationTestSupporter.runSSHKeygen([
                "-f", keyPath.path,
                "-y",  // Extract public key
                "-P", passphrase
            ])
            
            #expect(result.succeeded, "ssh-keygen should decrypt \(cipher.rawValue)")
        }
    }
}

@Test("Verify public key consistency", .tags(.integration))
func testPublicKeyConsistency() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        // Generate key with our implementation
        let key = try ECDSAKeyGenerator.generateP256(comment: "consistency-test")
        let passphrase = "consistent"
        
        // Get our public key in OpenSSH format
        let ourPublicKey = key.publicKeyString()
        
        // Export encrypted PEM
        let pemPath = tempDir.appendingPathComponent("key.pem")
        let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
        try IntegrationTestSupporter.write(encryptedPEM, to: pemPath)
        
        // Extract public key using ssh-keygen
        let result = try IntegrationTestSupporter.runSSHKeygen([
            "-f", pemPath.path,
            "-y",
            "-P", passphrase
        ])
        
        #expect(result.succeeded, "ssh-keygen should extract public key successfully")
        
        // Compare public keys (ignoring comment which might differ)
        let ourKeyNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourPublicKey)
        let sshKeyNormalized = IntegrationTestSupporter.normalizeOpenSSHPublicKey(result.stdout)
        
        #expect(ourKeyNormalized == sshKeyNormalized, "Public keys should match")
    }
}
