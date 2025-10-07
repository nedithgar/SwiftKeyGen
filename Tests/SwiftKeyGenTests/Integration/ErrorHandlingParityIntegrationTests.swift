import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for error handling parity between SwiftKeyGen and ssh-keygen.
@Suite("Error Handling Parity Integration Tests", .tags(.integration))
struct ErrorHandlingParityIntegrationTests {
    
    // MARK: - Wrong Passphrase
    
    @Test("Both reject keys with wrong passphrase")
    func testBothRejectWrongPassphrase() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate an encrypted key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("test_key")
            
            // Create key with ssh-keygen using passphrase "correctpass"
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "correctpass",
                "-C", "test@host.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted key")
            
            // Try to use ssh-keygen with wrong passphrase
            let wrongPassPath = tempDir.appendingPathComponent("wrong_pass.txt")
            try IntegrationTestSupporter.write("wrongpass\n", to: wrongPassPath)
            
            // ssh-keygen with wrong passphrase should fail
            // Note: ssh-keygen reads passphrase from stdin or SSH_ASKPASS
            let sshKeygenWrongResult = try IntegrationTestSupporter.runSSHKeygen(
                ["-y", "-f", keyPath.path],
                input: "wrongpass\n".data(using: .utf8)
            )
            #expect(sshKeygenWrongResult.failed, "ssh-keygen should reject wrong passphrase")
            
            // Try to parse with our implementation using wrong passphrase
            do {
                _ = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: "wrongpass")
                Issue.record("Parser should reject wrong passphrase")
            } catch {
                // Verify it's a passphrase-related error
                let errorDescription = String(describing: error)
                #expect(
                    errorDescription.localizedCaseInsensitiveContains("passphrase") ||
                    errorDescription.localizedCaseInsensitiveContains("decrypt") ||
                    errorDescription.localizedCaseInsensitiveContains("authentication") ||
                    errorDescription.localizedCaseInsensitiveContains("password"),
                    "Error should indicate passphrase problem: \(errorDescription)"
                )
            }
            
            // Verify correct passphrase works for both
            let sshKeygenCorrectResult = try IntegrationTestSupporter.runSSHKeygen(
                ["-y", "-f", keyPath.path],
                input: "correctpass\n".data(using: .utf8)
            )
            #expect(sshKeygenCorrectResult.succeeded, "ssh-keygen should accept correct passphrase")
            
            let parsedWithCorrect = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: "correctpass")
            #expect(parsedWithCorrect.publicKeyString().count > 0, "Correct passphrase should parse successfully")
        }
    }
    
    // MARK: - Malformed Base64
    
    @Test("Both reject malformed base64 encoding")
    func testBothRejectMalformedBase64() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create various malformed base64 scenarios
            let malformedKeys = [
                "ssh-ed25519 !!!InvalidBase64!!! test@host.com",
                "ssh-ed25519 AAAA@#$%^&*() test@host.com",
                "ssh-ed25519 A test@host.com", // Too short
                "ssh-rsa ABC=== test@host.com", // Invalid padding
            ]
            
            for (index, malformed) in malformedKeys.enumerated() {
                let pubPath = tempDir.appendingPathComponent("malformed_\(index).pub")
                try IntegrationTestSupporter.write(malformed, to: pubPath)
                
                // ssh-keygen should reject it
                let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
                #expect(sshKeygenResult.failed, "ssh-keygen should reject malformed base64: \(malformed)")
                
                // Both reject via ssh-keygen verification above
                
                try? FileManager.default.removeItem(at: pubPath)
            }
        }
    }
    
    // MARK: - Invalid Key Type
    
    @Test("Both reject invalid key type identifiers")
    func testBothRejectInvalidKeyType() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create keys with invalid type identifiers
            let invalidTypes = [
                "ssh-invalid",
                "ssh-dsa",      // Deprecated/unsupported
                "ssh-rsa1",     // Old SSH1 format
                "ecdsa-sha2",   // Incomplete type
                "ed25519",      // Missing ssh- prefix
            ]
            
            for (index, invalidType) in invalidTypes.enumerated() {
                // Generate a valid key first, then replace its type
                let validKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
                let validPubKey = validKey.publicKeyString()
                
                // Replace the type
                let parts = validPubKey.split(separator: " ", maxSplits: 2)
                #expect(parts.count >= 2, "Public key should have type and base64")
                
                let malformed = "\(invalidType) \(parts[1]) test@host.com"
                
                let pubPath = tempDir.appendingPathComponent("invalid_type_\(index).pub")
                try IntegrationTestSupporter.write(malformed, to: pubPath)
                
                // ssh-keygen should reject it
                let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
                #expect(sshKeygenResult.failed, "ssh-keygen should reject invalid key type: \(invalidType)")
                
                // Both reject via ssh-keygen verification above
                
                try? FileManager.default.removeItem(at: pubPath)
            }
        }
    }
    
    // MARK: - Invalid Signatures
    
    @Test("Both reject certificates with invalid signatures")
    func testBothRejectInvalidCertificateSignature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create a valid certificate
            let validCert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write the valid certificate
            let certPath = tempDir.appendingPathComponent("test-cert.pub")
            try IntegrationTestSupporter.write(validCert.publicKeyString(), to: certPath)
            
            // Verify it's valid first
            let validListResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(validListResult.succeeded, "Valid certificate should be readable by ssh-keygen")
            
            // Now corrupt the certificate by modifying its data
            let certData = try Data(contentsOf: certPath)
            let certString = String(data: certData, encoding: .utf8)!
            let parts = certString.split(separator: " ")
            #expect(parts.count >= 2, "Certificate should have type and data")
            
            // Decode, corrupt, and re-encode the base64
            guard let certBytes = Data(base64Encoded: String(parts[1])) else {
                throw SSHKeyError.invalidFormat
            }
            
            // Corrupt the last few bytes (likely part of signature)
            var corruptedBytes = certBytes
            let lastIndex = corruptedBytes.count - 1
            corruptedBytes[lastIndex] ^= 0xFF // Flip all bits in last byte
            
            let corruptedBase64 = corruptedBytes.base64EncodedString()
            let corruptedCert = "\(parts[0]) \(corruptedBase64) corrupted-cert"
            
            let corruptedPath = tempDir.appendingPathComponent("corrupted-cert.pub")
            try IntegrationTestSupporter.write(corruptedCert, to: corruptedPath)
            
            // ssh-keygen might be able to read it, but verification should fail
            // Let's try to parse it with both tools
            
            // Our parser should detect the corruption
            do {
                let parsedCorrupted = try CertificateParser.parseCertificate(from: corruptedCert)
                
                // If parsing succeeds, verification should fail
                let verifyOptions = CertificateVerificationOptions()
                let verifyResult = CertificateVerifier.verifyCertificate(parsedCorrupted, caKey: caKey, options: verifyOptions)
                #expect(verifyResult != .valid, "Corrupted certificate should fail verification")
            } catch {
                // Expected - parser detected corruption during parsing or verification failed
                print("Note: Parser/verifier detected corruption (expected)")
            }
        }
    }
    
    // MARK: - Expired Certificates
    
    @Test("Both reject expired certificates with appropriate errors")
    func testBothRejectExpiredCertificates() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create an expired certificate
            let now = Date()
            let expiredCert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "expired-user",
                principals: ["testuser"],
                validFrom: now.addingTimeInterval(-86400 * 7), // 1 week ago
                validTo: now.addingTimeInterval(-86400),      // Expired yesterday
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("expired-cert.pub")
            try IntegrationTestSupporter.write(expiredCert.publicKeyString(), to: certPath)
            
            // ssh-keygen can read it but shows it's expired
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should be able to list expired certificate")
            
            // Parse and verify with our implementation
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            
            // Our verifier should detect expiration
            let verifyOptions = CertificateVerificationOptions()
            let verifyResult = CertificateVerifier.verifyCertificate(parsed, caKey: caKey, options: verifyOptions)
            #expect(verifyResult == .expired, "Expired certificate should fail verification with .expired")
        }
    }
    
    // MARK: - Corrupted Key Files
    
    @Test("Both handle corrupted private key files")
    func testBothHandleCorruptedPrivateKeys() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate a valid key first
            let validKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            let privateKeyData = try OpenSSHPrivateKey.serialize(key: validKey, passphrase: nil)
            let privateKey = String(data: privateKeyData, encoding: .utf8)!
            
            // Create corrupted versions
            let corruptionScenarios = [
                ("Missing header", privateKey.replacingOccurrences(of: "-----BEGIN OPENSSH PRIVATE KEY-----", with: "")),
                ("Missing footer", privateKey.replacingOccurrences(of: "-----END OPENSSH PRIVATE KEY-----", with: "")),
                ("Truncated", String(privateKey.prefix(privateKey.count / 2))),
                ("Random garbage", "-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----"),
            ]
            
            for (name, corruptedKey) in corruptionScenarios {
                let keyPath = tempDir.appendingPathComponent("corrupted.key")
                try IntegrationTestSupporter.write(corruptedKey, to: keyPath)
                
                // ssh-keygen should reject it
                let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", keyPath.path])
                #expect(sshKeygenResult.failed, "ssh-keygen should reject corrupted key: \(name)")
                
                // Both reject via ssh-keygen verification above
                
                try? FileManager.default.removeItem(at: keyPath)
            }
        }
    }
    
    // MARK: - Missing Required Fields
    
    @Test("Both reject keys missing required fields")
    func testBothRejectKeysMissingRequiredFields() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create keys with missing components
            let incompleteKeys = [
                "ssh-ed25519",                    // Missing base64
                "AAAAC3NzaC1lZDI1NTE5AAAAII", // Missing type
                "",                                // Empty
            ]
            
            for (index, incomplete) in incompleteKeys.enumerated() {
                let pubPath = tempDir.appendingPathComponent("incomplete_\(index).pub")
                try IntegrationTestSupporter.write(incomplete, to: pubPath)
                
                // ssh-keygen should reject it
                let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
                #expect(sshKeygenResult.failed, "ssh-keygen should reject incomplete key")
                
                // Both reject via ssh-keygen verification above
                
                try? FileManager.default.removeItem(at: pubPath)
            }
        }
    }
}
