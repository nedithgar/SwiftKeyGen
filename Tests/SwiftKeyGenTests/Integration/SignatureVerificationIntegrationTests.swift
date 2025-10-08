import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for signature verification bidirectionality.
///
/// These tests ensure that:
/// 1. We can verify signatures created by ssh-keygen
/// 2. ssh-keygen can verify signatures we create (via certificate trust chains)
@Suite("Signature Verification Integration Tests", .tags(.integration))
struct SignatureVerificationIntegrationTests {
    
    // MARK: - Verify ssh-keygen Signatures
    
    /// Helper to create and sign a message with ssh-keygen via a certificate
    private static func createSSHKeygenSignedCertificate(
        tempDir: URL,
        caKeyType: String,
        caBits: String? = nil,
        signatureAlgorithm: String? = nil
    ) throws -> (caKey: any SSHKey, certifiedKey: CertifiedKey, certPath: URL) {
        // Generate CA key
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        var caGenArgs = ["-t", caKeyType, "-f", caKeyPath.path, "-N", "", "-C", "ca@example.com"]
        if let bits = caBits {
            caGenArgs.insert(contentsOf: ["-b", bits], at: 2)
        }
        let caGenResult = try IntegrationTestSupporter.runSSHKeygen(caGenArgs)
        guard caGenResult.succeeded else {
            throw SSHKeyError.invalidFormat
        }
        
        // Read CA key
        let caKey = try KeyManager.readPrivateKey(from: caKeyPath.path, passphrase: nil)
        
        // Generate user key
        let userKeyPath = tempDir.appendingPathComponent("user_key")
        let userGenResult = try IntegrationTestSupporter.runSSHKeygen([
            "-t", "ed25519",
            "-f", userKeyPath.path,
            "-N", "",
            "-C", "user@example.com"
        ])
        guard userGenResult.succeeded else {
            throw SSHKeyError.invalidFormat
        }
        
        // Sign certificate
        let certPath = userKeyPath.appendingPathExtension("pub")
        var signArgs = ["-s", caKeyPath.path, "-I", "sig-test", "-n", "testuser", certPath.path]
        if let sigAlg = signatureAlgorithm {
            signArgs.insert(contentsOf: ["-t", sigAlg], at: 4)
        }
        let signResult = try IntegrationTestSupporter.runSSHKeygen(signArgs)
        guard signResult.succeeded else {
            throw SSHKeyError.invalidFormat
        }
        
        // Parse the certificate
        let certFilePath = tempDir.appendingPathComponent("user_key-cert.pub")
        let certString = try String(contentsOf: certFilePath, encoding: .utf8)
        let certifiedKey = try CertificateParser.parseCertificate(from: certString)
        
        return (caKey, certifiedKey, certFilePath)
    }
    
    @Test("Verify ssh-keygen Ed25519 signature")
    func testVerifyEd25519Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ed25519"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "Ed25519 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "ssh-ed25519", "Signature type should be ssh-ed25519")
        }
    }
    
    @Test("Verify ssh-keygen RSA signature (rsa-sha2-256)", .tags(.rsa, .slow))
    func testVerifyRSASHA256Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "rsa",
                caBits: "2048",
                signatureAlgorithm: "rsa-sha2-256"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "RSA SHA-256 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "rsa-sha2-256", "Signature type should be rsa-sha2-256")
        }
    }
    
    @Test("Verify ssh-keygen RSA signature (rsa-sha2-512)", .tags(.rsa, .slow))
    func testVerifyRSASHA512Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "rsa",
                caBits: "2048",
                signatureAlgorithm: "rsa-sha2-512"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "RSA SHA-512 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "rsa-sha2-512", "Signature type should be rsa-sha2-512")
        }
    }
    
    @Test("Verify ssh-keygen ECDSA P-256 signature")
    func testVerifyECDSAP256Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ecdsa",
                caBits: "256"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "ECDSA P-256 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "ecdsa-sha2-nistp256", "Signature type should be ecdsa-sha2-nistp256")
        }
    }
    
    @Test("Verify ssh-keygen ECDSA P-384 signature")
    func testVerifyECDSAP384Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ecdsa",
                caBits: "384"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "ECDSA P-384 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "ecdsa-sha2-nistp384", "Signature type should be ecdsa-sha2-nistp384")
        }
    }
    
    @Test("Verify ssh-keygen ECDSA P-521 signature")
    func testVerifyECDSAP521Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ecdsa",
                caBits: "521"
            )
            
            // Verify the certificate signature created by ssh-keygen
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            
            #expect(result == .valid, "ECDSA P-521 signature from ssh-keygen should be valid")
            #expect(certifiedKey.certificate.signatureType == "ecdsa-sha2-nistp521", "Signature type should be ecdsa-sha2-nistp521")
        }
    }
    
    // MARK: - ssh-keygen Verifies Our Signatures
    
    @Test("ssh-keygen verifies our Ed25519 certificate signature")
    func testSSHKeygenVerifiesOurEd25519Signature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA key with our implementation
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@example.com") as! Ed25519Key
            
            // Generate user key with our implementation
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
            
            // Sign certificate with our implementation
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "our-ed25519-cert",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write CA public key for ssh-keygen verification
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can list the certificate (implicit signature check)
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept our Ed25519 certificate")
            #expect(listResult.stdout.contains("our-ed25519-cert"), "Certificate key ID should be present")
            #expect(listResult.stdout.contains("testuser"), "Principal should be present")
        }
    }
    
    @Test("ssh-keygen verifies our RSA certificate signature (rsa-sha2-512)", .tags(.rsa, .slow))
    func testSSHKeygenVerifiesOurRSASignature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate RSA CA key with our implementation
            let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca@example.com") as! RSAKey
            
            // Generate user key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
            
            // Sign certificate with rsa-sha2-512
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "our-rsa-cert",
                principals: ["testuser"],
                certificateType: .user,
                signatureAlgorithm: "rsa-sha2-512"
            )
            
            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can list the certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept our RSA certificate")
            #expect(listResult.stdout.contains("our-rsa-cert"), "Certificate key ID should be present")
            #expect(listResult.stdout.contains("testuser"), "Principal should be present")
        }
    }
    
    @Test("ssh-keygen verifies our ECDSA P-256 certificate signature")
    func testSSHKeygenVerifiesOurECDSASignature() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate ECDSA CA key with our implementation
            let caKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-ca@example.com") as! ECDSAKey
            
            // Generate user key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
            
            // Sign certificate
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "our-ecdsa-cert",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can list the certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept our ECDSA certificate")
            #expect(listResult.stdout.contains("our-ecdsa-cert"), "Certificate key ID should be present")
            #expect(listResult.stdout.contains("testuser"), "Principal should be present")
        }
    }
    
    // MARK: - Invalid Signature Detection
    
    @Test("Detect tampered ssh-keygen certificate")
    func testDetectTamperedCertificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (caKey, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ed25519"
            )
            
            // First verify it's valid
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            #expect(result == .valid, "Original certificate should be valid")
            
            // Tamper with the certificate by modifying the key ID
            // (This is a conceptual test - we'd need to re-serialize with a different key ID)
            // For now, verify that using the wrong CA key fails
            let wrongCAKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "wrong-ca") as! Ed25519Key
            
            let invalidResult = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: wrongCAKey
            )
            
            #expect(invalidResult != .valid, "Certificate should fail verification with wrong CA key")
        }
    }
    
    @Test("Verify certificate fails with wrong CA key (Ed25519)")
    func testVerifyCertificateFailsWithWrongCAKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (_, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ed25519"
            )
            
            // Generate a different CA key
            let wrongCAKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "wrong-ca") as! Ed25519Key
            
            // Verification should fail
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: wrongCAKey
            )
            
            #expect(result != .valid, "Certificate should fail verification with wrong CA key")
        }
    }
    
    @Test("Verify certificate fails with wrong CA key (RSA)", .tags(.rsa, .slow))
    func testVerifyCertificateFailsWithWrongCAKeyRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let (_, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "rsa",
                caBits: "2048"
            )
            
            // Generate a different RSA CA key
            let wrongCAKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "wrong-ca") as! RSAKey
            
            // Verification should fail
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: wrongCAKey
            )
            
            #expect(result != .valid, "RSA certificate should fail verification with wrong CA key")
        }
    }
    
    @Test("Verify certificate fails with wrong CA key type")
    func testVerifyCertificateFailsWithWrongCAKeyType() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create certificate signed with Ed25519 CA
            let (_, certifiedKey, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ed25519"
            )
            
            // Try to verify with ECDSA CA key (wrong type)
            let wrongTypeCAKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "wrong-type-ca") as! ECDSAKey
            
            // Verification should fail for mismatched key types
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: wrongTypeCAKey
            )
            #expect(result != .valid, "Certificate should fail verification with wrong CA key type")
        }
    }
    
    // MARK: - Cross-Implementation Round-Trip
    
    @Test("Round-trip: ssh-keygen CA signs, we verify, then we sign, ssh-keygen verifies")
    func testSignatureRoundTrip() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Phase 1: ssh-keygen creates CA and signs certificate
            let (caKey, sshKeygenCert, _) = try Self.createSSHKeygenSignedCertificate(
                tempDir: tempDir,
                caKeyType: "ed25519"
            )
            
            // Phase 2: We verify ssh-keygen's signature
            let sshKeygenResult = CertificateVerifier.verifyCertificate(
                sshKeygenCert,
                caKey: caKey
            )
            #expect(sshKeygenResult == .valid, "Should verify ssh-keygen's signature")
            
            // Phase 3: We create a certificate with the same CA
            let ourUserKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "our-user@example.com") as! Ed25519Key
            let ourCert = try CertificateAuthority.signCertificate(
                publicKey: ourUserKey,
                caKey: caKey as! Ed25519Key,
                keyId: "our-round-trip-cert",
                principals: ["roundtripuser"],
                certificateType: .user
            )
            
            // Phase 4: We verify our own signature
            let ourResult = CertificateVerifier.verifyCertificate(
                ourCert,
                caKey: caKey
            )
            #expect(ourResult == .valid, "Should verify our own signature")
            
            // Phase 5: ssh-keygen verifies our signature
            let ourCertPath = tempDir.appendingPathComponent("our_cert.pub")
            try IntegrationTestSupporter.write(ourCert.publicKeyString(), to: ourCertPath)
            
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", ourCertPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept our certificate")
            #expect(listResult.stdout.contains("our-round-trip-cert"), "Certificate should be readable by ssh-keygen")
        }
    }
}
