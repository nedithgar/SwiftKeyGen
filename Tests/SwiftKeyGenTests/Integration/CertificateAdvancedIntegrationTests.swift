import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for advanced certificate features including host certificates,
/// critical options, extensions, and edge cases.
@Suite("Advanced Certificate Features Integration Tests", .tags(.integration))
struct CertificateAdvancedIntegrationTests {
    
    // MARK: - Host Certificates - Our Implementation
    
    @Test("ssh-keygen verifies our host certificate (Ed25519 CA)")
    func testSSHKeygenVerifiesOurHostCertificateEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and host keys with our implementation
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host-ca@example.com") as! Ed25519Key
            let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host.example.com") as! Ed25519Key
            
            // Sign host certificate
            let hostCert = try CertificateAuthority.signCertificate(
                publicKey: hostKey,
                caKey: caKey,
                keyId: "host.example.com",
                principals: ["host.example.com", "192.168.1.100"],
                certificateType: .host
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("host_key-cert.pub")
            try IntegrationTestSupporter.write(hostCert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can read and validate the host certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read our host certificate")
            #expect(listResult.stdout.contains("host certificate"), "Should identify as host certificate")
            #expect(listResult.stdout.contains("host.example.com"), "Should contain hostname principal")
            #expect(listResult.stdout.contains("192.168.1.100"), "Should contain IP address principal")
        }
    }
    
    @Test("ssh-keygen verifies our host certificate (RSA CA)", .tags(.rsa, .slow))
    func testSSHKeygenVerifiesOurHostCertificateRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate RSA CA and host keys
            let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "host-rsa-ca@example.com") as! RSAKey
            let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host.example.com") as! Ed25519Key
            
            // Sign host certificate with rsa-sha2-512
            let hostCert = try CertificateAuthority.signCertificate(
                publicKey: hostKey,
                caKey: caKey,
                keyId: "web.example.com",
                principals: ["web.example.com", "www.example.com"],
                certificateType: .host,
                signatureAlgorithm: "rsa-sha2-512"
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("host_key-cert.pub")
            try IntegrationTestSupporter.write(hostCert.publicKeyString(), to: certPath)
            
            // Verify with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read our RSA-signed host certificate")
            #expect(listResult.stdout.contains("host certificate"), "Should identify as host certificate")
            #expect(listResult.stdout.contains("web.example.com"), "Should contain primary hostname")
            #expect(listResult.stdout.contains("www.example.com"), "Should contain alternate hostname")
        }
    }
    
    @Test("ssh-keygen verifies our host certificate (ECDSA CA)")
    func testSSHKeygenVerifiesOurHostCertificateECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate ECDSA CA and host keys
            let caKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "host-ecdsa-ca@example.com") as! ECDSAKey
            let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "api.example.com") as! Ed25519Key
            
            // Sign host certificate
            let hostCert = try CertificateAuthority.signCertificate(
                publicKey: hostKey,
                caKey: caKey,
                keyId: "api.example.com",
                principals: ["api.example.com"],
                certificateType: .host
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("host_key-cert.pub")
            try IntegrationTestSupporter.write(hostCert.publicKeyString(), to: certPath)
            
            // Verify with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read our ECDSA-signed host certificate")
            #expect(listResult.stdout.contains("host certificate"), "Should identify as host certificate")
            #expect(listResult.stdout.contains("api.example.com"), "Should contain API hostname")
        }
    }
    
    // MARK: - Parse ssh-keygen Host Certificates
    
    @Test("We verify ssh-keygen host certificate (Ed25519 CA)")
    func testWeVerifySSHKeygenHostCertificateEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA key with ssh-keygen
            let caKeyPath = tempDir.appendingPathComponent("ca_key")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            // Read CA key
            let caKey = try KeyManager.readPrivateKey(from: caKeyPath.path, passphrase: nil)
            
            // Generate host key with ssh-keygen
            let hostKeyPath = tempDir.appendingPathComponent("host_key")
            let hostGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", hostKeyPath.path,
                "-N", "",
                "-C", "host@example.com"
            ])
            #expect(hostGenResult.succeeded)
            
            // Sign host certificate with ssh-keygen
            let certPath = hostKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "test-host",
                "-n", "server.example.com",
                "-h",  // Host certificate
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse the certificate
            let certFilePath = tempDir.appendingPathComponent("host_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            // Verify it's a host certificate
            #expect(certifiedKey.certificate.type == .host, "Should be host certificate")
            #expect(certifiedKey.certificate.keyId == "test-host", "Key ID should match")
            #expect(certifiedKey.certificate.principals.contains("server.example.com"), "Should contain hostname")
            
            // Verify the signature
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            #expect(result == .valid, "Host certificate signature should be valid")
        }
    }
    
    @Test("We verify ssh-keygen host certificate (RSA CA)", .tags(.rsa))
    func testWeVerifySSHKeygenHostCertificateRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate RSA CA key with ssh-keygen
            let caKeyPath = tempDir.appendingPathComponent("ca_rsa")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "rsa-ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            // Read CA key
            let caKey = try KeyManager.readPrivateKey(from: caKeyPath.path, passphrase: nil)
            
            // Generate host key
            let hostKeyPath = tempDir.appendingPathComponent("host_key")
            let hostGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", hostKeyPath.path,
                "-N", "",
                "-C", "host@example.com"
            ])
            #expect(hostGenResult.succeeded)
            
            // Sign host certificate
            let certPath = hostKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "rsa-host-cert",
                "-n", "db.example.com",
                "-h",
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse and verify
            let certFilePath = tempDir.appendingPathComponent("host_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            #expect(certifiedKey.certificate.type == .host, "Should be host certificate")
            
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            #expect(result == .valid, "RSA host certificate signature should be valid")
        }
    }
    
    @Test("We verify ssh-keygen host certificate (ECDSA CA)")
    func testWeVerifySSHKeygenHostCertificateECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate ECDSA CA key with ssh-keygen
            let caKeyPath = tempDir.appendingPathComponent("ca_ecdsa")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ecdsa-ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            // Read CA key
            let caKey = try KeyManager.readPrivateKey(from: caKeyPath.path, passphrase: nil)
            
            // Generate host key
            let hostKeyPath = tempDir.appendingPathComponent("host_key")
            let hostGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", hostKeyPath.path,
                "-N", "",
                "-C", "host@example.com"
            ])
            #expect(hostGenResult.succeeded)
            
            // Sign host certificate
            let certPath = hostKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "ecdsa-host-cert",
                "-n", "mail.example.com",
                "-h",
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse and verify
            let certFilePath = tempDir.appendingPathComponent("host_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            #expect(certifiedKey.certificate.type == .host, "Should be host certificate")
            
            let result = CertificateVerifier.verifyCertificate(
                certifiedKey,
                caKey: caKey
            )
            #expect(result == .valid, "ECDSA host certificate signature should be valid")
        }
    }
    
    // MARK: - Wildcard Principals
    
    @Test("Host certificate with wildcard principals")
    func testHostCertificateWithWildcardPrincipals() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and host keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@example.com") as! Ed25519Key
            let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host@example.com") as! Ed25519Key
            
            // Sign host certificate with wildcard principal
            let hostCert = try CertificateAuthority.signCertificate(
                publicKey: hostKey,
                caKey: caKey,
                keyId: "wildcard-host",
                principals: ["*.example.com", "*.internal"],
                certificateType: .host
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("host_key-cert.pub")
            try IntegrationTestSupporter.write(hostCert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen accepts wildcard principals
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept wildcard principals")
            #expect(listResult.stdout.contains("*.example.com") || listResult.stdout.contains("*"), 
                   "Should show wildcard principal")
        }
    }
    
    // MARK: - Certificate Validity Checks
    
    @Test("Host certificate validity checks")
    func testHostCertificateValidityChecks() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA key with ssh-keygen
            let caKeyPath = tempDir.appendingPathComponent("ca_key")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            // Generate host key
            let hostKeyPath = tempDir.appendingPathComponent("host_key")
            let hostGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", hostKeyPath.path,
                "-N", "",
                "-C", "host@example.com"
            ])
            #expect(hostGenResult.succeeded)
            
            // Sign host certificate with specific validity period
            let certPath = hostKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "validity-test",
                "-n", "test.example.com",
                "-V", "+1h",  // Valid for 1 hour
                "-h",
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse the certificate
            let certFilePath = tempDir.appendingPathComponent("host_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            let cert = certifiedKey.certificate
            
            // Verify validity period is set
            #expect(cert.validAfter > 0, "Valid after should be set")
            #expect(cert.validBefore > cert.validAfter, "Valid before should be after valid after")
            
            // Verify it's currently valid (within the 1 hour window)
            let now = UInt64(Date().timeIntervalSince1970)
            #expect(now >= cert.validAfter, "Certificate should be valid now (after start)")
            #expect(now <= cert.validBefore, "Certificate should be valid now (before end)")
        }
    }
    
    // MARK: - Certificate Extensions
    
    @Test("Parse certificates with standard extensions")
    func testParseCertificateWithExtensions() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKeyPath = tempDir.appendingPathComponent("ca_key")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            let userKeyPath = tempDir.appendingPathComponent("user_key")
            let userGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", userKeyPath.path,
                "-N", "",
                "-C", "user@example.com"
            ])
            #expect(userGenResult.succeeded)
            
            // Sign with default extensions (permit-X11-forwarding, etc.)
            let certPath = userKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "ext-test",
                "-n", "testuser",
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse the certificate
            let certFilePath = tempDir.appendingPathComponent("user_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            let cert = certifiedKey.certificate
            
            // Verify extensions are present (ssh-keygen adds default extensions)
            #expect(cert.extensions.count > 0, "Certificate should have extensions")
            
            // Common extensions that ssh-keygen adds by default
            let commonExtensions = ["permit-X11-forwarding", "permit-agent-forwarding", 
                                   "permit-port-forwarding", "permit-pty", "permit-user-rc"]
            
            var foundExtensions = 0
            for ext in commonExtensions {
                if cert.extensions.contains(ext) {
                    foundExtensions += 1
                }
            }
            
            #expect(foundExtensions > 0, "Should have at least some standard extensions")
        }
    }
    
    @Test("Parse certificates with no extensions")
    func testParseCertificateWithNoExtensions() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKeyPath = tempDir.appendingPathComponent("ca_key")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            let userKeyPath = tempDir.appendingPathComponent("user_key")
            let userGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", userKeyPath.path,
                "-N", "",
                "-C", "user@example.com"
            ])
            #expect(userGenResult.succeeded)
            
            // Sign with clear extensions (no extensions)
            let certPath = userKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "no-ext-test",
                "-n", "restricteduser",
                "-O", "clear",  // Clear all extensions
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse the certificate
            let certFilePath = tempDir.appendingPathComponent("user_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            let cert = certifiedKey.certificate
            
            // Verify no extensions
            #expect(cert.extensions.isEmpty, "Certificate should have no extensions when cleared")
        }
    }
    
    // MARK: - Multiple Principals
    
    @Test("Certificate with multiple principals")
    func testCertificateWithMultiplePrincipals() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@example.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
            
            // Create certificate with 5 principals
            let principals = ["user1", "user2", "user3", "admin", "developer"]
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "multi-principal-cert",
                principals: principals,
                certificateType: .user
            )
            
            // Write and verify with ssh-keygen
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept multiple principals")
            
            // Verify all principals are present
            for principal in principals {
                #expect(listResult.stdout.contains(principal), "Should contain principal: \(principal)")
            }
        }
    }
    
    @Test("Certificate with empty principals list")
    func testCertificateWithEmptyPrincipals() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@example.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
            
            // Create certificate with no principals (wildcard access)
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "no-principals-cert",
                principals: [],
                certificateType: .user
            )
            
            // Write and verify with ssh-keygen
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should accept certificate with no principals")
            
            // Empty principals means wildcard access
            #expect(cert.certificate.principals.isEmpty, "Certificate should have no principals")
        }
    }
    
    // MARK: - Serial Number Handling
    
    @Test("Certificate with large serial number")
    func testCertificateWithLargeSerialNumber() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate keys with ssh-keygen
            let caKeyPath = tempDir.appendingPathComponent("ca_key")
            let caGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", caKeyPath.path,
                "-N", "",
                "-C", "ca@example.com"
            ])
            #expect(caGenResult.succeeded)
            
            let userKeyPath = tempDir.appendingPathComponent("user_key")
            let userGenResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", userKeyPath.path,
                "-N", "",
                "-C", "user@example.com"
            ])
            #expect(userGenResult.succeeded)
            
            // Sign with large serial number
            let largeSerial = "9223372036854775807"  // Max Int64
            let certPath = userKeyPath.appendingPathExtension("pub")
            let signResult = try IntegrationTestSupporter.runSSHKeygen([
                "-s", caKeyPath.path,
                "-I", "large-serial",
                "-n", "testuser",
                "-z", largeSerial,
                certPath.path
            ])
            #expect(signResult.succeeded)
            
            // Parse and verify serial number
            let certFilePath = tempDir.appendingPathComponent("user_key-cert.pub")
            let certString = try String(contentsOf: certFilePath, encoding: .utf8)
            let certifiedKey = try CertificateParser.parseCertificate(from: certString)
            
            #expect(certifiedKey.certificate.serial == UInt64(largeSerial)!, 
                   "Should handle large serial number")
        }
    }
    
    // MARK: - Certificate Extension Testing
    
    @Test("Certificate extension permit-pty")
    func testCertificateExtensionPermitPTY() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Sign certificate with default extensions (should include permit-pty)
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "pty-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("pty-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // List with ssh-keygen to see extensions
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read certificate")
            #expect(listResult.stdout.contains("permit-pty"), "Should contain permit-pty extension")
            
            // Parse and verify extension exists
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.extensions.contains("permit-pty"), "Certificate should have permit-pty extension")
        }
    }
    
    @Test("Certificate extension permit-user-rc")
    func testCertificateExtensionPermitUserRC() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Sign certificate with default extensions (should include permit-user-rc)
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "rc-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("rc-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // List with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read certificate")
            #expect(listResult.stdout.contains("permit-user-rc"), "Should contain permit-user-rc extension")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.extensions.contains("permit-user-rc"), "Certificate should have permit-user-rc extension")
        }
    }
    
    @Test("Certificate extension permit-X11-forwarding")
    func testCertificateExtensionPermitX11Forwarding() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Sign certificate with default extensions
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "x11-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("x11-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // List with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read certificate")
            #expect(listResult.stdout.contains("permit-X11-forwarding"), "Should contain permit-X11-forwarding extension")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.extensions.contains("permit-X11-forwarding"), "Certificate should have permit-X11-forwarding extension")
        }
    }
    
    @Test("Certificate extension permit-agent-forwarding")
    func testCertificateExtensionPermitAgentForwarding() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Sign certificate with default extensions
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "agent-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("agent-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // List with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read certificate")
            #expect(listResult.stdout.contains("permit-agent-forwarding"), "Should contain permit-agent-forwarding extension")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.extensions.contains("permit-agent-forwarding"), "Certificate should have permit-agent-forwarding extension")
        }
    }
    
    @Test("Certificate extension permit-port-forwarding")
    func testCertificateExtensionPermitPortForwarding() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Sign certificate with default extensions
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "port-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("port-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // List with ssh-keygen
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read certificate")
            #expect(listResult.stdout.contains("permit-port-forwarding"), "Should contain permit-port-forwarding extension")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.extensions.contains("permit-port-forwarding"), "Certificate should have permit-port-forwarding extension")
        }
    }
}
