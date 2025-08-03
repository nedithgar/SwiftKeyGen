import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Certificate Tests")
struct CertificateTests {
    
    @Test("Create and sign user certificate")
    func testCreateUserCertificate() throws {
        // Generate CA key
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-ca") as! Ed25519Key
        
        // Generate user key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test") as! Ed25519Key
        
        // Create certificate
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["alice", "bob"],
            certificateType: .user
        )
        
        #expect(cert.certificate.type == .user)
        #expect(cert.certificate.keyId == "test-user")
        #expect(cert.certificate.principals == ["alice", "bob"])
        #expect(cert.certificate.serial > 0)
        #expect(cert.certificate.signatureKey != nil)
        #expect(cert.certificate.certBlob != nil)
    }
    
    @Test("Create and sign host certificate")
    func testCreateHostCertificate() throws {
        // Generate CA key
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host-ca") as! Ed25519Key
        
        // Generate host key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host.example.com") as! Ed25519Key
        
        // Create certificate with specific validity
        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(365 * 24 * 60 * 60) // 1 year
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: hostKey,
            caKey: caKey,
            keyId: "host.example.com",
            principals: ["host.example.com", "*.example.com"],
            serial: 12345,
            validFrom: validFrom,
            validTo: validTo,
            certificateType: .host
        )
        
        #expect(cert.certificate.type == .host)
        #expect(cert.certificate.serial == 12345)
        #expect(cert.certificate.principals.count == 2)
        #expect(cert.certificate.principals.contains("host.example.com"))
        #expect(cert.certificate.principals.contains("*.example.com"))
    }
    
    @Test("Certificate validity period")
    func testCertificateValidity() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        // Create certificate valid for 1 hour
        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(3600) // 1 hour
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "short-lived",
            validFrom: validFrom,
            validTo: validTo
        )
        
        // Check validity
        #expect(cert.certificate.isValid(at: validFrom))
        #expect(cert.certificate.isValid(at: validFrom.addingTimeInterval(1800))) // 30 min later
        #expect(!cert.certificate.isValid(at: validFrom.addingTimeInterval(-60))) // 1 min before
        #expect(!cert.certificate.isValid(at: validTo.addingTimeInterval(60))) // 1 min after
        
        // Check formatting
        let validity = cert.certificate.formatValidity()
        #expect(validity.contains("from"))
        #expect(validity.contains("to"))
    }
    
    @Test("Certificate critical options")
    func testCriticalOptions() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "restricted-user",
            criticalOptions: [
                (.forceCommand, "/bin/echo Hello"),
                (.sourceAddress, "192.168.1.0/24")
            ]
        )
        
        #expect(cert.certificate.criticalOptions.count == 2)
        
        guard cert.certificate.criticalOptions.count >= 2 else {
            Issue.record("Expected 2 critical options but got \(cert.certificate.criticalOptions.count)")
            return
        }
        
        #expect(cert.certificate.criticalOptions[0].0 == "force-command")
        #expect(cert.certificate.criticalOptions[0].1 == "/bin/echo Hello")
        #expect(cert.certificate.criticalOptions[1].0 == "source-address")
        #expect(cert.certificate.criticalOptions[1].1 == "192.168.1.0/24")
    }
    
    @Test("Certificate extensions")
    func testExtensions() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "full-access-user",
            extensions: [
                .permitX11Forwarding,
                .permitAgentForwarding,
                .permitPortForwarding,
                .permitPty,
                .permitUserRc,
                .noTouchRequired
            ]
        )
        
        #expect(cert.certificate.extensions.count == 6)
        #expect(cert.certificate.extensions.contains("permit-X11-forwarding"))
        #expect(cert.certificate.extensions.contains("no-touch-required"))
    }
    
    @Test("Certificate verification - valid")
    func testCertificateVerificationValid() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["alice"]
        )
        
        // Verify with correct CA key
        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.allowedPrincipals = ["alice"]
        
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options)
        #expect(result == .valid)
    }
    
    @Test("Certificate verification - expired")
    func testCertificateVerificationExpired() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        // Create certificate that expired yesterday
        let validFrom = Date().addingTimeInterval(-2 * 24 * 60 * 60) // 2 days ago
        let validTo = Date().addingTimeInterval(-1 * 24 * 60 * 60) // 1 day ago
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "expired-user",
            validFrom: validFrom,
            validTo: validTo
        )
        
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .expired)
    }
    
    @Test("Certificate verification - invalid principal")
    func testCertificateVerificationInvalidPrincipal() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["alice"]
        )
        
        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.allowedPrincipals = ["bob"] // Different principal
        
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options)
        #expect(result == .invalidPrincipal)
    }
    
    @Test("Certificate wildcard principal matching")
    func testWildcardPrincipalMatching() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: hostKey,
            caKey: caKey,
            keyId: "wildcard-host",
            principals: ["*.example.com", "special.example.com"],
            certificateType: .host
        )
        
        // Test various hostnames
        let testCases = [
            ("www.example.com", true),
            ("mail.example.com", true),
            ("special.example.com", true),
            ("example.com", false),
            ("sub.domain.example.com", false),
            ("example.org", false)
        ]
        
        for (hostname, shouldMatch) in testCases {
            let result = CertificateManager.verifyCertificateForHost(
                cert,
                hostname: hostname,
                caKey: caKey
            )
            
            if shouldMatch {
                #expect(result == .valid, "Expected \(hostname) to match")
            } else {
                #expect(result == .invalidPrincipal, "Expected \(hostname) not to match")
            }
        }
    }
    
    @Test("Certificate info display")
    func testCertificateInfoDisplay() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-ca") as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test") as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "display-test",
            principals: ["alice", "bob"],
            serial: 99999,
            certificateType: .user,
            criticalOptions: [(.forceCommand, "ls")],
            extensions: [.permitPty, .permitUserRc]
        )
        
        let info = cert.certificateInfo()
        
        #expect(info.contains("user certificate"))
        #expect(info.contains("Key ID: \"display-test\""))
        #expect(info.contains("Serial: 99999"))
        #expect(info.contains("alice"))
        #expect(info.contains("bob"))
        #expect(info.contains("force-command ls"))
        #expect(info.contains("permit-pty"))
        #expect(info.contains("permit-user-rc"))
    }
    
    @Test("Save and read certificate")
    func testSaveAndReadCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "save-test",
            principals: ["testuser"]
        )
        
        // Save certificate
        let tempDir = FileManager.default.temporaryDirectory
        let certPath = tempDir.appendingPathComponent("test-cert.pub").path
        
        try CertificateManager.saveCertificate(cert, to: certPath, comment: "test certificate")
        
        // Read certificate back
        let readCert = try CertificateManager.readCertificate(from: certPath)
        
        #expect(readCert.certificate.keyId == "save-test")
        #expect(readCert.certificate.principals == ["testuser"])
        
        // Clean up
        try FileManager.default.removeItem(atPath: certPath)
    }
    
    @Test("Create user certificate with restrictions")
    func testCreateRestrictedUserCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let cert = try CertificateManager.createUserCertificate(
            publicKey: userKey,
            caKey: caKey,
            username: "restricted",
            validityDays: 7,
            forceCommand: "/usr/bin/git-shell",
            sourceAddress: "10.0.0.0/8"
        )
        
        #expect(cert.certificate.principals == ["restricted"])
        #expect(cert.certificate.criticalOptions.count == 2)
        
        // Verify it's valid for the user
        let result = CertificateManager.verifyCertificateForUser(
            cert,
            username: "restricted",
            caKey: caKey
        )
        #expect(result == .valid)
    }
}