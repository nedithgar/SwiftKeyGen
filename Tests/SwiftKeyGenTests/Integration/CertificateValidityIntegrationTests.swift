import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for certificate validity edge cases and boundary conditions.
@Suite("Certificate Validity Edge Cases Integration Tests", .tags(.integration))
struct CertificateValidityIntegrationTests {
    
    // MARK: - Expired Certificate Handling
    
    @Test("Expired certificate handling (past valid_before)")
    func testExpiredCertificateDetection() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create a certificate that expired 1 day ago
            let now = Date()
            let yesterday = now.addingTimeInterval(-86400) // 1 day ago
            let lastWeek = now.addingTimeInterval(-86400 * 7)
            
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "expired-user",
                principals: ["testuser"],
                validFrom: lastWeek,
                validTo: yesterday, // Already expired
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("expired-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen detects expiration
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read expired certificate")
            
            // Parse the certificate to verify validity window
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            let nowTimestamp = UInt64(Date().timeIntervalSince1970)
            #expect(parsed.certificate.validBefore < nowTimestamp, "Certificate should be expired")
            
            // Verify with CertificateVerifier
            let verifyResult = CertificateVerifier.verifyCertificate(parsed, caKey: caKey)
            #expect(verifyResult == .expired, "Verifier should detect expired certificate")
        }
    }
    
    @Test("Not-yet-valid certificate handling (future valid_after)")
    func testNotYetValidCertificateDetection() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create a certificate valid starting tomorrow
            let now = Date()
            let tomorrow = now.addingTimeInterval(86400) // 1 day from now
            let nextWeek = now.addingTimeInterval(86400 * 7)
            
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "future-user",
                principals: ["testuser"],
                validFrom: tomorrow, // Not yet valid
                validTo: nextWeek,
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("future-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can read it
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read future certificate")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            let nowTimestamp = UInt64(now.timeIntervalSince1970)
            #expect(parsed.certificate.validAfter > nowTimestamp, "Certificate should not be valid yet")
            
            // Verify with CertificateVerifier
            let verifyResult = CertificateVerifier.verifyCertificate(parsed, caKey: caKey)
            #expect(verifyResult == .notYetValid, "Verifier should detect not-yet-valid certificate")
        }
    }
    
    @Test("Certificate valid for exactly 1 second")
    func testOneSecondValidityCertificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create a certificate valid for exactly 1 second (in the past to avoid timing issues)
            let now = Date()
            let tenSecondsAgo = now.addingTimeInterval(-10)
            let validFor1Second = tenSecondsAgo.addingTimeInterval(1)
            
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "one-second-user",
                principals: ["testuser"],
                validFrom: tenSecondsAgo,
                validTo: validFor1Second,
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("one-second-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can read it
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read 1-second validity certificate")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            #expect(parsed.certificate.validBefore - parsed.certificate.validAfter == 1, "Certificate should have 1-second validity window")
            
            // Certificate should be expired now
            let nowTimestamp = UInt64(now.timeIntervalSince1970)
            #expect(parsed.certificate.validBefore < nowTimestamp, "1-second certificate should be expired")
        }
    }
    
    @Test("Certificate with forever validity (maximum timestamp)")
    func testForeverValidityCertificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            // Create a certificate with "forever" validity
            // Default behavior (no validFrom/validTo) creates a "forever" cert
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "forever-user",
                principals: ["testuser"],
                certificateType: .user
            )
            
            // Write certificate
            let certPath = tempDir.appendingPathComponent("forever-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)
            
            // Verify ssh-keygen can read it
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen should read forever-valid certificate")
            #expect(listResult.stdout.contains("forever") || listResult.stdout.contains("infinity"), 
                    "ssh-keygen should indicate infinite validity")
            
            // Parse and verify
            let certString = try String(contentsOf: certPath, encoding: .utf8)
            let parsed = try CertificateParser.parseCertificate(from: certString)
            // Default values should be 0 (validAfter) and UInt64.max (validBefore)
            #expect(parsed.certificate.validBefore == UInt64.max, "Certificate should have maximum timestamp")
            
            // Should be valid with our verifier
            let verifyResult = CertificateVerifier.verifyCertificate(parsed, caKey: caKey)
            #expect(verifyResult == .valid, "Forever-valid certificate should be valid")
        }
    }
    
    @Test("Certificate validity boundary conditions")
    func testCertificateValidityBoundaryConditions() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ca@test.com") as! Ed25519Key
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test.com") as! Ed25519Key
            
            let now = Date()
            let oneHourLater = now.addingTimeInterval(3600)
            
            // Test 1: Certificate valid starting exactly now
            let certNow = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "now-user",
                principals: ["testuser"],
                validFrom: now,
                validTo: oneHourLater, // Valid for 1 hour
                certificateType: .user
            )
            
            let certNowPath = tempDir.appendingPathComponent("now-cert.pub")
            try IntegrationTestSupporter.write(certNow.publicKeyString(), to: certNowPath)
            
            let listNow = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certNowPath.path])
            #expect(listNow.succeeded, "ssh-keygen should read certificate valid from now")
            
            // Test 2: Certificate with zero validity window (validFrom == validTo)
            // This is technically invalid but should be parseable
            let certZero = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "zero-user",
                principals: ["testuser"],
                validFrom: now,
                validTo: now, // Zero duration
                certificateType: .user
            )
            
            let certZeroPath = tempDir.appendingPathComponent("zero-cert.pub")
            try IntegrationTestSupporter.write(certZero.publicKeyString(), to: certZeroPath)
            
            let listZero = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certZeroPath.path])
            #expect(listZero.succeeded, "ssh-keygen should read zero-duration certificate")
            
            let certZeroString = try String(contentsOf: certZeroPath, encoding: .utf8)
            let parsedZero = try CertificateParser.parseCertificate(from: certZeroString)
            #expect(parsedZero.certificate.validAfter == parsedZero.certificate.validBefore, "Zero-duration certificate should have equal timestamps")
            
            // Test 3: Certificate with minimum possible timestamp (Unix epoch)
            let epoch = Date(timeIntervalSince1970: 0)
            let tomorrow = now.addingTimeInterval(86400)
            
            let certEpoch = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "epoch-user",
                principals: ["testuser"],
                validFrom: epoch, // Unix epoch
                validTo: tomorrow,
                certificateType: .user
            )
            
            let certEpochPath = tempDir.appendingPathComponent("epoch-cert.pub")
            try IntegrationTestSupporter.write(certEpoch.publicKeyString(), to: certEpochPath)
            
            let listEpoch = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certEpochPath.path])
            #expect(listEpoch.succeeded, "ssh-keygen should read certificate from Unix epoch")
            
            let certEpochString = try String(contentsOf: certEpochPath, encoding: .utf8)
            let parsedEpoch = try CertificateParser.parseCertificate(from: certEpochString)
            #expect(parsedEpoch.certificate.validAfter == 0, "Certificate should start from Unix epoch")
        }
    }
}
