import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Certificate Manager Tests")
struct CertificateManagerTests {

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

        let testCases: [(String, Bool)] = [
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

        let info = CertificateManager.displayCertificateInfo(cert)

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

        let tempDir = FileManager.default.temporaryDirectory
        let certPath = tempDir.appendingPathComponent("test-cert.pub").path

        try CertificateManager.saveCertificate(cert, to: certPath, comment: "test certificate")

        let readCert = try CertificateManager.readCertificate(from: certPath)

        #expect(readCert.certificate.keyId == "save-test")
        #expect(readCert.certificate.principals == ["testuser"])

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

        let result = CertificateManager.verifyCertificateForUser(
            cert,
            username: "restricted",
            caKey: caKey
        )
        #expect(result == .valid)
    }
}

