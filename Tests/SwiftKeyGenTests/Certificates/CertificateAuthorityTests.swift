import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Certificate Authority Tests")
struct CertificateAuthorityTests {

    @Test("Create and sign user certificate")
    func testCreateUserCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-ca") as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test") as! Ed25519Key

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
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host-ca") as! Ed25519Key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "host.example.com") as! Ed25519Key

        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(365 * 24 * 60 * 60)

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

    @Test("Certificate default validity is forever")
    func testCertificateDefaultValidityForever() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["test"],
            certificateType: .user
        )

        #expect(cert.certificate.validAfter == 0)
        #expect(cert.certificate.validBefore == UInt64.max)
        #expect(cert.certificate.formatValidity() == "forever")
        #expect(cert.certificate.isValid())
    }

    @Test("Certificate validity period")
    func testCertificateValidity() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(3600)

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "short-lived",
            validFrom: validFrom,
            validTo: validTo
        )

        #expect(cert.certificate.isValid(at: validFrom))
        #expect(cert.certificate.isValid(at: validFrom.addingTimeInterval(1800)))
        #expect(!cert.certificate.isValid(at: validFrom.addingTimeInterval(-60)))
        #expect(!cert.certificate.isValid(at: validTo.addingTimeInterval(60)))

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

    @Test("RSA certificate with different signature algorithms", .tags(.rsa, .slow))
    func testRSACertificateSignatureAlgorithms() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca") as! RSAKey
        let userKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "user@test") as! RSAKey

        let algorithms = ["rsa-sha2-256", "rsa-sha2-512"]

        for algorithm in algorithms {
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-\(algorithm)",
                principals: ["testuser"],
                certificateType: .user,
                signatureAlgorithm: algorithm
            )

            #expect(cert.certificate.signatureType == algorithm)
            #expect(cert.certificate.certBlob != nil)

            let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
            #expect(result == .valid, "Certificate with \(algorithm) should be valid")
        }
    }

    @Test("RSA certificate with incompatible signature algorithm", .tags(.rsa, .slow))
    func testRSACertificateIncompatibleAlgorithm() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        #expect(throws: SSHKeyError.incompatibleSignatureAlgorithm) {
            _ = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-incompatible",
                principals: ["testuser"],
                signatureAlgorithm: "ssh-ed25519"
            )
        }

        #expect(throws: SSHKeyError.incompatibleSignatureAlgorithm) {
            _ = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-incompatible",
                principals: ["testuser"],
                signatureAlgorithm: "ecdsa-sha2-nistp256"
            )
        }
    }

    @Test("Default signature algorithm for RSA", .tags(.rsa, .slow))
    func testDefaultSignatureAlgorithmRSA() throws {
        let rsaCA = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        let rsaUser = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey

        let rsaCert = try CertificateAuthority.signCertificate(
            publicKey: rsaUser,
            caKey: rsaCA,
            keyId: "rsa-default",
            principals: ["testuser"]
        )
        #expect(rsaCert.certificate.signatureType == "rsa-sha2-512")
    }

    @Test("Default signature algorithm for different key types")
    func testDefaultSignatureAlgorithms() throws {
        let ed25519CA = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let ed25519User = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let ed25519Cert = try CertificateAuthority.signCertificate(
            publicKey: ed25519User,
            caKey: ed25519CA,
            keyId: "ed25519-default",
            principals: ["testuser"]
        )
        #expect(ed25519Cert.certificate.signatureType == "ssh-ed25519")

        let ecdsaCA = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let ecdsaUser = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey

        let ecdsaCert = try CertificateAuthority.signCertificate(
            publicKey: ecdsaUser,
            caKey: ecdsaCA,
            keyId: "ecdsa-default",
            principals: ["testuser"]
        )
        #expect(ecdsaCert.certificate.signatureType == "ecdsa-sha2-nistp256")
    }
}
