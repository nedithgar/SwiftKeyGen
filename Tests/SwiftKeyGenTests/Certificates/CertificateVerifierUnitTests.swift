import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Certificate Verifier Unit Tests", .tags(.unit))
struct CertificateVerifierUnitTests {

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

        let validFrom = Date().addingTimeInterval(-2 * 24 * 60 * 60)
        let validTo = Date().addingTimeInterval(-1 * 24 * 60 * 60)

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
        options.allowedPrincipals = ["bob"]

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options)
        #expect(result == .invalidPrincipal)
    }

    @Test("Expected type mismatch returns invalidCertificateType")
    func testCertificateTypeMismatch() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            certificateType: .user
        )

        var options = CertificateVerificationOptions()
        options.expectedCertificateType = .host
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options)
        #expect(result == .invalidCertificateType)
    }

    @Test("Validity window boundaries inclusive")
    func testValidityBoundariesInclusive() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let now = Date()
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            validFrom: now,
            validTo: now
        )

        var options = CertificateVerificationOptions()
        options.verifyTime = now
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options)
        #expect(result == .valid)
    }

    @Test("Not yet valid and expired cases")
    func testNotYetValidAndExpired() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let now = Date()
        // Not yet valid
        let futureCert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "future",
            validFrom: now.addingTimeInterval(60),
            validTo: now.addingTimeInterval(3600)
        )
        var options = CertificateVerificationOptions()
        options.verifyTime = now
        #expect(CertificateVerifier.verifyCertificate(futureCert, caKey: caKey, options: options) == .notYetValid)

        // Expired
        let pastCert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "past",
            validFrom: now.addingTimeInterval(-3600),
            validTo: now.addingTimeInterval(-1)
        )
        options.verifyTime = now
        #expect(CertificateVerifier.verifyCertificate(pastCert, caKey: caKey, options: options) == .expired)
    }

    @Test("Wildcard principal matches one-level subdomains only")
    func testWildcardPrincipalOneLevel() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: hostKey,
            caKey: caKey,
            keyId: "host",
            principals: ["*.example.com"],
            certificateType: .host
        )

        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.expectedCertificateType = .host

        options.allowedPrincipals = ["www.example.com"]
        #expect(CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options) == .valid)

        options.allowedPrincipals = ["a.b.example.com"]
        #expect(CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options) == .invalidPrincipal)
    }

    @Test("Wildcard disabled requires exact principal match")
    func testWildcardDisabledPrincipal() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: hostKey,
            caKey: caKey,
            keyId: "host",
            principals: ["*.example.com"],
            certificateType: .host
        )

        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.wildcardPrincipalMatching = false
        options.allowedPrincipals = ["www.example.com"]
        #expect(CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options) == .invalidPrincipal)
    }

    @Test("Require principal with empty certificate principals")
    func testRequirePrincipalWithEmptyCertPrincipals() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            principals: []
        )

        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.allowedPrincipals = ["alice"]
        #expect(CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options) == .invalidPrincipal)
    }

    @Test("Allowed principals ignored when not required")
    func testAllowedPrincipalsIgnoredWhenNotRequired() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            principals: []
        )

        var options = CertificateVerificationOptions()
        options.requirePrincipal = false
        options.allowedPrincipals = ["alice"]
        #expect(CertificateVerifier.verifyCertificate(cert, caKey: caKey, options: options) == .valid)
    }

    @Test("Verification works with public-only CA key")
    func testVerifyWithPublicCAKey() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let caPublicKey = caKey.publicOnlyKey()

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            principals: ["alice"]
        )

        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.allowedPrincipals = ["alice"]
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey, options: options)
        #expect(result == .valid)
    }

    @Test("CA key mismatch detected")
    func testCAKeyMismatch() throws {
        let caKey1 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let caKey2 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey1,
            keyId: "id",
            principals: ["alice"]
        )

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey2)
        #expect(result == .caKeyMismatch)
    }

    @Test("Tampered signature yields invalidSignature")
    func testTamperedSignatureInvalid() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id"
        )

        // Corrupt the last byte of the cert blob (signature bytes are at the end)
        if var blob = cert.certificate.certBlob {
            blob[blob.count - 1] ^= 0xFF
            cert.certificate.certBlob = blob
        }

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .invalidSignature)
    }

    @Test("Signature type mismatch reported as error")
    func testSignatureTypeMismatchError() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id"
        )

        // Force a wrong signatureType to trigger mismatch
        cert.certificate.signatureType = "ssh-ed25519-wrong"

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        switch result {
        case .error(let message):
            #expect(message.contains("Signature verification failed"))
        default:
            Issue.record("Expected error due to signature type mismatch, got \(result)")
        }
    }

    @Test("No CA key skips signature verification")
    func testNoCAKeySkipsSignature() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            principals: ["alice"]
        )
        var options = CertificateVerificationOptions()
        options.requirePrincipal = true
        options.allowedPrincipals = ["alice"]
        let result = CertificateVerifier.verifyCertificate(cert, caKey: nil, options: options)
        #expect(result == .valid)
    }

    @Test("Missing certificate blob returns error")
    func testMissingCertificateBlob() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id"
        )
        cert.certificate.certBlob = nil

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        switch result {
        case .error(let message):
            #expect(message.contains("Certificate blob is missing"))
        default:
            Issue.record("Expected error for missing blob, got \(result)")
        }
    }

    @Test("RSA CA signing Ed25519 user certificate", .tags(.slow, .rsa))
    func testRSACASigningEd25519UserCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca@example.com") as! RSAKey
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["alice"],
            certificateType: .user
        )

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)

        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }

    @Test("ECDSA P256 CA signing RSA user certificate", .tags(.slow, .rsa))
    func testECDSAP256CASigningRSAUserCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-ca@example.com") as! ECDSAKey
        let userKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "user@example.com") as! RSAKey

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["bob"],
            certificateType: .user
        )

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)

        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }

    @Test("ECDSA P384 CA signing ECDSA P256 user certificate")
    func testECDSAP384CASigningECDSAP256UserCertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa-ca@example.com") as! ECDSAKey
        let userKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "user@example.com") as! ECDSAKey

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["charlie"],
            certificateType: .user
        )

        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)

        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }

    @Test("All key type combinations", .tags(.slow, .rsa))
    func testAllKeyTypeCombinations() throws {
        let caKeys: [(any SSHKey, String)] = [
            (try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-ca"), "Ed25519"),
            (try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca"), "RSA"),
            (try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-p256-ca"), "ECDSA-P256"),
            (try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa-p384-ca"), "ECDSA-P384"),
            (try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "ecdsa-p521-ca"), "ECDSA-P521")
        ]

        let userKeys: [(any SSHKey, String)] = [
            (try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-user"), "Ed25519"),
            (try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-user"), "RSA"),
            (try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-p256-user"), "ECDSA-P256")
        ]

        var successCount = 0
        var totalTests = 0

        for (caKey, caType) in caKeys {
            for (userKey, userType) in userKeys {
                totalTests += 1

                let cert = try CertificateAuthority.signCertificate(
                    publicKey: userKey,
                    caKey: caKey,
                    keyId: "\(userType)-signed-by-\(caType)",
                    principals: ["test"],
                    certificateType: .user
                )

                let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
                if result == .valid {
                    successCount += 1
                }

                let caPublicKey = caKey.publicOnlyKey()
                let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
                #expect(publicResult == .valid, "\(caType) CA -> \(userType) user public key verification failed")
            }
        }

        #expect(successCount == totalTests)
    }
}
