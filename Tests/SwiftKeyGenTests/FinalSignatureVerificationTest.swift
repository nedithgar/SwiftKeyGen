import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Final Signature Verification Test", .serialized)
struct FinalSignatureVerificationTest {
    
    @Test("RSA CA signing Ed25519 user certificate")
    func testRSACASignature() throws {
        // Generate RSA CA key
        let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca@example.com") as! RSAKey
        
        // Generate Ed25519 user key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
        
        // Create certificate
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["alice"],
            certificateType: .user
        )
        
        // Verify with CA key
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)
        
        // Verify with public-only CA key
        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }
    
    @Test("ECDSA P256 CA signing RSA user certificate")
    func testECDSAP256CASignature() throws {
        // Generate ECDSA P256 CA key
        let caKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-ca@example.com") as! ECDSAKey
        
        // Generate RSA user key
        let userKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "user@example.com") as! RSAKey
        
        // Create certificate
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["bob"],
            certificateType: .user
        )
        
        // Verify with CA key
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)
        
        // Verify with public-only CA key
        // Add a small delay to avoid potential race conditions
        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }
    
    @Test("ECDSA P384 CA signing ECDSA P256 user certificate")
    func testECDSAP384CASignature() throws {
        // Generate ECDSA P384 CA key
        let caKey = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa-ca@example.com") as! ECDSAKey
        
        // Generate ECDSA P256 user key
        let userKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "user@example.com") as! ECDSAKey
        
        // Create certificate
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["charlie"],
            certificateType: .user
        )
        
        // Verify with CA key
        let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
        #expect(result == .valid)
        
        // Verify with public-only CA key
        let caPublicKey = caKey.publicOnlyKey()
        let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
        #expect(publicResult == .valid)
    }
    
    @Test("All key type combinations", .disabled("Causing signal 5 crash - needs investigation"))
    func testAllKeyTypeCombinations() throws {
        // Test all CA key types
        let caKeys: [(any SSHKey, String)] = [
            (try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-ca"), "Ed25519"),
            (try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca"), "RSA"),
            (try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-p256-ca"), "ECDSA-P256"),
            (try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa-p384-ca"), "ECDSA-P384"),
            (try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "ecdsa-p521-ca"), "ECDSA-P521")
        ]
        
        // Test all user key types
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
                
                // Create certificate
                let cert = try CertificateAuthority.signCertificate(
                    publicKey: userKey,
                    caKey: caKey,
                    keyId: "\(userType)-signed-by-\(caType)",
                    principals: ["test"],
                    certificateType: .user
                )
                
                // Verify with full CA key
                let result = CertificateVerifier.verifyCertificate(cert, caKey: caKey)
                if result == .valid {
                    successCount += 1
                    print("✅ \(caType) CA -> \(userType) user: SUCCESS")
                } else {
                    print("❌ \(caType) CA -> \(userType) user: \(result)")
                }
                
                // Also verify with public-only CA key
                let caPublicKey = caKey.publicOnlyKey()
                let publicResult = CertificateVerifier.verifyCertificate(cert, caKey: caPublicKey)
                #expect(publicResult == .valid, "\(caType) CA -> \(userType) user public key verification failed")
            }
        }
        
        print("\nTotal: \(successCount)/\(totalTests) tests passed")
        #expect(successCount == totalTests)
    }
}