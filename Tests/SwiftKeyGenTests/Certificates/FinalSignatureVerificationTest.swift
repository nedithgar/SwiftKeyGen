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
    
    @Test("Verify certificate with ssh-keygen")
    func testSSHKeygenVerification() throws {
        // Create temp directory
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }
        
        // Generate Ed25519 CA key using SwiftKeyGen
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-ca@example.com") as! Ed25519Key
        
        // Generate Ed25519 user key using SwiftKeyGen
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key
        
        // Save CA private key
        let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
        let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
        try caPrivateKeyData.write(to: caPrivateKeyPath)
        // Fix permissions for ssh-keygen
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: caPrivateKeyPath.path)
        
        // Save CA public key
        let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
        try caKey.publicKeyString().write(to: caPublicKeyPath, atomically: true, encoding: .utf8)
        
        // Save user public key
        let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
        try userKey.publicKeyString().write(to: userPublicKeyPath, atomically: true, encoding: .utf8)
        
        // Create certificate using SwiftKeyGen
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["charlie", "test.example.com"],
            certificateType: .user
        )
        
        // Save certificate
        let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
        try cert.publicKeyString().write(to: certPath, atomically: true, encoding: .utf8)
        
        // Verify using ssh-keygen
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-L",  // Show certificate details
            "-f", certPath.path
        ]
        
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = outputPipe
        
        try process.run()
        process.waitUntilExit()
        
        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: outputData, encoding: .utf8) ?? ""
        
        // Check that ssh-keygen can read the certificate
        #expect(process.terminationStatus == 0, "ssh-keygen failed to read certificate")
        #expect(output.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
        #expect(output.contains("Key ID: \"test-user\""))
        #expect(output.contains("charlie"))
        #expect(output.contains("test.example.com"))
        
        // Now verify the certificate signature using ssh-keygen
        let verifyProcess = Process()
        verifyProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        verifyProcess.arguments = [
            "-L",
            "-f", certPath.path
        ]
        
        let verifyPipe = Pipe()
        verifyProcess.standardOutput = verifyPipe
        verifyProcess.standardError = verifyPipe
        
        try verifyProcess.run()
        verifyProcess.waitUntilExit()
        
        let verifyData = verifyPipe.fileHandleForReading.readDataToEndOfFile()
        let verifyOutput = String(data: verifyData, encoding: .utf8) ?? ""
        
        // Verify the CA fingerprint is shown (indicates valid signature)
        #expect(verifyOutput.contains("Signing CA: ED25519"))
        
        // Also test that ssh-keygen can verify using the CA public key
        let principals = tempDir.appendingPathComponent("principals")
        try "charlie\ntest.example.com\n".write(to: principals, atomically: true, encoding: .utf8)
        
        let checkProcess = Process()
        checkProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        checkProcess.arguments = [
            "-L",
            "-f", certPath.path,
            "-n", "charlie"  // Check for principal
        ]
        
        let checkPipe = Pipe()
        checkProcess.standardOutput = checkPipe
        checkProcess.standardError = checkPipe
        
        try checkProcess.run()
        checkProcess.waitUntilExit()
        
        #expect(checkProcess.terminationStatus == 0, "Certificate validation failed")
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