import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("Certificate SSH-keygen Integration Tests", .tags(.integration))
struct CertificateSSHKeygenIntegrationTests {
    
    @Test("Verify Ed25519 certificate with ssh-keygen")
    func testSSHKeygenVerificationEd25519Certificate() throws {
    try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
        // Generate CA and user keys
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-ca@example.com") as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

        // Write CA private key
        let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
        let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
        try IntegrationTestSupporter.write(caPrivateKeyData, to: caPrivateKeyPath)

        // Write CA public key
        let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
        try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)

        // Write user public key
        let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
        try IntegrationTestSupporter.write(userKey.publicKeyString(), to: userPublicKeyPath)

        // Sign certificate
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "test-user",
            principals: ["charlie", "test.example.com"],
            certificateType: .user
        )

        // Write certificate
        let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
        try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)

        // Verify ssh-keygen can read certificate
        let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
        #expect(listResult.succeeded, "ssh-keygen failed to read certificate")
        #expect(listResult.stdout.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
        #expect(listResult.stdout.contains("Key ID: \"test-user\""))
        #expect(listResult.stdout.contains("charlie"))
        #expect(listResult.stdout.contains("test.example.com"))

        // Verify signing CA information
        let verifyResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
        #expect(verifyResult.stdout.contains("Signing CA: ED25519"))

        // Write principals file
        let principals = tempDir.appendingPathComponent("principals")
        try IntegrationTestSupporter.write("charlie\ntest.example.com\n", to: principals)

        // Validate certificate with principal
        let checkResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path, "-n", "charlie"])
        #expect(checkResult.succeeded, "Certificate validation failed")
    }
}

    @Test("Verify RSA certificate with ssh-keygen", .tags(.rsa))
    func testSSHKeygenVerificationRSACertificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca@example.com") as! RSAKey
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

            // Write CA private key
            let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
            let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
            try IntegrationTestSupporter.write(caPrivateKeyData, to: caPrivateKeyPath)

            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)

            // Write user public key
            let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
            try IntegrationTestSupporter.write(userKey.publicKeyString(), to: userPublicKeyPath)

            // Sign certificate
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-rsa-user",
                principals: ["alice", "rsa.example.com"],
                certificateType: .user,
                signatureAlgorithm: "rsa-sha2-512"
            )

            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)

            // Verify ssh-keygen can read certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen failed to read certificate")
            #expect(listResult.stdout.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
            #expect(listResult.stdout.contains("Key ID: \"test-rsa-user\""))
            #expect(listResult.stdout.contains("alice"))
            #expect(listResult.stdout.contains("rsa.example.com"))

            // Verify signing CA information
            let verifyResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(verifyResult.stdout.contains("Signing CA: RSA"))

            // Write principals file
            let principals = tempDir.appendingPathComponent("principals")
            try IntegrationTestSupporter.write("alice\nrsa.example.com\n", to: principals)

            // Validate certificate with principal
            let checkResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path, "-n", "alice"])
            #expect(checkResult.succeeded, "Certificate validation failed")
        }
    }
    
    @Test("Verify ECDSA P-256 certificate with ssh-keygen")
    func testSSHKeygenVerificationECDSAP256Certificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-p256-ca@example.com") as! ECDSAKey
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

            // Write CA private key
            let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
            let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
            try IntegrationTestSupporter.write(caPrivateKeyData, to: caPrivateKeyPath)

            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)

            // Write user public key
            let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
            try IntegrationTestSupporter.write(userKey.publicKeyString(), to: userPublicKeyPath)

            // Sign certificate
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-ecdsa-p256-user",
                principals: ["bob", "p256.example.com"],
                certificateType: .user
            )

            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)

            // Verify ssh-keygen can read certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen failed to read certificate")
            #expect(listResult.stdout.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
            #expect(listResult.stdout.contains("Key ID: \"test-ecdsa-p256-user\""))
            #expect(listResult.stdout.contains("bob"))
            #expect(listResult.stdout.contains("p256.example.com"))

            // Verify signing CA information
            let verifyResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(verifyResult.stdout.contains("Signing CA: ECDSA"))

            // Write principals file
            let principals = tempDir.appendingPathComponent("principals")
            try IntegrationTestSupporter.write("bob\np256.example.com\n", to: principals)

            // Validate certificate with principal
            let checkResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path, "-n", "bob"])
            #expect(checkResult.succeeded, "Certificate validation failed")
        }
    }
    
    @Test("Verify ECDSA P-384 certificate with ssh-keygen")
    func testSSHKeygenVerificationECDSAP384Certificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa-p384-ca@example.com") as! ECDSAKey
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

            // Write CA private key
            let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
            let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
            try IntegrationTestSupporter.write(caPrivateKeyData, to: caPrivateKeyPath)

            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)

            // Write user public key
            let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
            try IntegrationTestSupporter.write(userKey.publicKeyString(), to: userPublicKeyPath)

            // Sign certificate
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-ecdsa-p384-user",
                principals: ["diana", "p384.example.com"],
                certificateType: .user
            )

            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)

            // Verify ssh-keygen can read certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen failed to read certificate")
            #expect(listResult.stdout.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
            #expect(listResult.stdout.contains("Key ID: \"test-ecdsa-p384-user\""))
            #expect(listResult.stdout.contains("diana"))
            #expect(listResult.stdout.contains("p384.example.com"))

            // Verify signing CA information
            let verifyResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(verifyResult.stdout.contains("Signing CA: ECDSA"))

            // Write principals file
            let principals = tempDir.appendingPathComponent("principals")
            try IntegrationTestSupporter.write("diana\np384.example.com\n", to: principals)

            // Validate certificate with principal
            let checkResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path, "-n", "diana"])
            #expect(checkResult.succeeded, "Certificate validation failed")
        }
    }
    
    @Test("Verify ECDSA P-521 certificate with ssh-keygen")
    func testSSHKeygenVerificationECDSAP521Certificate() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate CA and user keys
            let caKey = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "ecdsa-p521-ca@example.com") as! ECDSAKey
            let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

            // Write CA private key
            let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
            let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
            try IntegrationTestSupporter.write(caPrivateKeyData, to: caPrivateKeyPath)

            // Write CA public key
            let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
            try IntegrationTestSupporter.write(caKey.publicKeyString(), to: caPublicKeyPath)

            // Write user public key
            let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
            try IntegrationTestSupporter.write(userKey.publicKeyString(), to: userPublicKeyPath)

            // Sign certificate
            let cert = try CertificateAuthority.signCertificate(
                publicKey: userKey,
                caKey: caKey,
                keyId: "test-ecdsa-p521-user",
                principals: ["eve", "p521.example.com"],
                certificateType: .user
            )

            // Write certificate
            let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
            try IntegrationTestSupporter.write(cert.publicKeyString(), to: certPath)

            // Verify ssh-keygen can read certificate
            let listResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(listResult.succeeded, "ssh-keygen failed to read certificate")
            #expect(listResult.stdout.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
            #expect(listResult.stdout.contains("Key ID: \"test-ecdsa-p521-user\""))
            #expect(listResult.stdout.contains("eve"))
            #expect(listResult.stdout.contains("p521.example.com"))

            // Verify signing CA information
            let verifyResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path])
            #expect(verifyResult.stdout.contains("Signing CA: ECDSA"))

            // Write principals file
            let principals = tempDir.appendingPathComponent("principals")
            try IntegrationTestSupporter.write("eve\np521.example.com\n", to: principals)

            // Validate certificate with principal
            let checkResult = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", certPath.path, "-n", "eve"])
            #expect(checkResult.succeeded, "Certificate validation failed")
        }
    }
}

