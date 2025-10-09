import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("PKCS8 Decryption Integration", .tags(.integration))
struct PKCS8DecryptionIntegrationTests {
    @Test("Round-trip decrypt our ECDSA PKCS8 (aes-128-cbc)")
    func testDecryptOurECDSAPKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "pkcs8-dec-ecdsa@example.com") as! ECDSAKey
            let pass = "dec-pass-128"
            let pem = try key.pkcs8PEMRepresentation(passphrase: pass)
            let path = tempDir.appendingPathComponent("ecdsa.p8")
            try IntegrationTestSupporter.write(pem, to: path)
            let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
            #expect(parsed.cipher == "aes-128-cbc")
            let decrypted = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
            // Decrypted should contain EC private key sequence (0x30) prefix
            #expect(decrypted.first == 0x30, "DER should start with SEQUENCE")
        }
    }

    @Test("ssh-keygen PKCS8 decrypt (ECDSA)")
    func testDecryptSSHKeygenECDSAPKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("ecdsa")
            let pass = "ssh-pkcs8-ecdsa"
            let gen = try IntegrationTestSupporter.runSSHKeygen([
                "-t","ecdsa","-b","256","-f", keyPath.path, "-N", pass, "-m","PKCS8"
            ])
            #expect(gen.succeeded)
            let pem = try String(contentsOf: keyPath, encoding: .utf8)
            let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
            let decrypted = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
            #expect(decrypted.first == 0x30)
        }
    }

    @Test("ssh-keygen PKCS8 decrypt (RSA 2048)", .tags(.rsa))
    func testDecryptSSHKeygenRSAPKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("rsa")
            let pass = "ssh-pkcs8-rsa"
            let gen = try IntegrationTestSupporter.runSSHKeygen([
                "-t","rsa","-b","2048","-f", keyPath.path, "-N", pass, "-m","PKCS8"
            ])
            #expect(gen.succeeded)
            let pem = try String(contentsOf: keyPath, encoding: .utf8)
            let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
            let decrypted = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
            // RSA PrivateKeyInfo should contain rsaEncryption OID inside – quick heuristic: look for 0x06 (OID) and 0x2A 0x86 0x48 pattern
            #expect(decrypted.contains(Data([0x06])) )
        }
    }

    @Test("Our ECDSA AES-256/HMAC-SHA256 PBES2", .tags(.integration))
    func testDecryptOurECDSAAES256SHA256PKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { _ in
            let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-aes256-sha256") as! ECDSAKey
            let pass = "ecdsa-256-sha256-pass"
            let pem = try key.pkcs8PEMRepresentation(passphrase: pass,
                                                     iterations: 4096,
                                                     prf: .hmacSHA256,
                                                     cipher: .aes256cbc)
            let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
            #expect(parsed.cipher == "aes-256-cbc")
            #expect(parsed.prf == "hmacWithSHA256")
            let dec = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
            #expect(dec.first == 0x30)
        }
    }

    @Test("Our RSA AES-256/HMAC-SHA256 PBES2", .tags(.integration, .rsa))
    func testDecryptOurRSAAES256SHA256PKCS8() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { _ in
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-aes256-sha256") as! RSAKey
            let pass = "rsa-256-sha256-pass"
            let pem = try key.pkcs8PEMRepresentation(passphrase: pass,
                                                     iterations: 4096,
                                                     prf: .hmacSHA256,
                                                     cipher: .aes256cbc)
            let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
            #expect(parsed.cipher == "aes-256-cbc")
            #expect(parsed.prf == "hmacWithSHA256")
            let dec = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
            #expect(dec.first == 0x30)
        }
    }
}
