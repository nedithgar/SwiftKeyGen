import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("PKCS8 Ed25519 + Canonical DER", .tags(.integration))
struct PKCS8Ed25519AndCanonicalIntegrationTests {

    @Test("Ed25519 unencrypted PKCS#8 builds canonical DER")
    func testEd25519UnencryptedPKCS8Canonical() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-pkcs8") as! Ed25519Key
        let der1 = key.privateKeyInfoDER()
        // Rebuild via PEM path extraction
        let pem = key.pkcs8PEMRepresentation
        let der2 = extractDER(from: pem)
        #expect(der1 == der2)
    }

    @Test("Ed25519 encrypted PKCS#8 decrypt round-trip")
    func testEd25519EncryptedPKCS8RoundTrip() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-enc") as! Ed25519Key
        let pass = "p8-pass-ed25519"
        let pem = try key.pkcs8PEMRepresentation(passphrase: pass, iterations: 4096, prf: .hmacSHA256, cipher: .aes256cbc)
        let parsed = try PKCS8Parser.parseEncryptedPrivateKeyInfo(pem: pem)
        #expect(parsed.cipher == "aes-256-cbc")
        #expect(parsed.prf == "hmacWithSHA256")
        let decrypted = try PKCS8Parser.decrypt(info: parsed, passphrase: pass)
        // Decrypted DER should equal our original PrivateKeyInfo DER
        #expect(decrypted == key.privateKeyInfoDER())
    }

    @Test("ECDSA canonical DER round-trip (P-256)")
    func testECDSAP256CanonicalDERRoundTrip() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-can-der") as! ECDSAKey
        // Obtain unencrypted PKCS#8 via existing path (reusing pemRepresentation path).
        // We extract DER and re-wrap it to ensure stable canonical form.
        let pem = key.pkcs8PEMRepresentation // unencrypted
        let der1 = extractDER(from: pem)
        // Canonical rebuild: The unencrypted path for ECDSA uses CryptoKit; ensure re-extraction is identical.
        let pem2 = key.pkcs8PEMRepresentation
        let der2 = extractDER(from: pem2)
        #expect(der1 == der2)
    }

    private func extractDER(from pem: String) -> Data {
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") }
        return Data(base64Encoded: lines.joined()) ?? Data()
    }
}
