import Testing
import Foundation
import Crypto
@testable import SwiftKeyGen

@Suite("KeyConverter Unit Tests", .tags(.unit))
struct KeyConversionUnitTests {

    // MARK: - Ed25519 PEM/PKCS#8

    @Test("Ed25519 toPEM emits PKCS#8 with seed tail")
    func testEd25519ToPEMStructure() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key

        let pem = try KeyConverter.toPEM(key: key)
        #expect(pem.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        #expect(pem.contains("\n"))
        #expect(pem.hasSuffix("-----END PRIVATE KEY-----"))

        // Extract base64 payload and decode
        let base64 = pem.pemBody(type: "PRIVATE KEY")
        #expect(base64 != nil)

        if let base64 = base64, let der = Data(base64Encoded: base64) {
            // Ed25519 helper encodes a minimal structure and appends the raw 32‑byte seed
            // Verify prefix bytes and that the DER ends with the private seed
            let expectedPrefix: [UInt8] = [
                0x30, 0x2e,             // SEQUENCE, len 46
                0x02, 0x01, 0x00,       // INTEGER 0 (version)
                0x30, 0x05, 0x06, 0x03, // SEQUENCE OID len=5, OID len=3
                0x2b, 0x65, 0x70,       // OID 1.3.101.112 (Ed25519)
                0x04, 0x22, 0x04, 0x20  // OCTET STRING len=34, inner OCTET STRING len=32
            ]
            #expect(der.count >= expectedPrefix.count + 32)
            #expect(Array(der.prefix(expectedPrefix.count)) == expectedPrefix)

            let seed = key.privateKeyData() // 32‑byte raw seed
            #expect(der.suffix(32) == seed)
        }
    }

    @Test("Ed25519 toPKCS8 returns same PEM bytes")
    func testEd25519ToPKCS8MatchesPEM() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let pem = try KeyConverter.toPEM(key: key)
        let pkcs8 = try KeyConverter.toPKCS8(key: key)
        let pkcs8String = String(decoding: pkcs8, as: UTF8.self)
        #expect(pkcs8String == pem)
        #expect(pkcs8String.contains("-----BEGIN PRIVATE KEY-----"))
    }

    // MARK: - RSA behavior

    @Test("RSA toPEM/PKCS8 and passphrase error", .tags(.rsa, .slow))
    func testRSAToPEMAndPKCS8() throws {
        // Use smaller size for speed while still valid
        let key = try RSAKeyGenerator.generate(bits: 1024)

        // Plain PEM
        let pem = try KeyConverter.toPEM(key: key)
        #expect(pem.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
        #expect(pem.contains("-----END RSA PRIVATE KEY-----"))

        // "PKCS8" path currently returns same PEM bytes for RSA
        let pkcs8 = try KeyConverter.toPKCS8(key: key)
        let pkcs8String = String(decoding: pkcs8, as: UTF8.self)
        #expect(pkcs8String == pem)

        // Supplying a passphrase for RSA is not supported by the converter
        #expect(throws: SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")) {
            _ = try KeyConverter.toPEM(key: key, passphrase: "secret")
        }
        #expect(throws: SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")) {
            _ = try KeyConverter.toPKCS8(key: key, passphrase: "secret")
        }
    }

    // MARK: - RFC4716

    @Test("RFC4716 default comment and round-trip")
    func testRFC4716DefaultComment() throws {
        var key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        key.comment = nil // ensure default is used

        let rfc = try KeyConverter.toRFC4716(key: key)
        #expect(rfc.hasPrefix("---- BEGIN SSH2 PUBLIC KEY ----"))
        #expect(rfc.contains("Comment: \""))

        // Parse back and validate
        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment?.isEmpty == false)
        #expect(parsed.comment?.contains("@") == true)
        #expect(parsed.data == key.publicKeyData())
    }

    // MARK: - exportKey()

    @Test("exportKey writes all formats and round-trips (Ed25519)")
    func testExportAllFormatsEd25519() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "export-test") as! Ed25519Key
        let tmp = FileManager.default.temporaryDirectory
        let base = tmp.appendingPathComponent("swiftkeygen_export_\(UUID().uuidString)").path

        let results = try KeyConverter.exportKey(
            key,
            formats: [.openssh, .pem, .pkcs8, .rfc4716],
            basePath: base
        )

        // Paths returned for each format
        #expect(results[.openssh] == base)
        #expect(results[.pem] == base + ".pem")
        #expect(results[.pkcs8] == base + ".p8")
        #expect(results[.rfc4716] == base + ".rfc")

        // Validate file contents
        let opensshData = try Data(contentsOf: URL(fileURLWithPath: base))
        let openssh = String(decoding: opensshData, as: UTF8.self)
        #expect(openssh.contains("BEGIN OPENSSH PRIVATE KEY"))
        #expect(openssh.contains("END OPENSSH PRIVATE KEY"))

        let pemString = try String(contentsOfFile: base + ".pem", encoding: .utf8)
        #expect(pemString.contains("-----BEGIN PRIVATE KEY-----"))

        let pkcs8String = try String(contentsOfFile: base + ".p8", encoding: .utf8)
        #expect(pkcs8String.contains("-----BEGIN PRIVATE KEY-----"))

        let rfc = try String(contentsOfFile: base + ".rfc", encoding: .utf8)
        #expect(rfc.hasPrefix("---- BEGIN SSH2 PUBLIC KEY ----"))

        // Parse OpenSSH back to a key and compare public component
        let parsedKey = try OpenSSHPrivateKey.parse(data: opensshData)
        #expect(parsedKey.publicKeyData() == key.publicKeyData())

        // Cleanup
        try? FileManager.default.removeItem(atPath: base)
        try? FileManager.default.removeItem(atPath: base + ".pem")
        try? FileManager.default.removeItem(atPath: base + ".p8")
        try? FileManager.default.removeItem(atPath: base + ".rfc")
    }

    @Test("exportKey errors when RSA encryption requested", .tags(.rsa, .slow))
    func testExportRSAEncryptedPEMUnsupported() throws {
        let rsa = try RSAKeyGenerator.generate(bits: 1024)
        let tmp = FileManager.default.temporaryDirectory
        let base = tmp.appendingPathComponent("swiftkeygen_export_rsa_\(UUID().uuidString)").path

        #expect(throws: SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")) {
            _ = try KeyConverter.exportKey(
                rsa,
                formats: [.pem, .pkcs8],
                basePath: base,
                passphrase: "secret"
            )
        }
    }
}
