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

    @Test("RFC4716 export uses provided comment")
    func testRFC4716ExportWithComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key

        let rfc = try KeyConverter.toRFC4716(key: key)
        #expect(rfc.contains("---- BEGIN SSH2 PUBLIC KEY ----"))
        #expect(rfc.contains("---- END SSH2 PUBLIC KEY ----"))
        #expect(rfc.contains("Comment: \"test@example.com\""))

        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "test@example.com")
        #expect(parsed.data == key.publicKeyData())
    }

    @Test("RFC4716 explicit import")
    func testRFC4716ImportLiteral() throws {
        let rfc4716String = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        Comment: "user@host"
        AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
        ---- END SSH2 PUBLIC KEY ----
        """

        let parsed = try PublicKeyParser.parseRFC4716(rfc4716String)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "user@host")
        try PublicKeyParser.validatePublicKeyData(parsed.data, type: parsed.type)
    }

    @Test("RFC4716 base64 lines wrapped at 70", .tags(.rsa, .slow))
    func testRFC4716LongLinesRSA() throws {
        // RSA public key produces a long base64 payload
        let rsa = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-test") as! RSAKey
        let rfc = try KeyConverter.toRFC4716(key: rsa)

        let lines = rfc.split(separator: "\n")
        for (idx, line) in lines.enumerated() {
            if idx == 0 || idx == lines.count - 1 || line.hasPrefix("Comment:") { continue }
            #expect(line.count <= 70)
        }

        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .rsa)
        #expect(parsed.data == rsa.publicKeyData())
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

    // MARK: - Detection and parsing helpers

    @Test("Format detection: OpenSSH pub, RFC4716, OpenSSH private")
    func testFormatDetection() throws {
        // OpenSSH public key (ed25519) literal
        let opensshPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"
        #expect(try KeyConversionManager.detectFormat(from: opensshPub) == .openssh)

        // RFC4716
        let rfc = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
        ---- END SSH2 PUBLIC KEY ----
        """
        #expect(try KeyConversionManager.detectFormat(from: rfc) == .rfc4716)

        // OpenSSH private key markers
        let opensshPrivate = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        -----END OPENSSH PRIVATE KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: opensshPrivate) == .openssh)
    }

    @Test("PublicKeyParser.parseAnyFormat for OpenSSH and RFC4716")
    func testParseAnyFormat() throws {
        // Ed25519
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-key") as! Ed25519Key
        let openssh = key.publicKeyString()
        let parsedOpenSSH = try PublicKeyParser.parseAnyFormat(openssh)
        #expect(parsedOpenSSH.data == key.publicKeyData())

        let rfc = try KeyConverter.toRFC4716(key: key)
        let parsedRFC = try PublicKeyParser.parseAnyFormat(rfc)
        #expect(parsedRFC.data == key.publicKeyData())
    }

    @Test("Stdin/stdout helpers: filename and file read")
    func testStdinStdoutSupport() throws {
        #expect(KeyFileManager.STDIN_STDOUT_FILENAME == "-")

        let testData = Data("test data".utf8)
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("test_\(UUID().uuidString)")
        try testData.write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let read = try KeyFileManager.readKeyData(from: tmp.path)
        #expect(read == testData)
    }

    @Test("Batch convert OpenSSH pub -> RFC4716")
    func testBatchConversion() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        var inputFiles: [String] = []
        for i in 1...3 {
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-\(i)") as! Ed25519Key
            let path = tempDir.appendingPathComponent("key\(i).pub").path
            try key.publicKeyString().write(toFile: path, atomically: true, encoding: .utf8)
            inputFiles.append(path)
        }

        let options = KeyConversionManager.ConversionOptions(
            toFormat: .rfc4716,
            fromFormat: .openssh,
            output: tempDir.path
        )

        let results = try KeyConversionManager.batchConvert(files: inputFiles, options: options)
        #expect(results.count == 3)

        for result in results {
            #expect(result.success == true)
            #expect(result.error == nil)
            let out = try String(contentsOfFile: result.output, encoding: .utf8)
            #expect(PublicKeyParser.isRFC4716Format(out))
        }
    }

    @Test("RFC4716 conversion across all key types", .tags(.rsa, .slow))
    func testAllKeyTypesRFC4716() throws {
        // Ed25519
        let ed = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-test") as! Ed25519Key
        let edRFC = try KeyConverter.toRFC4716(key: ed)
        let edParsed = try PublicKeyParser.parseRFC4716(edRFC)
        #expect(edParsed.type == .ed25519)

        // RSA
        let rsa = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-test") as! RSAKey
        let rsaRFC = try KeyConverter.toRFC4716(key: rsa)
        let rsaParsed = try PublicKeyParser.parseRFC4716(rsaRFC)
        #expect(rsaParsed.type == .rsa)

        // ECDSA P-256
        let e256 = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa256-test") as! ECDSAKey
        let e256RFC = try KeyConverter.toRFC4716(key: e256)
        let e256Parsed = try PublicKeyParser.parseRFC4716(e256RFC)
        #expect(e256Parsed.type == .ecdsa256)

        // ECDSA P-384
        let e384 = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa384-test") as! ECDSAKey
        let e384RFC = try KeyConverter.toRFC4716(key: e384)
        let e384Parsed = try PublicKeyParser.parseRFC4716(e384RFC)
        #expect(e384Parsed.type == .ecdsa384)

        // ECDSA P-521
        let e521 = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "ecdsa521-test") as! ECDSAKey
        let e521RFC = try KeyConverter.toRFC4716(key: e521)
        let e521Parsed = try PublicKeyParser.parseRFC4716(e521RFC)
        #expect(e521Parsed.type == .ecdsa521)
    }
}
