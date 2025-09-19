import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("KeyConversionManager Unit Tests", .tags(.unit))
struct KeyConversionManagerUnitTests {

    // MARK: - Helpers

    private func withTempDir(_ body: (URL) throws -> Void) throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try body(dir)
    }

    // MARK: - detectFormat

    @Test("detectFormat recognizes PEM/PKCS8 variants")
    func testDetectFormatPEMAndPKCS8() throws {
        // RSA public (PEM)
        let rsaPEM = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
        QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
        GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
        FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
        sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
        AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
        -----END RSA PUBLIC KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: rsaPEM) == .pem)

        // Generic PUBLIC KEY (PKCS8)
        let p256PKCS8 = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
        Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
        -----END PUBLIC KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: p256PKCS8) == .pkcs8)

        // PKCS8 private key
        let pkcs8Private = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIE3x+4K1r8F1i7+1sP5GZk1SB9QqW5EoFf3G3XhQd4zG
        -----END PRIVATE KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: pkcs8Private) == .pkcs8)

        // Unknown content
        #expect(throws: SSHKeyError.unsupportedOperation("Unable to detect key format")) {
            _ = try KeyConversionManager.detectFormat(from: "not a key")
        }
    }

    @Test("detectFormat: OpenSSH public/private and RFC4716")
    func testDetectFormatOpenSSHAndRFC() throws {
        // OpenSSH public
        let ed = try SwiftKeyGen.generateKey(type: .ed25519, comment: "t");
        let openssh = ed.publicKeyString()
        #expect(try KeyConversionManager.detectFormat(from: openssh) == .openssh)

        // RFC4716
        let rfc = try KeyConverter.toRFC4716(key: ed)
        #expect(try KeyConversionManager.detectFormat(from: rfc) == .rfc4716)

        // OpenSSH private markers
        let opensshPriv = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        AAAAB3NzaC1yc2EAAAADAQABAAABAQDL
        -----END OPENSSH PRIVATE KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: opensshPriv) == .openssh)
    }

    // MARK: - convertKey success paths

    @Test("convertKey auto-detects OpenSSH -> RFC4716")
    func testConvertOpenSSHToRFC4716AutoDetect() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@test")
        let pub = key.publicKeyString()

        try withTempDir { dir in
            let inFile = dir.appendingPathComponent("in.pub")
            let outFile = dir.appendingPathComponent("out.rfc")
            try pub.write(to: inFile, atomically: true, encoding: .utf8)

            let options = KeyConversionManager.ConversionOptions(
                toFormat: .rfc4716,
                fromFormat: nil, // auto-detect
                input: inFile.path,
                output: outFile.path
            )
            try KeyConversionManager.convertKey(options: options)

            let rfc = try String(contentsOf: outFile, encoding: .utf8)
            #expect(PublicKeyParser.isRFC4716Format(rfc))

            let parsed = try PublicKeyParser.parseRFC4716(rfc)
            #expect(parsed.type == key.keyType)
            #expect(parsed.data == key.publicKeyData())
        }
    }

    @Test("convertKey auto-detects RFC4716 -> OpenSSH")
    func testConvertRFC4716ToOpenSSHAutoDetect() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "c1")
        let rfc = try KeyConverter.toRFC4716(key: key)

        try withTempDir { dir in
            let inFile = dir.appendingPathComponent("in.rfc")
            let outFile = dir.appendingPathComponent("out.pub")
            try rfc.write(to: inFile, atomically: true, encoding: .utf8)

            let options = KeyConversionManager.ConversionOptions(
                toFormat: .openssh,
                fromFormat: nil,
                input: inFile.path,
                output: outFile.path
            )
            try KeyConversionManager.convertKey(options: options)

            let out = try String(contentsOf: outFile, encoding: .utf8)
            #expect(out.hasPrefix("ecdsa-sha2-nistp256 "))

            let (parsedType, parsedData, _) = try PublicKeyParser.parsePublicKey(out)
            #expect(parsedType == key.keyType)
            #expect(parsedData == key.publicKeyData())
        }
    }

    @Test("convertKey auto-detects PEM/PKCS8 -> OpenSSH")
    func testConvertPEMAndPKCS8AutoDetect() throws {
        // RSA PEM public key (constant)
        let rsaPEM = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
        QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
        GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
        FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
        sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
        AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
        -----END RSA PUBLIC KEY-----
        """

        // ECDSA P-256 PKCS8 public key (constant)
        let p256PKCS8 = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
        Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
        -----END PUBLIC KEY-----
        """

        try withTempDir { dir in
            // RSA
            let inRSA = dir.appendingPathComponent("rsa.pem")
            let outRSA = dir.appendingPathComponent("rsa.pub")
            try rsaPEM.write(to: inRSA, atomically: true, encoding: .utf8)
            var options = KeyConversionManager.ConversionOptions(toFormat: .openssh, input: inRSA.path, output: outRSA.path)
            try KeyConversionManager.convertKey(options: options)
            let out1 = try String(contentsOf: outRSA, encoding: .utf8)
            #expect(out1.hasPrefix("ssh-rsa "))

            // ECDSA P-256 PKCS8
            let inP256 = dir.appendingPathComponent("p256.p8")
            let outP256 = dir.appendingPathComponent("p256.pub")
            try p256PKCS8.write(to: inP256, atomically: true, encoding: .utf8)
            options = KeyConversionManager.ConversionOptions(toFormat: .openssh, input: inP256.path, output: outP256.path)
            try KeyConversionManager.convertKey(options: options)
            let out2 = try String(contentsOf: outP256, encoding: .utf8)
            #expect(out2.hasPrefix("ecdsa-sha2-nistp256 "))
        }
    }

    // MARK: - convertKey error paths

    @Test("convertKey rejects OpenSSH private key")
    func testConvertRejectsOpenSSHPrivate() throws {
        let opensshPriv = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        AAAAB3NzaC1yc2EAAAADAQABAAABAQDL
        -----END OPENSSH PRIVATE KEY-----
        """

        try withTempDir { dir in
            let inFile = dir.appendingPathComponent("in")
            let outFile = dir.appendingPathComponent("out.rfc")
            try opensshPriv.write(to: inFile, atomically: true, encoding: .utf8)

            let options = KeyConversionManager.ConversionOptions(
                toFormat: .rfc4716,
                input: inFile.path,
                output: outFile.path
            )

            #expect(throws: SSHKeyError.unsupportedOperation("OpenSSH private key conversion not yet implemented")) {
                try KeyConversionManager.convertKey(options: options)
            }
        }
    }

    @Test("convertKey to PEM/PKCS8 requires private key")
    func testConvertToPEMOrPKCS8Unsupported() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let pub = key.publicKeyString()

        try withTempDir { dir in
            let inFile = dir.appendingPathComponent("in.pub")
            try pub.write(to: inFile, atomically: true, encoding: .utf8)

            var options = KeyConversionManager.ConversionOptions(
                toFormat: .pem,
                input: inFile.path,
                output: dir.appendingPathComponent("out.pem").path
            )
            #expect(throws: SSHKeyError.unsupportedOperation("PEM/PKCS8 export requires private key")) {
                try KeyConversionManager.convertKey(options: options)
            }

            options = KeyConversionManager.ConversionOptions(
                toFormat: .pkcs8,
                input: inFile.path,
                output: dir.appendingPathComponent("out.p8").path
            )
            #expect(throws: SSHKeyError.unsupportedOperation("PEM/PKCS8 export requires private key")) {
                try KeyConversionManager.convertKey(options: options)
            }
        }
    }

    @Test("convertKey unsupported/invalid PEM content")
    func testConvertUnsupportedOrInvalidPEM() throws {
        // Unsupported PEM type
        let unknownPEM = """
        -----BEGIN FOO BAR-----
        AAAA
        -----END FOO BAR-----
        """

        // FromFormat specified as PEM forces PEM path
        try withTempDir { dir in
            let in1 = dir.appendingPathComponent("foo.pem")
            try unknownPEM.write(to: in1, atomically: true, encoding: .utf8)
            let options1 = KeyConversionManager.ConversionOptions(
                toFormat: .openssh,
                fromFormat: .pem,
                input: in1.path,
                output: dir.appendingPathComponent("out1.pub").path
            )
            #expect(throws: SSHKeyError.unsupportedOperation("Unsupported PEM type: FOO BAR")) {
                try KeyConversionManager.convertKey(options: options1)
            }

            // Invalid content while claiming PEM
            let in2 = dir.appendingPathComponent("notpem.pem")
            try "ssh-ed25519 AAAA".write(to: in2, atomically: true, encoding: .utf8)
            let options2 = KeyConversionManager.ConversionOptions(
                toFormat: .openssh,
                fromFormat: .pem,
                input: in2.path,
                output: dir.appendingPathComponent("out2.pub").path
            )
            #expect(throws: SSHKeyError.invalidFormat) {
                try KeyConversionManager.convertKey(options: options2)
            }
        }
    }

    // MARK: - batchConvert

    @Test("batchConvert builds output names and aggregates results")
    func testBatchConvertMixedSuccess() throws {
        // Prepare three files: valid RSA PEM, valid RFC4716, and invalid
        let rsaPEM = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
        QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
        GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
        FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
        sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
        AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
        -----END RSA PUBLIC KEY-----
        """
        let ed = try SwiftKeyGen.generateKey(type: .ed25519)
        let rfc = try KeyConverter.toRFC4716(key: ed)

        try withTempDir { dir in
            let pemFile = dir.appendingPathComponent("rsa.pem")
            let rfcFile = dir.appendingPathComponent("key.rfc")
            let badFile = dir.appendingPathComponent("bad.txt")
            try rsaPEM.write(to: pemFile, atomically: true, encoding: .utf8)
            try rfc.write(to: rfcFile, atomically: true, encoding: .utf8)
            try "not a key".write(to: badFile, atomically: true, encoding: .utf8)

            let opts = KeyConversionManager.ConversionOptions(
                toFormat: .openssh,
                output: dir.appendingPathComponent("dummy").path // switched per-file in batch
            )

            let results = try KeyConversionManager.batchConvert(files: [pemFile.path, rfcFile.path, badFile.path], options: opts)
            #expect(results.count == 3)

            // Output names computed from input base + .pub
            for result in results {
                #expect(result.output.hasSuffix(".pub"))
                if result.success {
                    #expect(FileManager.default.fileExists(atPath: result.output))
                    let content = try String(contentsOfFile: result.output, encoding: .utf8)
                    #expect(content.split(separator: " ").first?.hasPrefix("ssh-") == true || content.hasPrefix("ecdsa-"))
                } else {
                    #expect(result.error != nil)
                }
            }
        }
    }
}
