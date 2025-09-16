import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Suite("ECDSA SEC1 Unit Tests", .tags(.unit))
struct ECDSASEC1UnitTests {
    // MARK: - SEC1 DER structure tests
    @Test
    func sec1DERStructure_P256() throws {
        let key = P256.Signing.PrivateKey()
        let der = key.sec1DERRepresentation

        var parser = ASN1Parser(data: der)
        #expect(der.first == 0x30) // SEQUENCE
        parser.offset += 1
        let _ = try parser.parseLength()

        let versionOpt = try parser.parseInteger()
        #expect(versionOpt != nil)
        let version = versionOpt!
        #expect(version.count == 1 && version[0] == 1)

        let privateKeyOctetOpt = try parser.parseOctetString()
        #expect(privateKeyOctetOpt != nil)
        let privateKeyOctet = privateKeyOctetOpt!
        #expect(privateKeyOctet == key.rawRepresentation)

        #expect(parser.offset < der.count && der[parser.offset] == 0xA0)
        parser.offset += 1
        let tag0Len = try parser.parseLength()
        let tag0End = parser.offset + tag0Len
        let p256OIDOpt = try parser.parseObjectIdentifier()
        #expect(p256OIDOpt != nil)
        let p256OID = p256OIDOpt!
        #expect(p256OID == Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]))
        parser.offset = tag0End

        #expect(parser.offset < der.count && der[parser.offset] == 0xA1)
        parser.offset += 1
        let _ = try parser.parseLength()
        let publicKeyBitStringOpt = try parser.parseBitString()
        #expect(publicKeyBitStringOpt != nil)
        let publicKeyBitString = publicKeyBitStringOpt!
        #expect(publicKeyBitString == key.publicKey.x963Representation)
    }

    @Test
    func sec1DERStructure_P384() throws {
        let key = P384.Signing.PrivateKey()
        let der = key.sec1DERRepresentation

        var parser = ASN1Parser(data: der)
        #expect(der.first == 0x30)
        parser.offset += 1
        let _ = try parser.parseLength()

        let versionOpt = try parser.parseInteger()
        #expect(versionOpt != nil)
        let version = versionOpt!
        #expect(version.count == 1 && version[0] == 1)

        let privateKeyOctetOpt = try parser.parseOctetString()
        #expect(privateKeyOctetOpt != nil)
        let privateKeyOctet = privateKeyOctetOpt!
        #expect(privateKeyOctet == key.rawRepresentation)

        #expect(parser.offset < der.count && der[parser.offset] == 0xA0)
        parser.offset += 1
        let tag0Len = try parser.parseLength()
        let tag0End = parser.offset + tag0Len
        let p384OIDOpt = try parser.parseObjectIdentifier()
        #expect(p384OIDOpt != nil)
        let p384OID = p384OIDOpt!
        #expect(p384OID == Data([0x2B, 0x81, 0x04, 0x00, 0x22]))
        parser.offset = tag0End

        #expect(parser.offset < der.count && der[parser.offset] == 0xA1)
        parser.offset += 1
        let _ = try parser.parseLength()
        let publicKeyBitStringOpt = try parser.parseBitString()
        #expect(publicKeyBitStringOpt != nil)
        let publicKeyBitString = publicKeyBitStringOpt!
        #expect(publicKeyBitString == key.publicKey.x963Representation)
    }

    @Test
    func sec1DERStructure_P521() throws {
        let key = P521.Signing.PrivateKey()
        let der = key.sec1DERRepresentation

        var parser = ASN1Parser(data: der)
        #expect(der.first == 0x30)
        parser.offset += 1
        let _ = try parser.parseLength()

        let versionOpt = try parser.parseInteger()
        #expect(versionOpt != nil)
        let version = versionOpt!
        #expect(version.count == 1 && version[0] == 1)

        let privateKeyOctetOpt = try parser.parseOctetString()
        #expect(privateKeyOctetOpt != nil)
        let privateKeyOctet = privateKeyOctetOpt!
        #expect(privateKeyOctet == key.rawRepresentation)

        #expect(parser.offset < der.count && der[parser.offset] == 0xA0)
        parser.offset += 1
        let tag0Len = try parser.parseLength()
        let tag0End = parser.offset + tag0Len
        let p521OIDOpt = try parser.parseObjectIdentifier()
        #expect(p521OIDOpt != nil)
        let p521OID = p521OIDOpt!
        #expect(p521OID == Data([0x2B, 0x81, 0x04, 0x00, 0x23]))
        parser.offset = tag0End

        #expect(parser.offset < der.count && der[parser.offset] == 0xA1)
        parser.offset += 1
        let _ = try parser.parseLength()
        let publicKeyBitStringOpt = try parser.parseBitString()
        #expect(publicKeyBitStringOpt != nil)
        let publicKeyBitString = publicKeyBitStringOpt!
        #expect(publicKeyBitString == key.publicKey.x963Representation)
    }

    // MARK: - PEM wrapping tests
    @Test
    func sec1PEMWrapsDER_P256() throws {
        let key = try ECDSAKeyGenerator.generateP256(comment: "wrap-test")
        let pem = key.sec1PEMRepresentation

        let (type, payload) = try PEMParser.parsePEM(pem)
        #expect(type == "EC PRIVATE KEY")

        // Compute expected DER directly from underlying P-256 key
        guard key.keyType == .ecdsa256 else {
            Issue.record("Unexpected curve type: \(key.keyType)")
            return
        }
        guard case let .p256(p256) = key.privateKeyStorage else {
            Issue.record("Unexpected privateKeyStorage backing for P-256")
            return
        }
        let expectedDER = p256.sec1DERRepresentation
        #expect(payload == expectedDER)
    }

    // MARK: - Encrypted SEC1 PEM round-trip tests
    @Test
    func encryptedSEC1PEMRoundTrip_AES128CBC() throws {
        let original = try ECDSAKeyGenerator.generateP384(comment: "enc-aes128")
        let passphrase = "p@ssw0rd-AES128"

        let encryptedPEM = try original.sec1PEMRepresentation(passphrase: passphrase, cipher: .aes128CBC)
        let parsed = try PEMParser.parseECDSAPrivateKey(encryptedPEM, passphrase: passphrase)

        #expect(parsed.keyType == original.keyType)
        #expect(parsed.privateKeyData() == original.privateKeyData())
        #expect(parsed.publicKeyData() == original.publicKeyData())
    }

    @Test
    func encryptedSEC1PEMRoundTrip_3DES() throws {
        let original = try ECDSAKeyGenerator.generateP521(comment: "enc-3des")
        let passphrase = "p@ssw0rd-3DES"

        let encryptedPEM = try original.sec1PEMRepresentation(passphrase: passphrase, cipher: .des3CBC)
        let parsed = try PEMParser.parseECDSAPrivateKey(encryptedPEM, passphrase: passphrase)

        #expect(parsed.keyType == original.keyType)
        #expect(parsed.privateKeyData() == original.privateKeyData())
        #expect(parsed.publicKeyData() == original.publicKeyData())
    }

    // MARK: - Consolidated tests from FormatConversion/ECDSASEC1Tests.swift
    @Test
    func ecdsaSEC1PEMHeadersForCurves() throws {
        let p256Key = try ECDSAKeyGenerator.generateP256(comment: "test-p256")
        let p384Key = try ECDSAKeyGenerator.generateP384(comment: "test-p384")
        let p521Key = try ECDSAKeyGenerator.generateP521(comment: "test-p521")

        let p256PEM = p256Key.sec1PEMRepresentation
        #expect(p256PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
        #expect(p256PEM.contains("-----END EC PRIVATE KEY-----"))
        #expect(!p256PEM.contains("-----BEGIN PRIVATE KEY-----"))

        let p384PEM = p384Key.sec1PEMRepresentation
        #expect(p384PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
        #expect(p384PEM.contains("-----END EC PRIVATE KEY-----"))
        #expect(!p384PEM.contains("-----BEGIN PRIVATE KEY-----"))

        let p521PEM = p521Key.sec1PEMRepresentation
        #expect(p521PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
        #expect(p521PEM.contains("-----END EC PRIVATE KEY-----"))
        #expect(!p521PEM.contains("-----BEGIN PRIVATE KEY-----"))
    }

    @Test
    func ecdsaFormatCompatibilityPEMvsPKCS8() throws {
        let key = try ECDSAKeyGenerator.generateP256(comment: "format-test")
        let sec1PEM = key.sec1PEMRepresentation
        let pkcs8PEM = key.pkcs8PEMRepresentation

        #expect(sec1PEM.contains("BEGIN EC PRIVATE KEY"))
        #expect(pkcs8PEM.contains("BEGIN PRIVATE KEY"))
        #expect(sec1PEM != pkcs8PEM)
    }

    @Test
    func ecdsaKeyConverterFormatSelection() throws {
        let key = try ECDSAKeyGenerator.generateP384()
        let pemString = try KeyConverter.toPEM(key: key)
        #expect(pemString.contains("-----BEGIN EC PRIVATE KEY-----"))
        #expect(pemString.contains("-----END EC PRIVATE KEY-----"))

        let pkcs8Data = try KeyConverter.toPKCS8(key: key)
        let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
        #expect(pkcs8String.contains("-----BEGIN PRIVATE KEY-----"))
        #expect(pkcs8String.contains("-----END PRIVATE KEY-----"))
    }
}

@Suite("ECDSA SEC1 Integration Tests", .tags(.integration))
struct ECDSASEC1IntegrationTests {
    @Test
    func ecdsaExportFormatsMatchSSHKeygen() throws {
        let key = try ECDSAKeyGenerator.generateP521()
        let formats: Set<KeyFormat> = [.pem, .pkcs8]
        let tempDir = FileManager.default.temporaryDirectory
        let basePath = tempDir.appendingPathComponent("test_ecdsa_\(UUID().uuidString)").path

        let results = try KeyConverter.exportKey(key, formats: formats, basePath: basePath)

        if let pemPath = results[.pem] {
            let pemContent = try String(contentsOfFile: pemPath, encoding: .utf8)
            #expect(pemContent.contains("BEGIN EC PRIVATE KEY"))
        } else {
            Issue.record("PEM format not exported")
        }

        if let pkcs8Path = results[.pkcs8] {
            let pkcs8Content = try String(contentsOfFile: pkcs8Path, encoding: .utf8)
            #expect(pkcs8Content.contains("BEGIN PRIVATE KEY"))
        } else {
            Issue.record("PKCS8 format not exported")
        }

        // Cleanup
        try? FileManager.default.removeItem(atPath: basePath + ".pem")
        try? FileManager.default.removeItem(atPath: basePath + ".p8")
    }
}
