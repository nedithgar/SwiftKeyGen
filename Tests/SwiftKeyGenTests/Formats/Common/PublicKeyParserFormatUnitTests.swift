import Testing
import Foundation
@testable import SwiftKeyGen

// MARK: - Unified PublicKeyParser Tests (OpenSSH + RFC4716, non-RSA fast path)
// This suite consolidates prior OpenSSH-focused tests (moved from Utilities/) and existing
// RFC4716 format tests into a single format-centric location. RSA-specific (slower) cases
// are separated into their own suite below and tagged `.rsa` to allow selective execution.
@Suite("PublicKeyParser Format Tests", .tags(.unit))
struct PublicKeyParserFormatUnitTests {
    // MARK: Format Detection
    @Test("isRFC4716Format detects markers")
    func testIsRFC4716Format() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "fmt-test")
        let rfc = try KeyConverter.toRFC4716(key: key)
        #expect(PublicKeyParser.isRFC4716Format(rfc))
        let openssh = key.publicKeyString()
        #expect(!PublicKeyParser.isRFC4716Format(openssh))
    }

    @Test("detectKeyType works for RFC4716")
    func testDetectKeyTypeFromRFC4716() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "detect-rfc")
        let rfc = try KeyConverter.toRFC4716(key: key)
        let detected = PublicKeyParser.detectKeyType(from: rfc)
        #expect(detected == .ed25519)
    }

    @Test("detectKeyTypes OpenSSH non-RSA")
    func testDetectKeyTypesOpenSSHNonRSA() throws {
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]
        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType, comment: "detect")
            let publicKeyString = key.publicKeyString()
            let detectedType = PublicKeyParser.detectKeyType(from: publicKeyString)
            #expect(detectedType == keyType, "Expected detection for \(keyType)")
        }
    }

    // MARK: Parsing (OpenSSH + RFC4716)
    @Test("parseRFC4716 preserves comment")
    func testParseRFC4716PreservesComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@host") as! Ed25519Key
        let rfc = try KeyConverter.toRFC4716(key: key)
        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.data == key.publicKeyData())
        #expect(parsed.comment == "user@host")
    }

    @Test("parseOpenSSH with comment")
    func testParseOpenSSHWithComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@host") as! Ed25519Key
        let publicKeyString = key.publicKeyString()
        let (type, data, comment) = try PublicKeyParser.parsePublicKey(publicKeyString)
        #expect(type == .ed25519)
        #expect(data == key.publicKeyData())
        #expect(comment == "user@host")
    }

    @Test("parseOpenSSH without comment")
    func testParseOpenSSHWithoutComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let publicKeyString = key.publicKeyString()
        let (type, _, comment) = try PublicKeyParser.parsePublicKey(publicKeyString)
        #expect(type == .ed25519)
        #expect(comment == nil)
    }

    @Test("parseAnyFormat routes correctly")
    func testParseAnyFormat() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "anyfmt") as! Ed25519Key
        // OpenSSH
        let openssh = key.publicKeyString()
        let parsedOpen = try PublicKeyParser.parseAnyFormat(openssh)
        #expect(parsedOpen.type == .ed25519)
        #expect(parsedOpen.data == key.publicKeyData())
        #expect(parsedOpen.comment == "anyfmt")
        // RFC4716
        let rfc = try KeyConverter.toRFC4716(key: key)
        let parsedRFC = try PublicKeyParser.parseAnyFormat(rfc)
        #expect(parsedRFC.type == .ed25519)
        #expect(parsedRFC.data == key.publicKeyData())
        #expect(parsedRFC.comment == "anyfmt")
    }

    // MARK: Validation (non-RSA fast path)
    @Test("validatePublicKeyData for non-RSA key types")
    func testValidatePublicKeyDataNonRSA() throws {
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]
        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let data = key.publicKeyData()
            try PublicKeyParser.validatePublicKeyData(data, type: keyType)
        }
    }

    @Test("validate rejects extra trailing bytes")
    func testValidateRejectsExtraData() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        var data = key.publicKeyData()
        data.append(0)
        do {
            try PublicKeyParser.validatePublicKeyData(data, type: .ed25519)
            Issue.record("Expected invalidKeyData for extra trailing bytes")
        } catch SSHKeyError.invalidKeyData { /* expected */ }
    }

    @Test("ECDSA curve mismatch invalid")
    func testECDSACurveMismatchInvalid() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let publicData = key.publicKeyData()
        var dec = SSHDecoder(data: publicData)
        _ = try dec.decodeString() // type
        _ = try dec.decodeString() // curve (actual)
        let point = try dec.decodeData()
        var enc = SSHEncoder()
        enc.encodeString(KeyType.ecdsa256.rawValue)
        enc.encodeString("nistp384") // wrong curve
        enc.encodeData(point)
        let mutated = enc.encode()
        do {
            try PublicKeyParser.validatePublicKeyData(mutated, type: .ecdsa256)
            Issue.record("Expected invalidKeyData for curve mismatch")
        } catch SSHKeyError.invalidKeyData { /* expected */ }
    }

    @Test("invalid raw key data rejected")
    func testInvalidKeyData() throws {
        let invalidData = Data("invalid".utf8)
        do {
            try PublicKeyParser.validatePublicKeyData(invalidData, type: .ed25519)
            Issue.record("Expected validation to fail")
        } catch SSHKeyError.invalidKeyData { /* expected */ }
    }

    @Test("mismatched embedded key type rejects")
    func testMismatchedEmbeddedKeyType() throws {
        let ed25519 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let data = ed25519.publicKeyData()
        // Attempt to validate Ed25519 blob as RSA should fail.
        do {
            try PublicKeyParser.validatePublicKeyData(data, type: .rsa)
            Issue.record("Expected invalidKeyData for mismatched type")
        } catch SSHKeyError.invalidKeyData { /* expected */ }
    }

    // MARK: Fingerprints (non-RSA key types)
    @Test("fingerprints across hash algorithms (OpenSSH)")
    func testFingerprintsAllHashesOpenSSHNonRSA() throws {
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]
        let hashes: [HashFunction] = [.sha256, .sha512, .md5]
        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let openssh = key.publicKeyString()
            let directSHA256 = key.fingerprint(hash: .sha256, format: .base64)
            let parsedSHA256 = try PublicKeyParser.fingerprint(from: openssh, hash: .sha256)
            #expect(directSHA256 == parsedSHA256)
            for hash in hashes {
                let fp = try PublicKeyParser.fingerprint(from: openssh, hash: hash)
                switch hash {
                case .sha256: #expect(fp.hasPrefix("SHA256:"))
                case .sha512: #expect(fp.hasPrefix("SHA512:"))
                case .md5: #expect(fp.contains(":" ) && !fp.hasPrefix("SHA"))
                }
            }
        }
    }

    @Test("fingerprints equivalent between OpenSSH and RFC4716 for SHA256")
    func testFingerprintEquivalenceAcrossFormats() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let openssh = key.publicKeyString()
        let rfc = try KeyConverter.toRFC4716(key: key)
        let a = try PublicKeyParser.fingerprint(from: openssh, hash: .sha256)
        let b = try PublicKeyParser.fingerprint(from: rfc, hash: .sha256)
        #expect(a == b)
    }
}

// MARK: - RSA Specific (slower) coverage
@Suite("PublicKeyParser RSA Tests", .tags(.rsa))
struct PublicKeyParserRSAUnitTests {
    @Test("detectKeyType OpenSSH RSA")
    func testDetectKeyTypeRSA() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa, comment: "rsa-detect")
        let publicKeyString = key.publicKeyString()
        let detectedType = PublicKeyParser.detectKeyType(from: publicKeyString)
        #expect(detectedType == .rsa)
    }

    @Test("validatePublicKeyData RSA")
    func testValidatePublicKeyDataRSA() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa)
        let data = key.publicKeyData()
        try PublicKeyParser.validatePublicKeyData(data, type: .rsa)
    }

    @Test("fingerprint SHA256 RSA OpenSSH")
    func testFingerprintSHA256RSA() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa) as! RSAKey
        let openssh = key.publicKeyString()
        let sha256 = try PublicKeyParser.fingerprint(from: openssh, hash: .sha256)
        #expect(sha256.hasPrefix("SHA256:"))
    }

    @Test("RFC4716 parse + fingerprint RSA")
    func testRFC4716ParseFingerprintRSA() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa, comment: "rsa-rfc") as! RSAKey
        let rfc = try KeyConverter.toRFC4716(key: key)
        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .rsa)
        #expect(parsed.comment == "rsa-rfc")
        let fp = try PublicKeyParser.fingerprint(from: rfc)
        #expect(fp.hasPrefix("SHA256:"))
    }
}
