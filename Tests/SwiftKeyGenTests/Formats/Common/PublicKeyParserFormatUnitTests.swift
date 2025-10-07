import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PublicKeyParser Format Tests", .tags(.unit))
struct PublicKeyParserFormatUnitTests {
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

    @Test("parseRFC4716 preserves comment")
    func testParseRFC4716PreservesComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@host") as! Ed25519Key
        let rfc = try KeyConverter.toRFC4716(key: key)

        let parsed = try PublicKeyParser.parseRFC4716(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.data == key.publicKeyData())
        #expect(parsed.comment == "user@host")
    }

    @Test("fingerprint computed from RFC4716 matches direct")
    func testFingerprintFromRFC4716() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let rfc = try KeyConverter.toRFC4716(key: key)

        let fromParser = try PublicKeyParser.fingerprint(from: rfc, hash: .sha256)
        let direct = key.fingerprint(hash: .sha256, format: .base64)
        #expect(fromParser == direct)
    }

    @Test("parseAnyFormat selects appropriate parser")
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

    @Test("validatePublicKeyData rejects trailing bytes")
    func testValidateRejectsExtraData() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        var data = key.publicKeyData()
        data.append(0) // add an unexpected extra byte

        do {
            try PublicKeyParser.validatePublicKeyData(data, type: .ed25519)
            Issue.record("Expected invalidKeyData for extra trailing bytes")
        } catch SSHKeyError.invalidKeyData {
            // expected
        }
    }

    @Test("ECDSA curve mismatch is invalid")
    func testECDSACurveMismatchInvalid() throws {
        // Generate a valid P-256 key
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let publicData = key.publicKeyData()

        // Decode to capture the public point bytes
        var dec = SSHDecoder(data: publicData)
        _ = try dec.decodeString() // type
        _ = try dec.decodeString() // curve (actual)
        let point = try dec.decodeData()

        // Re-encode with wrong curve identifier for a P-256 type
        var enc = SSHEncoder()
        enc.encodeString(KeyType.ecdsa256.rawValue)
        enc.encodeString("nistp384") // wrong curve
        enc.encodeData(point)
        let mutated = enc.encode()

        do {
            try PublicKeyParser.validatePublicKeyData(mutated, type: .ecdsa256)
            Issue.record("Expected invalidKeyData for curve mismatch")
        } catch SSHKeyError.invalidKeyData {
            // expected
        }
    }
}
