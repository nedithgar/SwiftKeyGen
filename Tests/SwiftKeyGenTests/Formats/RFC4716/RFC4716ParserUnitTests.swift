import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("RFC4716Parser Unit Tests", .tags(.unit))
struct RFC4716ParserUnitTests {

    // MARK: - Helpers

    private func makeEd25519KeyData(pub: Data, extraAfter: Bool = false) -> Data {
        var enc = SSHEncoder()
        enc.encodeString("ssh-ed25519")
        enc.encodeData(pub)
        if extraAfter { enc.encodeUInt32(0) } // Add trailing field to trigger hasMoreData
        return enc.encode()
    }

    private func makeRSAKeyData(exponent: Data, modulus: Data) -> Data {
        var enc = SSHEncoder()
        enc.encodeString("ssh-rsa")
        enc.encodeData(exponent)
        enc.encodeData(modulus)
        return enc.encode()
    }

    private func makeECDSAKeyData(type: KeyType, curve: String, pub: Data) -> Data {
        var enc = SSHEncoder()
        enc.encodeString(type.rawValue)
        enc.encodeString(curve)
        enc.encodeData(pub)
        return enc.encode()
    }

    private func rfc4716Block(comment: String? = nil, headers: [String] = [], base64Lines: [String]) -> String {
        var s = "---- BEGIN SSH2 PUBLIC KEY ----\n"
        if let comment = comment {
            s += "Comment: \"\(comment)\"\n"
        }
        for h in headers { s += h + "\n" }
        for line in base64Lines { s += line + "\n" }
        s += "---- END SSH2 PUBLIC KEY ----"
        return s
    }

    // MARK: - Detection

    @Test("isFormat detects RFC4716 markers")
    func testIsFormat() throws {
        let valid = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        AAAA
        ---- END SSH2 PUBLIC KEY ----
        """
        #expect(RFC4716Parser.isFormat(valid))

        let missingBegin = """
        AAAA
        ---- END SSH2 PUBLIC KEY ----
        """
        #expect(!RFC4716Parser.isFormat(missingBegin))

        let missingEnd = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        AAAA
        """
        #expect(!RFC4716Parser.isFormat(missingEnd))

        let noisy = """
        prefix text
        ---- BEGIN SSH2 PUBLIC KEY ----
        AAAA
        ---- END SSH2 PUBLIC KEY ----
        suffix text
        """
        #expect(RFC4716Parser.isFormat(noisy))
    }

    // MARK: - Successful parses

    @Test("Parse Ed25519 with quoted comment and ignore extra headers")
    func testParseEd25519WithCommentAndHeaders() throws {
        // 32-byte public key
        let pub = Data((0..<32).map { UInt8($0) })
        let keyData = makeEd25519KeyData(pub: pub)
        let b64 = keyData.base64EncodedString()

        let rfc = rfc4716Block(
            comment: "user@host",
            headers: ["x-foo: bar", "x-bar: baz"],
            base64Lines: [b64]
        )

        let parsed = try RFC4716Parser.parse(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "user@host")
        #expect(parsed.data == keyData)
    }

    @Test("Parse with multi-line base64 (space-continued second line)")
    func testParseWrappedBase64WithContinuationSpace() throws {
        // RSA: small exponent and short modulus (validator only checks non-empty)
        let e = Data([0x01, 0x00, 0x01])
        let n = Data(repeating: 0xA5, count: 16)
        let keyData = makeRSAKeyData(exponent: e, modulus: n)
        let b64 = keyData.base64EncodedString()

        // Split base64 into two lines; prefix the second with a space to exercise continuation handling
        let mid = b64.index(b64.startIndex, offsetBy: max(10, b64.count / 2))
        let line1 = String(b64[..<mid])
        let line2 = " " + String(b64[mid...])

        let rfc = rfc4716Block(
            comment: "rsa-test",
            base64Lines: [line1, line2]
        )

        let parsed = try RFC4716Parser.parse(rfc)
        #expect(parsed.type == .rsa)
        #expect(parsed.data == keyData)
        #expect(parsed.comment == "rsa-test")
    }

    @Test("Parse ECDSA P-256 with correct curve and length")
    func testParseECDSAP256() throws {
        // Uncompressed point: 0x04 || X(32) || Y(32)
        let pub = Data([0x04]) + Data(repeating: 0x11, count: 32) + Data(repeating: 0x22, count: 32)
        let keyData = makeECDSAKeyData(type: .ecdsa256, curve: "nistp256", pub: pub)
        let b64 = keyData.base64EncodedString()

        let rfc = rfc4716Block(comment: "p256", base64Lines: [b64])
        let parsed = try RFC4716Parser.parse(rfc)
        #expect(parsed.type == .ecdsa256)
        #expect(parsed.data == keyData)
        #expect(parsed.comment == "p256")
    }

    // MARK: - Failure cases

    @Test("Unsupported key type in payload throws")
    func testUnsupportedKeyType() throws {
        var enc = SSHEncoder()
        enc.encodeString("ssh-unknown")
        enc.encodeData(Data([0x01]))
        let keyData = enc.encode()
        let b64 = keyData.base64EncodedString()

        let rfc = rfc4716Block(base64Lines: [b64])
        #expect(throws: SSHKeyError.unsupportedKeyType) {
            _ = try RFC4716Parser.parse(rfc)
        }
    }

    @Test("Invalid base64 in payload throws invalidKeyData")
    func testInvalidBase64() throws {
        let rfc = rfc4716Block(comment: "bad", base64Lines: ["not*base64??!!"])
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try RFC4716Parser.parse(rfc)
        }
    }

    @Test("Begin marker after end marker throws invalidKeyData")
    func testReversedMarkers() throws {
        let s = """
        ---- END SSH2 PUBLIC KEY ----
        AAAA
        ---- BEGIN SSH2 PUBLIC KEY ----
        """
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try RFC4716Parser.parse(s)
        }
    }

    @Test("Ed25519 wrong length (31 bytes) rejected")
    func testInvalidEd25519Length() throws {
        let pub = Data(repeating: 0x33, count: 31) // should be 32
        let keyData = makeEd25519KeyData(pub: pub)
        let b64 = keyData.base64EncodedString()
        let rfc = rfc4716Block(base64Lines: [b64])

        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try RFC4716Parser.parse(rfc)
        }
    }

    @Test("Extra fields after valid payload rejected")
    func testExtraTrailingData() throws {
        let pub = Data(repeating: 0x77, count: 32)
        let keyData = makeEd25519KeyData(pub: pub, extraAfter: true)
        let b64 = keyData.base64EncodedString()
        let rfc = rfc4716Block(base64Lines: [b64])

        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try RFC4716Parser.parse(rfc)
        }
    }

    @Test("Comment without quotes is accepted and preserved")
    func testUnquotedComment() throws {
        let pub = Data(repeating: 0xAB, count: 32)
        let keyData = makeEd25519KeyData(pub: pub)
        let b64 = keyData.base64EncodedString()

        // Build block manually to avoid quoting the comment
        let rfc = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        Comment: user-no-quotes
        \(b64)
        ---- END SSH2 PUBLIC KEY ----
        """

        let parsed = try RFC4716Parser.parse(rfc)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "user-no-quotes")
        #expect(parsed.data == keyData)
    }
}

