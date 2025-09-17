import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("ASN.1 Parser Unit", .tags(.unit))
struct ASN1ParserUnitTests {

    // MARK: - DER helpers (tests only)

    private func derLength(_ length: Int) -> [UInt8] {
        precondition(length >= 0)
        if length < 0x80 {
            return [UInt8(length)]
        } else if length <= 0xFF {
            return [0x81, UInt8(length)]
        } else {
            return [0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }

    private func derInteger(_ bytes: [UInt8]) -> [UInt8] {
        return [0x02] + derLength(bytes.count) + bytes
    }

    private func derNull() -> [UInt8] { [0x05, 0x00] }

    private func derOID(_ bytes: [UInt8]) -> [UInt8] {
        return [0x06] + derLength(bytes.count) + bytes
    }

    private func derSequence(_ content: [UInt8]) -> [UInt8] {
        return [0x30] + derLength(content.count) + content
    }

    private func derBitString(pad: UInt8, payload: [UInt8]) -> [UInt8] {
        // payload is the encoded content (e.g., inner SEQUENCE TLV)
        let value = [pad] + payload
        return [0x03] + derLength(value.count) + value
    }

    // MARK: - parseLength

    @Test("parseLength short form")
    func testParseLengthShortForm() throws {
        var parser = ASN1Parser(data: Data([0x05]))
        let length = try parser.parseLength()
        #expect(length == 5)
        #expect(parser.hasMoreData == false)
    }

    @Test("parseLength long form 1 byte")
    func testParseLengthLongForm1() throws {
        var parser = ASN1Parser(data: Data([0x81, 0x80]))
        let length = try parser.parseLength()
        #expect(length == 128)
        #expect(parser.hasMoreData == false)
    }

    @Test("parseLength long form 2 bytes")
    func testParseLengthLongForm2() throws {
        var parser = ASN1Parser(data: Data([0x82, 0x01, 0x00]))
        let length = try parser.parseLength()
        #expect(length == 256)
        #expect(parser.hasMoreData == false)
    }

    @Test("parseLength invalid (truncated)")
    func testParseLengthInvalid() {
        var parser = ASN1Parser(data: Data([0x82, 0x01]))
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try parser.parseLength()
        }
    }

    // MARK: - parseInteger

    @Test("parseInteger short form")
    func testParseIntegerShortForm() throws {
        // INTEGER 0x05
        let bytes: [UInt8] = [0x02, 0x01, 0x05]
        var parser = ASN1Parser(data: Data(bytes))
        let opt = try parser.parseInteger()
        let value = try #require(opt)
        #expect(value == Data([0x05]))
        #expect(parser.hasMoreData == false)
    }

    @Test("parseInteger long form")
    func testParseIntegerLongForm() throws {
        // INTEGER of 256 bytes (all 0xAA)
        let intBytes = [UInt8](repeating: 0xAA, count: 256)
        let bytes = derInteger(intBytes)
        var parser = ASN1Parser(data: Data(bytes))
        let opt = try parser.parseInteger()
        let value = try #require(opt)
        #expect(value.count == 256)
        #expect(value.allSatisfy { $0 == 0xAA })
    }

    @Test("parseInteger wrong tag -> nil, no advance")
    func testParseIntegerWrongTag() throws {
        var parser = ASN1Parser(data: Data([0x03, 0x01, 0x00]))
        let value = try parser.parseInteger()
        #expect(value == nil)
        #expect(parser.offset == 0)
    }

    @Test("parseInteger invalid length")
    func testParseIntegerInvalidLength() throws {
        // Declared length 3 but only 1 byte present
        var parser = ASN1Parser(data: Data([0x02, 0x03, 0x05]))
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try parser.parseInteger()
        }
    }

    // MARK: - parseSequence

    @Test("parseSequence simple content")
    func testParseSequence() throws {
        // SEQUENCE { INTEGER 0x05 }
        let seq = derSequence([0x02, 0x01, 0x05])
        var parser = ASN1Parser(data: Data(seq))
        let opt = try parser.parseSequence()
        let content = try #require(opt)
        #expect(content == Data([0x02, 0x01, 0x05]))
        #expect(parser.hasMoreData == false)
    }

    @Test("parseSequence wrong tag -> nil")
    func testParseSequenceWrongTag() throws {
        var parser = ASN1Parser(data: Data([0x02, 0x01, 0x00]))
        let content = try parser.parseSequence()
        #expect(content == nil)
        #expect(parser.offset == 0)
    }

    // MARK: - parseObjectIdentifier

    @Test("parseObjectIdentifier returns OID bytes")
    func testParseOID() throws {
        // OID 1.2.840.113549.1.1.1 -> 06 09 2A 86 48 86 F7 0D 01 01 01
        let oidBytes: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let data = Data(derOID(oidBytes))
        var parser = ASN1Parser(data: data)
        let opt = try parser.parseObjectIdentifier()
        let oid = try #require(opt)
        #expect(oid == Data(oidBytes))
        #expect(parser.hasMoreData == false)
    }

    // MARK: - parseBitString

    @Test("parseBitString returns payload minus pad")
    func testParseBitString() throws {
        // BIT STRING with 0 pad, payload DE AD BE
        let data = Data(derBitString(pad: 0x00, payload: [0xDE, 0xAD, 0xBE]))
        var parser = ASN1Parser(data: data)
        let opt = try parser.parseBitString()
        let payload = try #require(opt)
        #expect(payload == Data([0xDE, 0xAD, 0xBE]))
        #expect(parser.hasMoreData == false)
    }

    @Test("parseBitString empty payload")
    func testParseBitStringEmptyPayload() throws {
        // BIT STRING with length 1 (pad only) -> empty payload
        let data = Data([0x03, 0x01, 0x00])
        var parser = ASN1Parser(data: data)
        let opt = try parser.parseBitString()
        let payload = try #require(opt)
        #expect(payload.isEmpty)
        #expect(parser.hasMoreData == false)
    }

    @Test("parseBitString truncated -> error")
    func testParseBitStringTruncated() throws {
        // Declared length 3 but only 2 bytes present
        var parser = ASN1Parser(data: Data([0x03, 0x03, 0x00, 0xAA]))
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try parser.parseBitString()
        }
    }

    // MARK: - parseNull

    @Test("parseNull present -> true")
    func testParseNullPresent() throws {
        var parser = ASN1Parser(data: Data([0x05, 0x00]))
        let isNull = try parser.parseNull()
        #expect(isNull == true)
        #expect(parser.hasMoreData == false)
    }

    @Test("parseNull absent -> false, no advance")
    func testParseNullAbsent() throws {
        var parser = ASN1Parser(data: Data([0x05, 0x01, 0x00]))
        let isNull = try parser.parseNull()
        #expect(isNull == false)
        #expect(parser.offset == 0)
    }

    // MARK: - parseOctetString

    @Test("parseOctetString returns bytes")
    func testParseOctetString() throws {
        let content: [UInt8] = [0xAA, 0xBB, 0xCC]
        let data = Data([0x04] + derLength(content.count) + content)
        var parser = ASN1Parser(data: data)
        let opt = try parser.parseOctetString()
        let octets = try #require(opt)
        #expect(octets == Data(content))
        #expect(parser.hasMoreData == false)
    }

    @Test("parseOctetString truncated -> error")
    func testParseOctetStringTruncated() throws {
        // Declared length 3, but only 2 bytes present
        var parser = ASN1Parser(data: Data([0x04, 0x03, 0xAA, 0xBB]))
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try parser.parseOctetString()
        }
    }

    // MARK: - skipSequence

    @Test("skipSequence advances over sequence")
    func testSkipSequence() throws {
        // SEQUENCE { OCTET STRING 0xAA }
        let seq = derSequence([0x04, 0x01, 0xAA])
        var parser = ASN1Parser(data: Data(seq))
        try parser.skipSequence()
        #expect(parser.offset == seq.count)
        #expect(parser.hasMoreData == false)
    }

    // MARK: - parseRSAPublicKey (minimal SPKI)

    @Test("parseRSAPublicKey parses modulus and exponent")
    func testParseRSAPublicKeyMinimalSPKI() throws {
        // Build minimal SubjectPublicKeyInfo for RSA: SEQUENCE { algId, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
        let rsaOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] // 1.2.840.113549.1.1.1
        let algId = derSequence(derOID(rsaOID) + derNull())

        let modulus: [UInt8] = [0x01, 0x02, 0x03]
        let exponent: [UInt8] = [0x01, 0x00, 0x01]
        let innerSeq = derSequence(derInteger(modulus) + derInteger(exponent))
        let bitString = derBitString(pad: 0x00, payload: innerSeq)

        let spki = Data(derSequence(algId + bitString))

        var parser = ASN1Parser(data: spki)
        let (parsedMod, parsedExp) = try parser.parseRSAPublicKey()
        #expect(parsedMod == Data(modulus))
        #expect(parsedExp == Data(exponent))
        #expect(parser.hasMoreData == false)
    }

    @Test("parseRSAPublicKey invalid layout -> error")
    func testParseRSAPublicKeyInvalid() throws {
        // Outer SEQUENCE present but missing BIT STRING tag afterwards
        let rsaOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
        let algId = derSequence(derOID(rsaOID) + derNull())
        // Intentionally put OCTET STRING instead of BIT STRING
        let bogus: [UInt8] = [0x04, 0x01, 0x00]
        let spki = Data(derSequence(algId + bogus))

        var parser = ASN1Parser(data: spki)
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try parser.parseRSAPublicKey()
        }
    }
}
