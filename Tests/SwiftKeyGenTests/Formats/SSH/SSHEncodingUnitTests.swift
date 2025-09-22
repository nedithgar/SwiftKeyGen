import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("SSHEncoding Unit Tests", .tags(.unit))
struct SSHEncodingUnitTests {

    // MARK: - encodeString / decodeString

    @Test("Round-trip simple ASCII string")
    func testStringRoundTripASCII() throws {
        var enc = SSHEncoder()
        enc.encodeString("hello")

        var dec = SSHDecoder(data: enc.encode())
        let s = try dec.decodeString()
        #expect(s == "hello")
        #expect(dec.hasMoreData == false)
        #expect(dec.remaining == 0)
    }

    @Test("Round-trip UTF-8 string")
    func testStringRoundTripUTF8() throws {
        let original = "こんにちは世界"
        var enc = SSHEncoder()
        enc.encodeString(original)

        var dec = SSHDecoder(data: enc.encode())
        let s = try dec.decodeString()
        #expect(s == original)
        #expect(dec.hasMoreData == false)
    }

    @Test("decodeString invalid UTF-8 -> error")
    func testDecodeStringInvalidUTF8() throws {
        // Build length-prefixed invalid UTF-8: 0xC3 0x28
        var bytes = Data()
        var len = UInt32(2).bigEndian
        bytes.append(Data(bytes: &len, count: 4))
        bytes.append(contentsOf: [0xC3, 0x28])

        var dec = SSHDecoder(data: bytes)
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try dec.decodeString()
        }
    }

    // MARK: - encodeData / decodeData

    @Test("Round-trip raw Data payload")
    func testDataRoundTrip() throws {
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        var enc = SSHEncoder()
        enc.encodeData(payload)

        var dec = SSHDecoder(data: enc.encode())
        let out = try dec.decodeData()
        #expect(out == payload)
        #expect(dec.hasMoreData == false)
    }

    @Test("decodeData length exceeds remaining -> error")
    func testDecodeDataInvalidLength() throws {
        // length=10, only 3 bytes present
        var bytes = Data()
        var len = UInt32(10).bigEndian
        bytes.append(Data(bytes: &len, count: 4))
        bytes.append(contentsOf: [0xAA, 0xBB, 0xCC])

        var dec = SSHDecoder(data: bytes)
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try dec.decodeData()
        }
    }

    // MARK: - decodeUInt32

    @Test("decodeUInt32 big-endian and offset advance")
    func testDecodeUInt32() throws {
        // Two 32-bit words: 0x11223344, 0xAABBCCDD
        let bytes: [UInt8] = [
            0x11, 0x22, 0x33, 0x44,
            0xAA, 0xBB, 0xCC, 0xDD
        ]
        var dec = SSHDecoder(data: Data(bytes))
        let w0 = try dec.decodeUInt32()
        #expect(w0 == 0x11223344)
        let w1 = try dec.decodeUInt32()
        #expect(w1 == 0xAABBCCDD)
        #expect(dec.hasMoreData == false)
        #expect(dec.remaining == 0)
    }

    @Test("decodeUInt32 truncated -> error")
    func testDecodeUInt32Truncated() throws {
        var dec = SSHDecoder(data: Data([0x00, 0x01, 0x02])) // 3 bytes only
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try dec.decodeUInt32()
        }
    }

    // MARK: - decodeBytes(count:)

    @Test("decodeBytes consumes exact count and advances")
    func testDecodeBytes() throws {
        var dec = SSHDecoder(data: Data([0xAA, 0xBB, 0xCC, 0xDD]))
        let first = try dec.decodeBytes(count: 3)
        #expect(first == [0xAA, 0xBB, 0xCC])
        #expect(dec.remaining == 1)
        let last = try dec.decodeBytes(count: 1)
        #expect(last == [0xDD])
        #expect(dec.hasMoreData == false)
    }

    @Test("decodeBytes past end -> error")
    func testDecodeBytesPastEnd() throws {
        var dec = SSHDecoder(data: Data([0x00, 0x01]))
        #expect(throws: SSHKeyError.invalidKeyData) {
            _ = try dec.decodeBytes(count: 3)
        }
    }

    // MARK: - mpint (encodeBigInt / decodeBigInt)

    @Test("mpint round-trip magnitude (no sign byte needed)")
    func testMpintRoundTripNoSignByte() throws {
        // Leading zeros should be stripped during encode; high bit not set
        let magnitude = Data([0x00, 0x00, 0x7F, 0x00])

        var enc = SSHEncoder()
        enc.encodeBigInt(magnitude)
        var dec = SSHDecoder(data: enc.encode())

        // Check encoded payload trimmed to 0x7F 0x00
        let encodedPayload = try dec.decodeData()
        #expect(encodedPayload == Data([0x7F, 0x00]))

        // Decode via decodeBigInt -> magnitude without leading zeros
        var dec2 = SSHDecoder(data: enc.encode())
        let decoded = try dec2.decodeBigInt()
        #expect(decoded == Data([0x7F, 0x00]))
    }

    @Test("mpint adds sign 0x00 when high bit set")
    func testMpintAddsSignByte() throws {
        // High bit set in first byte -> encoder must prepend 0x00
        let magnitude = Data([0x80, 0x01, 0x02])
        var enc = SSHEncoder()
        enc.encodeBigInt(magnitude)

        var dec = SSHDecoder(data: enc.encode())
        let payload = try dec.decodeData()
        #expect(payload == Data([0x00, 0x80, 0x01, 0x02]))

        // decodeBigInt should strip the added 0x00 and return the original magnitude
        var dec2 = SSHDecoder(data: enc.encode())
        let decoded = try dec2.decodeBigInt()
        #expect(decoded == magnitude)
    }

    @Test("mpint preserves single leading 0x00 when required for sign")
    func testMpintPreservesRequiredSignZero() throws {
        // Multiple leading zeros before a high-bit byte -> only one should remain
        let magnitude = Data([0x00, 0x00, 0x80, 0x55])
        var enc = SSHEncoder()
        enc.encodeBigInt(magnitude)

        var dec = SSHDecoder(data: enc.encode())
        let payload = try dec.decodeData()
        #expect(payload == Data([0x00, 0x80, 0x55]))

        // decodeBigInt returns magnitude without leading zeros
        var dec2 = SSHDecoder(data: enc.encode())
        let decoded = try dec2.decodeBigInt()
        #expect(decoded == Data([0x80, 0x55]))
    }

    @Test("mpint zero encodes as zero-length and decodes to empty Data")
    func testMpintZero() throws {
        var enc = SSHEncoder()
        enc.encodeBigInt(Data())

        // Encoded length should be 0; decodeBigInt returns empty
        var dec = SSHDecoder(data: enc.encode())
        let decoded = try dec.decodeBigInt()
        #expect(decoded.isEmpty)
    }

    @Test("mpint single 0x00 payload decodes to zero magnitude")
    func testMpintSingleZeroDecodesToZero() throws {
        // Manually craft: length=1, payload=0x00
        var bytes = Data()
        var len = UInt32(1).bigEndian
        bytes.append(Data(bytes: &len, count: 4))
        bytes.append(0x00)

        var dec = SSHDecoder(data: bytes)
        let magnitude = try dec.decodeBigInt()
        #expect(magnitude.isEmpty)
    }
}
