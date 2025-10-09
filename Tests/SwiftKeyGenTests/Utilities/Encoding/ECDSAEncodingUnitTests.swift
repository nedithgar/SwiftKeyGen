import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("ECDSAEncoding Unit Tests", .tags(.unit))
struct ECDSAEncodingUnitTests {
    // Helper to build Data from hex more tersely inside expectations.
    private func D(_ bytes: [UInt8]) -> Data { Data(bytes) }

    @Test("rawSignature pads both r and s to component length")
    func testRawSignaturePadsComponents() {
        let r = Data([0x01, 0x02])          // length 2
        let s = Data([0xAA])                // length 1
        let componentLen = 4
        let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: componentLen)

        // Expect r padded to 4 bytes => 00 00 01 02
        let expectedR = Data([0x00, 0x00, 0x01, 0x02])
        // Expect s padded to 4 bytes => 00 00 00 AA
        let expectedS = Data([0x00, 0x00, 0x00, 0xAA])
        let expected = expectedR + expectedS

        #expect(raw.count == componentLen * 2)
        #expect(raw == expected)
    }

    @Test("rawSignature truncates when components exceed length (big-endian least significant bytes kept)")
    func testRawSignatureTruncatesComponents() {
        // 5-byte r where componentLength is 4: expect to keep last 4 bytes
        let r = Data([0x11, 0x22, 0x33, 0x44, 0x55]) // => 22 33 44 55
        let s = Data([0xFF, 0xEE, 0xDD, 0xCC, 0xBB]) // => EE DD CC BB
        let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 4)

        let expected = Data([0x22, 0x33, 0x44, 0x55, 0xEE, 0xDD, 0xCC, 0xBB])
        #expect(raw == expected)
    }

    @Test("rawSignature handles already-exact-length components without modification")
    func testRawSignatureExactLength() {
        let r = Data([0x10, 0x20, 0x30, 0x40])
        let s = Data([0xAA, 0xBB, 0xCC, 0xDD])
        let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 4)

        let expected = r + s
        #expect(raw == expected)
    }

    @Test("rawSignature assembled length matches 2 * componentLength for varied component sizes")
    func testRawSignatureLengthInvariant() {
        for len in [1, 2, 8, 16, 32] { // small selection
            // Build r shorter than len, s longer than len to exercise both paths
            let r = Data(repeating: 0x01, count: max(1, len / 2))
            let s = Data(repeating: 0x02, count: len + 1) // force truncation when > len
            let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: len)
            #expect(raw.count == len * 2)
        }
    }
}
