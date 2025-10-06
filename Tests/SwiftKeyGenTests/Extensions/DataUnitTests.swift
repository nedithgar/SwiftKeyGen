import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Data Extensions Unit Tests", .tags(.unit))
struct DataUnitTests {

    // MARK: - Hashes
    @Test("SHA digests for common vectors")
    func testSHADigests() {
        let empty = Data()
        let abc = Data("abc".utf8)

        // Known-good digests from NIST test vectors
        let sha1Empty = Data(hexString: "da39a3ee5e6b4b0d3255bfef95601890afd80709")!
        let sha256Empty = Data(hexString: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")!
        let sha384Empty = Data(hexString: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")!
        let sha512Empty = Data(hexString: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")!

        #expect(empty.sha1DataInsecure() == sha1Empty)
        #expect(empty.sha256Data() == sha256Empty)
        #expect(empty.sha384Data() == sha384Empty)
        #expect(empty.sha512Data() == sha512Empty)

        let sha1ABC = Data(hexString: "a9993e364706816aba3e25717850c26c9cd0d89d")!
        let sha256ABC = Data(hexString: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")!
        let sha384ABC = Data(hexString: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")!
        let sha512ABC = Data(hexString: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")!

        #expect(abc.sha1DataInsecure() == sha1ABC)
        #expect(abc.sha256Data() == sha256ABC)
        #expect(abc.sha384Data() == sha384ABC)
        #expect(abc.sha512Data() == sha512ABC)
    }

    // MARK: - Hex encoding/decoding
    @Test("hexEncodedString lowercase/uppercase and separators")
    func testHexEncodedStringVariants() {
        let bytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
        #expect(bytes.hexEncodedString() == "deadbeef")
        #expect(bytes.hexEncodedString(uppercase: true) == "DEADBEEF")
        #expect(bytes.hexEncodedString(uppercase: true, separator: ":") == "DE:AD:BE:EF")
        #expect(bytes.hexEncodedString(separator: "-") == "de-ad-be-ef")
    }

    @Test("init(hexString:) accepts spaces and enforces validity")
    func testHexStringInitializer() {
        #expect(Data(hexString: "de ad be ef") == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(Data(hexString: "DEADBEEF") == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(Data(hexString: "") == Data())

        // Odd number of digits => nil
        #expect(Data(hexString: "DEADBEE") == nil)

        // Invalid characters => nil
        #expect(Data(hexString: "zz") == nil)
        #expect(Data(hexString: "12 3x") == nil)
    }

    // MARK: - Base64 helpers
    @Test("base64EncodedStringStrippingPadding removes trailing =")
    func testBase64StripPadding() {
        #expect(Data([0xFF]).base64EncodedStringStrippingPadding() == "/w")
        #expect(Data([0x01, 0x02]).base64EncodedStringStrippingPadding() == "AQI")

        // No padding present remains unchanged
        #expect(Data([0x01, 0x02, 0x03]).base64EncodedStringStrippingPadding() == "AQID")
    }

    @Test("base64EncodedString(wrappedAt:) wraps lines without trailing newline")
    func testBase64WrappedAtColumns() {
        let data = Data(repeating: 0, count: 48) // 64 Base64 chars
        let wrapped = data.base64EncodedString(wrappedAt: 16)

        // Expect 4 lines of 16 chars, no trailing newline
        #expect(wrapped.hasSuffix("\n") == false)
        let lines = wrapped.components(separatedBy: "\n")
        #expect(lines.count == 4)
        for line in lines { #expect(line.count == 16) }
    }

    // MARK: - Padding helpers
    @Test("leftPadded(to:) pads with leading zeros or returns self")
    func testLeftPadded() {
        let d = Data([0x01, 0x02])
        #expect(d.leftPadded(to: 4) == Data([0x00, 0x00, 0x01, 0x02]))

        // Already long enough => identity
        let four = Data([1, 2, 3, 4])
        #expect(four.leftPadded(to: 4) == four)
        let five = Data([1, 2, 3, 4, 5])
        #expect(five.leftPadded(to: 4) == five)
    }

    @Test("leftPaddedZero(to:) trims or pads to exact length")
    func testLeftPaddedZero() {
        // Longer than requested => take rightmost bytes
        #expect(Data([0x01, 0x02, 0x03]).leftPaddedZero(to: 2) == Data([0x02, 0x03]))

        // Shorter than requested => pad with leading zeros
        #expect(Data([0xAA]).leftPaddedZero(to: 3) == Data([0x00, 0x00, 0xAA]))
    }

    // MARK: - Secure randomness
    @Test("generateSecureRandomBytes rejects negative count and handles sizes")
    func testGenerateSecureRandomBytes() {
        // Negative count => throws
        #expect(throws: Error.self) {
            _ = try Data.generateSecureRandomBytes(count: -1)
        }

        // Zero bytes => empty Data
        let zero = try! Data.generateSecureRandomBytes(count: 0)
        #expect(zero.count == 0)

        // Positive count => exact length
        let sixteen = try! Data.generateSecureRandomBytes(count: 16)
        #expect(sixteen.count == 16)
    }
}
