import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("String Extensions Unit Tests", .tags(.unit))
struct StringUnitTests {

    // MARK: - wrapped(every:separator:)
    @Test("wrapped(every:) splits into expected line lengths without trailing separator")
    func testWrappedBasic() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" // 26 chars
        let wrapped = alphabet.wrapped(every: 5)
        let lines = wrapped.components(separatedBy: "\n")
        #expect(lines == ["ABCDE", "FGHIJ", "KLMNO", "PQRST", "UVWXY", "Z"]) // final line shorter
        #expect(!wrapped.hasSuffix("\n"))
    }

    @Test("wrapped(every:) handles length equal to string and greater than length")
    func testWrappedBoundaryCounts() {
        let s = "OpenSSH"
        // Count equal to length => identity
        #expect(s.wrapped(every: s.count) == s)
        // Count greater than length => identity
        #expect(s.wrapped(every: s.count + 10) == s)
    }

    @Test("wrapped(every:) with custom separator preserves grapheme clusters")
    func testWrappedUnicodeGraphemes() {
        // Use characters that are multi-scalar grapheme clusters (flag + skin-tone emoji)
        let flags = "🇺🇸🇨🇦🇯🇵" // 3 flag emojis
        let tones = "👍🏼👍🏿👍" // 3 thumbs up with different skin tones (last one default)
        #expect(flags.count == 3)
        #expect(tones.count == 3)

        let wrappedFlags = flags.wrapped(every: 2, separator: "|")
        // Expect 2 + 1 segments (because 3 graphemes)
        #expect(wrappedFlags == "🇺🇸🇨🇦|🇯🇵")

        let wrappedTones = tones.wrapped(every: 2, separator: ":")
        #expect(wrappedTones == "👍🏼👍🏿:👍")
    }

    @Test("wrapped(every:) returns self for non-positive or empty input")
    func testWrappedEdgeCases() {
        #expect("".wrapped(every: 10) == "")
        let s = "abc"
        // Non-positive (0 or negative) count returns self per guard branch
        #expect(s.wrapped(every: 0) == s)
        #expect(s.wrapped(every: -5) == s)
    }

    // MARK: - concatenatedBody(between:and:skipEmpty:)
    @Test("concatenatedBody extracts content between markers and skips empty lines")
    func testConcatenatedBodyBasic() {
        let input = """
        ---BEGIN BLOCK---
        line1
        
        line2
        line3
        ---END BLOCK---
        trailing
        """
        if let body = input.concatenatedBody(between: "---BEGIN BLOCK---", and: "---END BLOCK---", skipEmpty: true) {
            #expect(body == "line1line2line3")
        } else {
            #expect(Bool(false), "Expected non-nil body")
        }
    }

    @Test("concatenatedBody includes empty lines when skipEmpty is false")
    func testConcatenatedBodyIncludingEmpty() {
        let input = """
        <BEGIN>
        a
        
        b
        <END>
        """
        let body = input.concatenatedBody(between: "<BEGIN>", and: "<END>", skipEmpty: false)
        // Empty line preserved -> becomes an empty string segment between a and b
        #expect(body == "a" + "" + "b")
    }

    @Test("concatenatedBody returns nil when markers missing or empty body")
    func testConcatenatedBodyMissingMarkersOrEmpty() {
        let noMarkers = "just some text"
        #expect(noMarkers.concatenatedBody(between: "BEGIN", and: "END") == nil)

        let emptyBody = """
        START
        END
        """
        #expect(emptyBody.concatenatedBody(between: "START", and: "END") == nil)
    }

    // MARK: - pemBody(type:)
    @Test("pemBody extracts base64 payload and strips newlines")
    func testPEMBodyExtraction() {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        QUJD
        Rkdo
        -----END PUBLIC KEY-----
        """
        let body = pem.pemBody(type: "PUBLIC KEY")
        #expect(body == "QUJDRkdo")
    }

    @Test("pemBody returns nil for absent type")
    func testPEMBodyAbsent() {
        let pem = """
        -----BEGIN PRIVATE KEY-----
        AAA=
        -----END PRIVATE KEY-----
        """
        #expect(pem.pemBody(type: "PUBLIC KEY") == nil)
    }

    @Test("pemBody handles multiple PEM blocks selecting the matching one")
    func testPEMMultipleBlocks() {
        let multi = """
        -----BEGIN CERTIFICATE-----
        MQ==
        -----END CERTIFICATE-----
        -----BEGIN RSA PUBLIC KEY-----
        Ag==
        -----END RSA PUBLIC KEY-----
        -----BEGIN PUBLIC KEY-----
        Aw==
        -----END PUBLIC KEY-----
        """
        #expect(multi.pemBody(type: "RSA PUBLIC KEY") == "Ag==")
        #expect(multi.pemBody(type: "PUBLIC KEY") == "Aw==")
        #expect(multi.pemBody(type: "CERTIFICATE") == "MQ==")
    }
}
