import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("BubbleBabble Unit Tests", .tags(.unit))
struct BubbleBabbleUnitTests {
    @Test("Empty input encodes to xexax")
    func emptyInputVector() {
        let encoded = BubbleBabble.encode(Data())
        #expect(encoded == "xexax")
    }

    @Test("Known vectors (RFC/Perl-compatible)")
    func knownVectors() {
        struct Vector { let input: Data; let expected: String }
        let vectors: [Vector] = [
            .init(input: Data("1234567890".utf8), expected: "xesef-disof-gytuf-katof-movif-baxux"),
            .init(input: Data("Pineapple".utf8),    expected: "xigak-nyryk-humil-bosek-sonax")
        ]
        for v in vectors {
            #expect(BubbleBabble.encode(v.input) == v.expected)
        }
    }

    @Test("Alphabet + structure are valid")
    func alphabetAndStructureAreValid() {
        // Use deterministic bytes (not RSA) to keep this test fast
        let bytes = Array(0..<32).map { UInt8($0) } // 32 bytes
        let encoded = BubbleBabble.encode(Data(bytes))

        // Starts and ends with 'x'
        #expect(encoded.first == Character("x"))
        #expect(encoded.last == Character("x"))

        // Hyphen count equals floor(n/2)
        let hyphenCount = encoded.filter { $0 == Character("-") }.count
        #expect(hyphenCount == bytes.count / 2)

        // No leading/trailing/consecutive hyphens
        #expect(!encoded.hasPrefix("-"))
        #expect(!encoded.hasSuffix("-"))
        #expect(!encoded.contains("--"))

        // Only permitted characters appear
        let vowels = Set("aeiouy")
        let consonants = Set("bcdfghklmnprstvzx")
        let allowed = vowels.union(consonants).union([Character("-")])
        for ch in encoded {
            #expect(allowed.contains(ch))
        }
    }

    @Test("Deterministic for identical inputs")
    func deterministicEncoding() {
        let data = Data([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
        #expect(BubbleBabble.encode(data) == BubbleBabble.encode(data))
    }

    @Test("Hyphen count across small lengths")
    func hyphenCountByLength() {
        for n in 0...9 {
            let data = Data((0..<n).map(UInt8.init))
            let encoded = BubbleBabble.encode(data)
            let hyphens = encoded.filter { $0 == "-" }.count
            #expect(hyphens == n / 2)
        }
    }
}
