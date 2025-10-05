import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("InlineArray Extensions Unit Tests", .tags(.unit))
struct InlineArrayUnitTests {
    @Test("toData returns identical bytes for literal initializer")
    func toDataFromLiteral() {
        let bytes: InlineArray<16, UInt8> = [
            0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15
        ]
        let data = bytes.toData()
        #expect(data.count == 16)
        for i in 0..<16 {
            #expect(data[i] == UInt8(i))
        }
    }

    @Test("toData produces an independent copy (no aliasing)")
    func toDataProducesIndependentCopy() {
        var bytes: InlineArray<8, UInt8> = [1, 2, 3, 4, 5, 6, 7, 8]
        let snapshot = bytes.toData()

        // Mutate original InlineArray after taking snapshot
        bytes[0] = 99

        // Snapshot remains unchanged (copy semantics)
        #expect(snapshot[0] == 1)

        // Fresh conversion reflects current InlineArray contents
        let updated = bytes.toData()
        #expect(updated[0] == 99)

        // Mutating Data does not affect the InlineArray value
        var mutableSnapshot = snapshot
        mutableSnapshot[1] = 77
        #expect(bytes[1] == 2)
    }

    @Test("toData works for repeating init and sequential values")
    func toDataRepeatingAndSequential() {
        let repeated: InlineArray<4, UInt8> = InlineArray<4, UInt8>(repeating: 0xAB)
        let repeatedData = repeated.toData()
        #expect(repeatedData == Data([0xAB, 0xAB, 0xAB, 0xAB]))

        var sequential = InlineArray<32, UInt8>(repeating: 0)
        for i in 0..<32 { sequential[i] = UInt8(i) }
        let sequentialData = sequential.toData()
        #expect(sequentialData.count == 32)
        #expect(sequentialData[10] == 10)
        #expect(sequentialData[31] == 31)
    }

    @Test("toData on empty InlineArray yields empty Data")
    func toDataOnEmptyInlineArray() {
        let empty: InlineArray<0, UInt8> = []
        let data = empty.toData()
        #expect(data.count == 0)
    }
}

