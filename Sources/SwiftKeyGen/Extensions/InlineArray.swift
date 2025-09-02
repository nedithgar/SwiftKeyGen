import Foundation

extension InlineArray where Element == UInt8 {
    @inlinable func toData() -> Data {
        var dataBuffer = Data(count: count)
        for index in 0..<count { dataBuffer[index] = self[index] }
        return dataBuffer
    }
}
