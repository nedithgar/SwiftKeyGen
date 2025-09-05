import Foundation
import Crypto

extension Data {
    @inlinable
    func sha512Data() -> Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }
    
    /// Returns this data left-padded with 0x00 to the requested length.
    /// If the data is longer than the length, returns the suffix of that length.
    /// Useful for normalizing SSH mpint-encoded big-endian integers.
    @inlinable
    func leftPaddedZero(to length: Int) -> Data {
        if self.count >= length {
            return self.suffix(length)
        } else {
            return Data(repeating: 0, count: length - self.count) + self
        }
    }
}
