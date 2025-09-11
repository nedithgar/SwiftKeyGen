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
    
    // @inlinable
    // static func generateSecureRandomBytes(count: Int) -> Data {
    //     var bytes = [UInt8](repeating: 0, count: count)
    //     let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    //     precondition(result == errSecSuccess, "Failed to generate secure random bytes")
    //     return Data(bytes)
    // }

    @inlinable
    static func generateSecureRandomBytes(count: Int) throws -> Data {
        guard count >= 0 else { throw SecureRandomError.negativeCount }

        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in 
            guard let baseAddress = bytes.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, bytes.count, baseAddress)
        }
        guard status == errSecSuccess else { throw SecureRandomError.generationFailed(status) }
        return data
    }

    public enum SecureRandomError: Error {
        case negativeCount
        case generationFailed(OSStatus)
    }

}