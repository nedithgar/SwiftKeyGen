import Foundation
import Crypto

extension Data {
    @inlinable
    func sha1DataInsecure() -> Data {
        let digest = Insecure.SHA1.hash(data: self)
        return Data(digest)
    }

    @inlinable
    func sha256Data() -> Data {
        let digest = SHA256.hash(data: self)
        return Data(digest)
    }

    @inlinable
    func sha384Data() -> Data {
        let digest = SHA384.hash(data: self)
        return Data(digest)
    }

    @inlinable
    func sha512Data() -> Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }

    @inlinable
    func leftPadded(to size: Int) -> Data {
        guard count < size else { return self }
        return Data(repeating: 0, count: size - count) + self
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