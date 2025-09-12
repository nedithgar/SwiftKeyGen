import Foundation
import Crypto

extension Data {
    // MARK: - Hashes
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

    // MARK: - Hex Encoding/Decoding
    /// Return a hex string for this data.
    /// - Parameters:
    ///   - uppercase: Whether alphabetic hex digits are uppercased. Defaults to lowercase.
    ///   - separator: Optional separator inserted between bytes (e.g. ":" for MD5 fingerprints).
    /// - Returns: The hex string.
    @inlinable
    func hexEncodedString(uppercase: Bool = false, separator: String? = nil) -> String {
        if let sep = separator, !sep.isEmpty {
            return self.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined(separator: sep)
        } else {
            return self.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined()
        }
    }

    /// Initialize from a hex string. Whitespace is permitted and ignored.
    @inlinable
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    // MARK: - Base64 helpers
    /// Base64-encode this data and strip any padding characters ('='). Useful for SSH fingerprints.
    @inlinable
    func base64EncodedStringStrippingPadding() -> String {
        return self.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    // MARK: - Padding
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
