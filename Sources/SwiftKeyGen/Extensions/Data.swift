import Foundation
import Crypto
#if canImport(Security)
import Security
#endif

/// Convenience utilities for common binary processing used across SwiftKeyGen.
///
/// - Important: Keep helpers here format‑agnostic and broadly reusable.
///   Prefer adding cross‑cutting extensions in `Sources/SwiftKeyGen/Extensions/`.
extension Data {
    // MARK: - Hashes
    /// Compute the insecure SHA‑1 digest of this data.
    ///
    /// - Returns: The 20‑byte SHA‑1 digest as `Data`.
    /// - Warning: SHA‑1 is considered cryptographically broken and must not be
    ///   used for security‑sensitive purposes. This is provided only for
    ///   compatibility with legacy formats.
    /// - SeeAlso: ``sha256Data()``, ``sha384Data()``, ``sha512Data()``
    @inlinable
    func sha1DataInsecure() -> Data {
        let digest = Insecure.SHA1.hash(data: self)
        return Data(digest)
    }

    /// Compute the SHA‑256 digest of this data.
    ///
    /// - Returns: The 32‑byte SHA‑256 digest as `Data`.
    @inlinable
    func sha256Data() -> Data {
        let digest = SHA256.hash(data: self)
        return Data(digest)
    }

    /// Compute the SHA‑384 digest of this data.
    ///
    /// - Returns: The 48‑byte SHA‑384 digest as `Data`.
    @inlinable
    func sha384Data() -> Data {
        let digest = SHA384.hash(data: self)
        return Data(digest)
    }

    /// Compute the SHA‑512 digest of this data.
    ///
    /// - Returns: The 64‑byte SHA‑512 digest as `Data`.
    @inlinable
    func sha512Data() -> Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }

    // MARK: - Hex Encoding/Decoding
    /// Return a hex string representing the bytes of this data.
    ///
    /// - Parameters:
    ///   - uppercase: Whether alphabetic hex digits are uppercased. Defaults to lowercase.
    ///   - separator: Optional delimiter inserted between bytes (for example, `":"` for MD5‑style fingerprints).
    /// - Returns: The hex string.
    /// - Example:
    ///   ```swift
    ///   let bytes = Data([0xDE, 0xAD, 0xBE, 0xEF])
    ///   bytes.hexEncodedString() // "deadbeef"
    ///   bytes.hexEncodedString(uppercase: true, separator: ":") // "DE:AD:BE:EF"
    ///   ```
    @inlinable
    func hexEncodedString(uppercase: Bool = false, separator: String? = nil) -> String {
        if let sep = separator, !sep.isEmpty {
            return self.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined(separator: sep)
        } else {
            return self.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined()
        }
    }

    /// Initialize `Data` from a hex string. ASCII spaces are permitted and ignored.
    ///
    /// The initializer expects an even number of hex digits after spaces are
    /// removed. Any non‑hex character (other than spaces) causes the initializer
    /// to fail.
    ///
    /// - Parameter hexString: The input string containing hexadecimal digits.
    /// - Returns: `nil` if the input is malformed; otherwise the decoded bytes.
    /// - Example:
    ///   ```swift
    ///   Data(hexString: "de ad be ef") // 4 bytes
    ///   Data(hexString: "DEADBE")      // nil (odd number of digits)
    ///   ```
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
    /// Base64‑encode this data and strip padding characters (`=`).
    ///
    /// Useful for fingerprint encodings where padding is undesirable.
    /// - Returns: The base64 string without trailing `=` padding.
    /// - Example:
    ///   ```swift
    ///   let s = Data([0xFF]).base64EncodedString()                 // "/w=="
    ///   let t = Data([0xFF]).base64EncodedStringStrippingPadding() // "/w"
    ///   ```
    @inlinable
    func base64EncodedStringStrippingPadding() -> String {
        return self.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    /// Base64‑encode this data and wrap lines at the requested column width.
    ///
    /// Does not include a trailing newline.
    /// - Parameter columns: Maximum characters per line in the output.
    /// - Returns: The base64 string wrapped to the specified width.
    /// - Example:
    ///   ```swift
    ///   let wrapped = Data(repeating: 0, count: 48)
    ///       .base64EncodedString(wrappedAt: 16)
    ///   // e.g. "AAAA..." with newlines every 16 chars
    ///   ```
    @inlinable
    func base64EncodedString(wrappedAt columns: Int) -> String {
        return self.base64EncodedString().wrapped(every: columns)
    }

    // MARK: - Padding
    /// Return this data left‑padded with `0x00` to reach `size` bytes.
    ///
    /// If the data is already at least `size` bytes long, returns `self`.
    /// - Parameter size: The desired output length.
    /// - Returns: A buffer of length `size` with left padding if needed.
    /// - SeeAlso: ``leftPaddedZero(to:)``
    /// - Example:
    ///   ```swift
    ///   Data([0x01, 0x02]).leftPadded(to: 4) // 00 00 01 02
    ///   ```
    @inlinable
    func leftPadded(to size: Int) -> Data {
        guard count < size else { return self }
        return Data(repeating: 0, count: size - count) + self
    }
    
    /// Return this data left‑padded with `0x00` to the requested `length`.
    ///
    /// If the data is longer than `length`, returns the rightmost `length` bytes
    /// (i.e. the big‑endian least‑significant bytes). Useful for normalizing SSH
    /// `mpint`‑encoded big‑endian integers.
    /// - Parameter length: Desired output length in bytes.
    /// - Returns: A buffer of exactly `length` bytes.
    /// - SeeAlso: ``leftPadded(to:)``
    /// - Example:
    ///   ```swift
    ///   Data([0x01, 0x02, 0x03]).leftPaddedZero(to: 2) // 02 03
    ///   Data([0xAA]).leftPaddedZero(to: 3)             // 00 00 AA
    ///   ```
    @inlinable
    func leftPaddedZero(to length: Int) -> Data {
        if self.count >= length {
            return self.suffix(length)
        } else {
            return Data(repeating: 0, count: length - self.count) + self
        }
    }

    /// Generate cryptographically secure random bytes.
    ///
    /// - Parameter count: Number of random bytes to generate. Must be non‑negative.
    /// - Returns: A `Data` buffer containing `count` random bytes.
    /// - Throws: ``SecureRandomError/negativeCount`` if `count` is negative,
    ///   or ``SecureRandomError/generationFailed(_:)`` if the system RNG call fails.
    /// - Important: Uses `SecRandomCopyBytes` under the hood.
    @inlinable
    static func generateSecureRandomBytes(count: Int) throws -> Data {
        guard count >= 0 else { throw SecureRandomError.negativeCount }

        var data = Data(count: count)
        #if canImport(Security)
        let status: OSStatus = data.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, bytes.count, baseAddress)
        }
        guard status == errSecSuccess else { throw SecureRandomError.generationFailed(status) }
        return data
        #else
        // Fill using the system CSPRNG via SystemRandomNumberGenerator.
        data.withUnsafeMutableBytes { rawBuffer in
            guard let ptr = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return }
            var rng = SystemRandomNumberGenerator()
            for i in 0..<rawBuffer.count {
                ptr.advanced(by: i).pointee = UInt8.random(in: UInt8.min...UInt8.max, using: &rng)
            }
        }
        return data
        #endif
    }

    /// Errors that can occur during secure random byte generation.
    public enum SecureRandomError: Error {
        /// The requested byte count was negative.
        case negativeCount
        /// The underlying system call failed with the given status code.
        #if canImport(Security)
        case generationFailed(OSStatus)
        #else
        case generationFailed(Int32)
        #endif
    }

}
