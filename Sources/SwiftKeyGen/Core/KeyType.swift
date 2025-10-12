import Foundation

/// Supported SSH key algorithms (extensible).
///
/// - Design: This is a `RawRepresentable` string-backed type (not an `enum`)
///   to allow forward-compatibility with future OpenSSH algorithms without
///   requiring a library update. It mirrors the approach used by
///   ``OpenSSHPrivateKey/EncryptionCipher``.
/// - Backward compatibility: Existing call sites using ``KeyType/rsa``-style
///   static members, equality checks, pattern matching in `switch`, and
///   single-value `Codable` encoding continue to work.
public struct KeyType: RawRepresentable, Hashable, Sendable, ExpressibleByStringLiteral, Codable, CaseIterable {
    public let rawValue: String

    public init(rawValue: String) { self.rawValue = rawValue }
    public init(stringLiteral value: String) { self.rawValue = value }

    internal enum BackingKeyType: String {
        case rsa = "ssh-rsa"
        case ed25519 = "ssh-ed25519"
        case ecdsa256 = "ecdsa-sha2-nistp256"
        case ecdsa384 = "ecdsa-sha2-nistp384"
        case ecdsa521 = "ecdsa-sha2-nistp521"
    }

    internal var knownBacking: BackingKeyType? { BackingKeyType(rawValue: rawValue) }

    // Known algorithm constants (stable API surface)
    public static let rsa: KeyType = "ssh-rsa"
    public static let ed25519: KeyType = "ssh-ed25519"
    public static let ecdsa256: KeyType = "ecdsa-sha2-nistp256"
    public static let ecdsa384: KeyType = "ecdsa-sha2-nistp384"
    public static let ecdsa521: KeyType = "ecdsa-sha2-nistp521"

    /// The set of algorithms known to this library version.
    ///
    /// Ordering is preserved for backward compatibility with previous snapshots
    /// and tests that intentionally assert order.
    public static var known: [KeyType] { [.rsa, .ed25519, .ecdsa256, .ecdsa384, .ecdsa521] }
    /// CaseIterable conformance for backward compatibility (known only).
    public static var allCases: [KeyType] { known }

    /// Default bit size for this algorithm.
    ///
    /// - For known algorithms, returns the canonical size used by this
    ///   library. For unknown future algorithms, returns 0 (unspecified).
    public var defaultBits: Int {
        switch self {
        case .rsa:
            return 3072
        case .ed25519:
            return 256
        case .ecdsa256:
            return 256
        case .ecdsa384:
            return 384
        case .ecdsa521:
            return 521
        default:
            // Unknown/future algorithm – no canonical default.
            return 0
        }
    }

    /// A human‑readable algorithm family name.
    public var algorithmName: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ed25519:
            return "ED25519"
        case .ecdsa256, .ecdsa384, .ecdsa521:
            return "ECDSA"
        default:
            // Heuristic family detection for forward-compatibility
            if rawValue.hasPrefix("ssh-rsa") { return "RSA" }
            if rawValue.hasPrefix("ssh-ed25519") { return "ED25519" }
            if rawValue.contains("ecdsa") || rawValue.contains("nistp") { return "ECDSA" }
            return "UNKNOWN"
        }
    }

    /// A readable algorithm + curve label.
    public var humanReadableName: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ed25519:
            return "Ed25519"
        case .ecdsa256:
            return "ECDSA P-256"
        case .ecdsa384:
            return "ECDSA P-384"
        case .ecdsa521:
            return "ECDSA P-521"
        default:
            // Attempt a friendly guess, otherwise surface the raw value.
            if rawValue.contains("nistp256") { return "ECDSA P-256" }
            if rawValue.contains("nistp384") { return "ECDSA P-384" }
            if rawValue.contains("nistp521") { return "ECDSA P-521" }
            if rawValue.hasPrefix("ssh-rsa") { return "RSA" }
            if rawValue.hasPrefix("ssh-ed25519") { return "Ed25519" }
            return rawValue
        }
    }

    // Codable as a single string value for backward compatibility with the
    // previous RawRepresentable enum implementation.
    public init(from decoder: Decoder) throws {
        let singleValueContainer = try decoder.singleValueContainer()
        self.rawValue = try singleValueContainer.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        try singleValueContainer.encode(rawValue)
    }
}
