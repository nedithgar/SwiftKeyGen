import Foundation

// TODO: Wait for SE-0487: Nonexhaustive Enums
/// A flexible identifier for SSH key algorithms.
///
/// `KeyType` models OpenSSH algorithm identifiers (for example, "ssh-ed25519",
/// "ssh-rsa", or "ecdsa-sha2-nistp256"). Instead of using a closed `enum`, it is
/// a string-backed `struct` that conforms to `RawRepresentable` and
/// `ExpressibleByStringLiteral`. This design keeps the public API stable while
/// allowing forward-compatibility with new algorithms introduced by OpenSSH
/// without requiring a library update.
///
/// - Design: Mirrors ``OpenSSHPrivateKey/EncryptionCipher`` by using a
///   `RawRepresentable` wrapper so unknown algorithms can be represented
///   losslessly via their raw string value.
/// - Backward compatibility: Existing call sites using static members like
///   ``KeyType/rsa``, equality checks, `switch` pattern matching on those known
///   members, and single-value `Codable` encoding/decoding continue to work.
/// - Forward compatibility: Unknown/future algorithms are preserved as-is via
///   ``rawValue``; helpers such as ``defaultBits``, ``algorithmName`` and
///   ``humanReadableName`` provide reasonable fallbacks when the algorithm is
///   not among the library's ``known`` set.
///
/// ### Examples
///
/// Create from a known static member:
/// ```swift
/// let t: KeyType = .ed25519
/// XCTAssertEqual(t.rawValue, "ssh-ed25519")
/// ```
///
/// Create from an arbitrary future algorithm string:
/// ```swift
/// let postQuantum: KeyType = "ssh-mlkem768@openquantum.org"
/// // Not in this library's known set, but still usable as an identifier
/// _ = postQuantum.rawValue
/// ```
///
/// Pattern matching with known cases remains ergonomic:
/// ```swift
/// switch KeyType.ed25519 {
/// case .ed25519:    print("Ed25519")
/// case .rsa:        print("RSA")
/// case .ecdsa256:   print("ECDSA P-256")
/// default:          print("Unknown/future")
/// }
/// ```
///
/// Encoding/decoding uses a single string value:
/// ```swift
/// let original: KeyType = .rsa
/// let data = try JSONEncoder().encode(original)
/// let decoded = try JSONDecoder().decode(KeyType.self, from: data)
/// XCTAssertEqual(decoded, .rsa)
/// ```
///
/// - SeeAlso: ``KeyGeneration``, ``KeyManager``, ``PublicKeys``
/// - Warning: Some helpers (for example, ``defaultBits``) intentionally return
///   neutral values for unknown algorithms to avoid guessing.
/// - TODO: Update once SE-0487 (Nonexhaustive Enums) is widely available and
///   evaluated for this use case.
///
/// ### Identifiable
///
/// ``KeyType`` conforms to ``Identifiable``. Its ``KeyType/id`` is the same as
/// ``KeyType/rawValue`` (the OpenSSH algorithm string). This makes it convenient
/// to use `KeyType` values in SwiftUI lists or other collections that require
/// a stable and unique identity. The identity remains stable across encoding
/// and decoding operations because the raw value round‑trips verbatim.
public struct KeyType: RawRepresentable, Hashable, Sendable, ExpressibleByStringLiteral, Codable, CaseIterable, Identifiable {
    /// The OpenSSH algorithm identifier backing this value.
    ///
    /// Examples: "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256".
    public let rawValue: String
    /// A stable identifier for this key type.
    ///
    /// This is equal to ``rawValue`` (for example, "ssh-ed25519", "ssh-rsa").
    /// It provides a unique, stable identity suitable for SwiftUI `List`/`ForEach`
    /// and other collection contexts.
    public var id: String { rawValue }
    
    /// Creates a new `KeyType` from a raw OpenSSH algorithm string.
    ///
    /// - Parameter rawValue: The OpenSSH algorithm identifier.
    /// - Returns: A `KeyType` that preserves the provided string exactly.
    /// - Note: The value is not validated here; unknown identifiers are allowed
    ///   to support forward‑compatibility.
    public init(rawValue: String) { self.rawValue = rawValue }
    
    /// Creates a new `KeyType` from a string literal.
    ///
    /// This allows convenient creation like `let t: KeyType = "ssh-ed25519"`.
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
    /// RSA key algorithm (OpenSSH: "ssh-rsa").
    public static let rsa: KeyType = "ssh-rsa"
    /// Ed25519 key algorithm (OpenSSH: "ssh-ed25519").
    public static let ed25519: KeyType = "ssh-ed25519"
    /// ECDSA over NIST P‑256 (OpenSSH: "ecdsa-sha2-nistp256").
    public static let ecdsa256: KeyType = "ecdsa-sha2-nistp256"
    /// ECDSA over NIST P‑384 (OpenSSH: "ecdsa-sha2-nistp384").
    public static let ecdsa384: KeyType = "ecdsa-sha2-nistp384"
    /// ECDSA over NIST P‑521 (OpenSSH: "ecdsa-sha2-nistp521").
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
    ///
    /// Examples:
    /// - ``KeyType/rsa`` → 3072
    /// - ``KeyType/ed25519`` → 256
    /// - ``KeyType/ecdsa256`` → 256
    /// - ``KeyType/ecdsa384`` → 384
    /// - ``KeyType/ecdsa521`` → 521
    /// - Unknown → 0
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
    ///
    /// For known algorithms, this returns one of "RSA", "ED25519", or
    /// "ECDSA". For unknown values, a lightweight heuristic is used based on
    /// the raw identifier (prefix checks and curve hints). If no match can be
    /// inferred, "UNKNOWN" is returned.
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
    ///
    /// Examples:
    /// - ``KeyType/rsa`` → "RSA"
    /// - ``KeyType/ed25519`` → "Ed25519"
    /// - ``KeyType/ecdsa256`` → "ECDSA P-256"
    /// - ``KeyType/ecdsa384`` → "ECDSA P-384"
    /// - ``KeyType/ecdsa521`` → "ECDSA P-521"
    ///
    /// For unknown algorithms, an attempt is made to produce a friendly label
    /// (for example, mapping "nistp256" to "ECDSA P-256"); otherwise the
    /// ``rawValue`` is returned verbatim so consumers can still display the
    /// exact identifier.
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
    /// Decodes a `KeyType` from a single string value.
    ///
    /// Decoding is lenient and accepts any string to preserve unknown
    /// algorithms. The exact value is stored in ``rawValue``.
    public init(from decoder: Decoder) throws {
        let singleValueContainer = try decoder.singleValueContainer()
        self.rawValue = try singleValueContainer.decode(String.self)
    }

    /// Encodes this `KeyType` as a single string value.
    ///
    /// The emitted value is the exact ``rawValue`` so round‑tripping preserves
    /// unknown/future algorithms unchanged.
    public func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        try singleValueContainer.encode(rawValue)
    }
}
