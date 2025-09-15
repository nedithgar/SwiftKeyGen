import Foundation
import Crypto

/// Common interface for SSH key implementations.
///
/// Conforming types represent concrete key algorithms (e.g. RSA, Ed25519, ECDSA)
/// and provide access to standard SSH encodings and fingerprints.
public protocol SSHKey {
    /// The algorithm for this key.
    var keyType: KeyType { get }
    /// Optional comment appended to the OpenSSH public key string.
    var comment: String? { get set }
    
    /// Return the SSH wire‑format public key bytes.
    func publicKeyData() -> Data
    /// Return the raw private key bytes for the underlying algorithm.
    func privateKeyData() -> Data
    /// Return the OpenSSH public key string (e.g. for `authorized_keys`).
    func publicKeyString() -> String
    /// Compute a fingerprint for the public key.
    func fingerprint(hash: HashFunction, format: FingerprintFormat) -> String
}

/// Generator interface for key implementations.
public protocol SSHKeyGenerator {
    associatedtype KeyImplementation: SSHKey
    
    /// Generate a new key of the implementing type.
    /// - Parameters:
    ///   - bits: Optional key size override when applicable (e.g. RSA).
    ///   - comment: Optional key comment stored on the resulting key.
    static func generate(bits: Int?, comment: String?) throws -> KeyImplementation
}

/// Hash functions supported for key fingerprints.
public enum HashFunction {
    /// MD5 digest (legacy; produces `aa:bb:...` hex by default).
    case md5
    /// SHA‑256 digest (default; OpenSSH style with `SHA256:` prefix).
    case sha256
    /// SHA‑512 digest (OpenSSH style with `SHA512:` prefix).
    case sha512
}

/// Output formats for fingerprint strings.
public enum FingerprintFormat {
    /// Lowercase hexadecimal; MD5 uses colon separators.
    case hex
    /// Base64 without padding, prefixed with the hash label (e.g. `SHA256:`).
    case base64
    /// Bubble Babble encoding.
    case bubbleBabble
}
