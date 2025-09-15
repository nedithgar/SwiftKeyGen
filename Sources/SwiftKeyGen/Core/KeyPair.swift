import Foundation

/// A convenience wrapper around an ``SSHKey`` providing
/// easy access to public and private representations.
public struct KeyPair {
    /// The generated private key.
    public let privateKey: any SSHKey
    
    /// The OpenSSH public key string (suitable for `authorized_keys`).
    public var publicKeyString: String {
        privateKey.publicKeyString()
    }
    
    /// The binary SSH-encoded public key bytes.
    public var publicKeyData: Data {
        privateKey.publicKeyData()
    }
    
    /// The raw private key data for the underlying algorithm.
    public var privateKeyData: Data {
        privateKey.privateKeyData()
    }
    
    /// Compute a fingerprint for the public key.
    ///
    /// - Parameters:
    ///   - hash: Hash function to use (MD5, SHA‑256, or SHA‑512).
    ///   - format: Output format for the digest string.
    /// - Returns: A formatted fingerprint string.
    public func fingerprint(hash: HashFunction = .sha256, format: FingerprintFormat = .base64) -> String {
        privateKey.fingerprint(hash: hash, format: format)
    }
}
