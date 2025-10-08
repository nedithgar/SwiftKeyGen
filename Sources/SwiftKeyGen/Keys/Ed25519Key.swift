import Foundation
import Crypto
import _CryptoExtras

/// A private Ed25519 (Curve25519 in Edwards form) signing key and associated
/// metadata.
///
/// This type wraps a `Curve25519.Signing.PrivateKey` (CryptoKit) and exposes
/// helpers for producing SSH wire‐format public keys, OpenSSH *authorized_keys*
/// strings, and public key fingerprints. Only the minimal and commonly
/// required SSH operations are surfaced here; advanced format conversions and
/// certificate handling are implemented elsewhere in the library.
///
/// Security: Avoid persisting or transmitting the `privateKey` or its raw
/// seed unless absolutely necessary. Prefer exporting in encrypted private key
/// formats (e.g., future OpenSSH private key writer) once available.
public struct Ed25519Key: SSHKey {
    /// The SSH key type discriminator (always `ssh-ed25519`).
    public let keyType = KeyType.ed25519

    /// An optional human‑readable comment appended to rendered OpenSSH public
    /// key strings (e.g. user or host identifier).
    public var comment: String?

    /// Underlying CryptoKit private key object.
    ///
    /// Exposed publicly for advanced callers needing direct access to
    /// CryptoKit functionality (e.g. detached signatures outside SSH
    /// formatting). Use with care; leaking this value compromises the
    /// key. Prefer using the higher‑level helpers (`sign`, `publicKeyData`,
    /// etc.).
    public let privateKey: Curve25519.Signing.PrivateKey

    /// Internal convenience initializer from a CryptoKit private key.
    ///
    /// - Parameters:
    ///   - privateKey: Existing CryptoKit Ed25519 private key.
    ///   - comment: Optional comment to associate with the key.
    init(privateKey: Curve25519.Signing.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }

    /// Creates a key from a 32‑byte Ed25519 seed (raw private key data).
    ///
    /// The provided data must be exactly 32 bytes (RFC 8032 seed). The public
    /// key is derived deterministically from this seed.
    ///
    /// - Parameters:
    ///   - privateKeyData: 32‑byte seed for the Ed25519 key.
    ///   - comment: Optional comment stored with the key.
    /// - Throws: ``SSHKeyError/invalidKeyData`` if the seed length is not 32
    ///   bytes or CryptoKit rejects the raw representation.
    public init(privateKeyData: Data, comment: String? = nil) throws {
        guard privateKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        self.comment = comment
    }

    /// Produces the SSH wire‑format public key blob.
    ///
    /// Encoding layout (length‑prefixed fields):
    ///  1. `ssh-ed25519` (string)
    ///  2. 32‑byte public key
    ///
    /// - Returns: Concatenated SSH binary encoding suitable for inclusion in
    ///   OpenSSH public key lines (after Base64) or for fingerprinting.
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(privateKey.publicKey.rawRepresentation)
        return encoder.encode()
    }

    /// Returns the raw 32‑byte private key seed (NOT an OpenSSH private key
    /// file representation).
    ///
    /// - Warning: This is sensitive material. Handle using secure storage
    ///   primitives. Do not log or embed in source control.
    /// - Returns: The 32‑byte seed from which the key pair can be reproduced.
    public func privateKeyData() -> Data {
        // For full OpenSSH format, we'll implement that separately
        return privateKey.rawRepresentation
    }

    /// Renders the OpenSSH *authorized_keys* line representation.
    ///
    /// Format: `ssh-ed25519 <base64(publicKeyBlob)> [comment]`
    ///
    /// - Returns: A single‑line string ready to append to an
    ///   `authorized_keys` file.
    public func publicKeyString() -> String {
        let publicData = publicKeyData()
        var result = keyType.rawValue + " " + publicData.base64EncodedString()

        if let comment = comment {
            result += " " + comment
        }

        return result
    }

    /// Computes a fingerprint of the public key blob using the specified
    /// hash and output format.
    ///
    /// - Parameters:
    ///   - hash: The hash algorithm to apply (e.g. MD5, SHA‑256, SHA‑512).
    ///   - format: Output presentation for the digest (hex, Base64, bubble
    ///     babble). Defaults to ``FingerprintFormat/base64`` to mirror modern
    ///     OpenSSH usage for SHA‑256.
    /// - Returns: A human‑readable fingerprint string. For SHA‑based hashes a
    ///   `SHA256:` / `SHA512:` prefix is applied when using Base64 or hex,
    ///   matching OpenSSH conventions.
    public func fingerprint(hash: HashFunction, format: FingerprintFormat = .base64) -> String {
        let publicKey = publicKeyData()
        // Match OpenSSH behavior: bubblebabble is always over SHA-1
        if format == .bubbleBabble {
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }

        let digestData: Data
        let prefix: String

        switch hash {
        case .md5:
            let digest = Insecure.MD5.hash(data: publicKey)
            digestData = Data(digest)
            prefix = ""

        case .sha256:
            let digest = SHA256.hash(data: publicKey)
            digestData = Data(digest)
            prefix = "SHA256:"

        case .sha512:
            let digest = SHA512.hash(data: publicKey)
            digestData = Data(digest)
            prefix = "SHA512:"
        }

        switch format {
        case .hex:
            if hash == .md5 {
                return digestData.hexEncodedString(separator: ":")
            } else {
                return prefix + digestData.hexEncodedString()
            }

        case .base64:
            let base64 = digestData.base64EncodedStringStrippingPadding()
            return prefix + base64

        case .bubbleBabble:
            // Already handled above
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }
    }

    /// Creates an SSH‑formatted signature for the supplied message data.
    ///
    /// Internal API used by higher‑level signing / certificate flows.
    ///
    /// Encoding layout (SSH signature blob):
    ///  1. `ssh-ed25519` (string)
    ///  2. 64‑byte raw Ed25519 signature
    ///
    /// - Parameter data: Message to sign.
    /// - Returns: SSH wire‑format signature blob.
    /// - Throws: Any error propagated from CryptoKit during signing.
    func sign(data: Data) throws -> Data {
        let signature = try privateKey.signature(for: data)

        // Return SSH formatted signature
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(Data(signature))
        return encoder.encode()
    }

    /// Verifies either a raw 64‑byte Ed25519 signature or an SSH‑formatted
    /// signature blob for the provided message data.
    ///
    /// - Parameters:
    ///   - signature: Raw signature (64 bytes) or SSH signature encoding.
    ///   - data: The original message data.
    /// - Returns: `true` if the signature is valid; otherwise `false`.
    /// - Throws: Never (parsing failures fall back to raw verification).
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format if needed
        if signature.count > 4 {
            var decoder = SSHDecoder(data: signature)
            if let sigType = try? decoder.decodeString() {
                // This is SSH format, extract the actual signature
                if sigType == keyType.rawValue,
                   let sigData = try? decoder.decodeData() {
                    return privateKey.publicKey.isValidSignature(sigData, for: data)
                }
            }
        }
        // Fall back to raw signature
        return privateKey.publicKey.isValidSignature(signature, for: data)
    }
}

/// Ed25519 key pair generator.
///
/// Provides factory creation of new random Ed25519 key pairs. The `bits`
/// parameter is accepted for API symmetry with other algorithms but ignored
/// (Ed25519 has a fixed size).
public struct Ed25519KeyGenerator: SSHKeyGenerator {
    /// Generates a fresh Ed25519 key pair.
    ///
    /// - Parameters:
    ///   - bits: Unused; present for interface compatibility (ignored).
    ///   - comment: Optional comment attached to the resulting key.
    /// - Returns: A newly generated ``Ed25519Key`` instance.
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> Ed25519Key {
        // Ed25519 has a fixed key size, ignore bits parameter
        let privateKey = Curve25519.Signing.PrivateKey()
        return Ed25519Key(privateKey: privateKey, comment: comment)
    }
}
