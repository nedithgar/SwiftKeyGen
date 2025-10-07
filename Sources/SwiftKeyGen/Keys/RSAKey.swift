import Foundation
import Crypto

/// A concrete SSH private key representing an RSA key pair.
///
/// `RSAKey` wraps the project’s RSA implementation (``Insecure/RSA``) and provides
/// higher‑level conveniences aligned with OpenSSH tooling:
///
/// - Produces SSH wire‑format public key blobs (``publicKeyData()``)
/// - Produces an OpenSSH `authorized_keys` style public key string (``publicKeyString()``)
/// - Exposes PKCS#1 DER private key material (``privateKeyData()``) for downstream
///   container formats (PEM / OpenSSH private key serialization is handled elsewhere)
/// - Computes public key fingerprints across multiple hash + output formats (``fingerprint(hash:format:)``)
///
/// Instances are typically created via ``RSAKeyGenerator`` rather than directly.
/// You can also construct one internally from an existing ``Insecure/RSA/PrivateKey``
/// (e.g. after parsing) using the internal initializer.
public struct RSAKey: SSHKey {
    /// The strongly‑typed SSH key kind (`rsa`).
    ///
    /// Mirrors ``KeyType/rsa`` and is emitted as the leading field in SSH public key blobs
    /// and OpenSSH `authorized_keys` lines.
    public let keyType = KeyType.rsa

    /// Optional human‑readable comment appended in OpenSSH public key text form.
    ///
    /// Commonly used to store an email address, username, host, or purpose marker.
    /// This value does not affect cryptographic properties.
    public var comment: String?
    
    /// The underlying RSA private key primitive.
    ///
    /// Exposed publicly for advanced operations that may require direct access.
    /// Prefer using the high‑level APIs on ``RSAKey`` where possible to preserve
    /// consistent encoding and defensive behaviors.
    public let privateKey: Insecure.RSA.PrivateKey
    
    init(privateKey: Insecure.RSA.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }
    
    /// Encodes the public portion of the key in SSH wire format.
    ///
    /// The returned blob matches the OpenSSH binary layout:
    ///
    /// ```
    /// string    "ssh-rsa"          (algorithm identifier)
    /// mpint     e                  (public exponent)
    /// mpint     n                  (modulus)
    /// ```
    ///
    /// - Returns: A `Data` value suitable for inclusion in higher‑level envelopes
    ///   (e.g. `authorized_keys` text line base64 section, certificate signing, fingerprinting).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        
        let publicKey = privateKey.publicKey
        encoder.encodeBigInt(publicKey.exponentData)
        encoder.encodeBigInt(publicKey.modulusData)
        
        return encoder.encode()
    }
    
    /// Exposes the raw private key encoded as PKCS#1 DER (`RSAPrivateKey`).
    ///
    /// This does **not** wrap the key in PEM headers/footers or the OpenSSH
    /// proprietary private key container; those responsibilities live in
    /// format modules under `Sources/SwiftKeyGen/Formats/`.
    ///
    /// - Returns: DER bytes of the PKCS#1 `RSAPrivateKey` sequence, or empty `Data`
    ///   if an encoding failure occurs (should be rare). Failures are intentionally
    ///   swallowed to avoid throwing in simple introspection contexts.
    public func privateKeyData() -> Data {
        // Return PKCS#1 DER-encoded RSA private key (RSAPrivateKey)
        // OpenSSH private key container serialization is handled in Formats/OpenSSH
        if let der = try? privateKey.pkcs1DERRepresentation() {
            return der
        }
        return Data()
    }
    
    /// Produces the canonical OpenSSH public key text line (`authorized_keys` format).
    ///
    /// Layout: `<type> <base64(wire-format)> [comment]`.
    ///
    /// - Returns: A UTF‑8 string safe to append to an `authorized_keys` file or
    ///   use in clipboard / provisioning contexts.
    public func publicKeyString() -> String {
        let publicData = publicKeyData()
        var result = keyType.rawValue + " " + publicData.base64EncodedString()
        
        if let comment = comment {
            result += " " + comment
        }
        
        return result
    }
    
    /// Computes a fingerprint of the SSH public key blob using a selected hash and presentation.
    ///
    /// The hash is taken over the SSH wire‑format public key returned by ``publicKeyData()``.
    ///
    /// - Parameters:
    ///   - hash: The hash function to apply (e.g. ``HashFunction/sha256``).
    ///   - format: Output representation (hex, base64, bubble babble). Defaults to ``FingerprintFormat/base64``.
    /// - Returns: A formatted fingerprint string. For SHA‑based hashes, a `SHA256:`/`SHA512:` prefix
    ///   mirrors OpenSSH conventions. MD5 fingerprints are colon‑separated hex (legacy compatibility).
    public func fingerprint(hash: HashFunction, format: FingerprintFormat = .base64) -> String {
        let publicKey = publicKeyData()
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
            return BubbleBabble.encode(digestData)
        }
    }
    
    /// Create an SSH‑formatted signature for `data`.
    ///
    /// Uses `rsa-sha2-256` by default.
    func sign(data: Data) throws -> Data {
        // Default to SHA256 for RSA signatures
        return try signWithAlgorithm(data: data, algorithm: "rsa-sha2-256")
    }
    
    /// Create an SSH‑formatted signature for `data` using `algorithm`.
    /// - Parameter algorithm: One of `ssh-rsa`, `rsa-sha2-256`, or `rsa-sha2-512`.
    func signWithAlgorithm(data: Data, algorithm: String) throws -> Data {
        // Sign the data based on algorithm
        let signatureData: Data
        
        switch algorithm {
        case "ssh-rsa":
            // SHA1 signature for legacy compatibility
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha1)
            
        case "rsa-sha2-256":
            // SHA256 signature (recommended)
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha256)
            
        case "rsa-sha2-512":
            // SHA512 signature
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha512)
            
        default:
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
        
        // Encode in SSH format
        var encoder = SSHEncoder()
        encoder.encodeString(algorithm)
        encoder.encodeData(signatureData)
        
        return encoder.encode()
    }
    
    /// Verify an SSH‑formatted signature for `data`.
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        let publicKey = privateKey.publicKey
        
        // Verify based on signature type
        switch signatureType {
        case "ssh-rsa":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha1)
        case "rsa-sha2-256":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha256)
        case "rsa-sha2-512":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha512)
        default:
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
    }
    
    // Helper property for compatibility with existing code
    var pemRepresentation: String {
        do {
            return try privateKey.pkcs1PEMRepresentation()
        } catch {
            // Return empty string if encoding fails
            return ""
        }
    }
}

/// Factory utilities for creating ``RSAKey`` instances with validated modulus sizes.
///
/// Centralizes OpenSSH‑aligned bounds checking (minimum and maximum bit lengths,
/// byte alignment) to ensure consistent key strength and compatibility.
public struct RSAKeyGenerator: SSHKeyGenerator {
    // Constants matching OpenSSH
    private static let SSH_RSA_MINIMUM_MODULUS_SIZE = 1024
    private static let OPENSSL_RSA_MAX_MODULUS_BITS = 16384
    
    /// Generates a new RSA key pair.
    ///
    /// Performs strict validation before key generation:
    /// - Enforces a minimum modulus size of 1024 bits (legacy lower bound; consider 2048+ for modern use)
    /// - Enforces an upper bound consistent with OpenSSL (16384 bits)
    /// - Requires the bit size to be an exact multiple of 8
    ///
    /// - Parameters:
    ///   - bits: Desired modulus length. If `nil`, defaults to ``KeyType/rsa``'s ``KeyType/defaultBits``.
    ///   - comment: Optional comment to embed in the resulting key’s public string.
    /// - Returns: A freshly generated ``RSAKey`` containing a secure random key pair.
    /// - Throws: ``SSHKeyError/invalidKeySize(_:_:)`` when outside accepted bounds or not byte aligned.
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> RSAKey {
        let keySize = bits ?? KeyType.rsa.defaultBits
        
        // Validate key size according to OpenSSH standards
        guard keySize >= SSH_RSA_MINIMUM_MODULUS_SIZE else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must be at least \(SSH_RSA_MINIMUM_MODULUS_SIZE) bits")
        }
        
        guard keySize <= OPENSSL_RSA_MAX_MODULUS_BITS else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must not exceed \(OPENSSL_RSA_MAX_MODULUS_BITS) bits")
        }
        
        // Ensure key size is a multiple of 8
        guard keySize % 8 == 0 else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must be a multiple of 8")
        }
        
        // Generate RSA key pair using our implementation
        let (privateKey, _) = try Insecure.RSA.generateKeyPair(bitSize: keySize)
        return RSAKey(privateKey: privateKey, comment: comment)
    }
}
