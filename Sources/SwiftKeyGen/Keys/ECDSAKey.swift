import Foundation
import Crypto

/// An elliptic curve (ECDSA) private key supporting NIST curves
/// P-256, P-384, and P-521.
///
/// This type encapsulates the private key material and exposes SSH‑compatible
/// public key emission, fingerprinting, and serialization utilities used
/// throughout the library (e.g. for `authorized_keys`, certificate signing,
/// and format conversion).
///
/// Instances are created via the ``ECDSAKeyGenerator`` factory which ensures
/// correct curve selection and centralizes generation policy.
///
/// ### Supported Curves
/// - ``KeyType/ecdsa256`` (nistp256 / P‑256)
/// - ``KeyType/ecdsa384`` (nistp384 / P‑384)
/// - ``KeyType/ecdsa521`` (nistp521 / P‑521)
///
/// ### Thread Safety
/// Keys are immutable value types; concurrent reads are safe. Avoid copying
/// instances unnecessarily to limit duplication of private key material in
/// memory.
///
/// ### Security Notes
/// - The private key's raw bytes can be accessed via ``privateKeyData()``.
///   Only export or persist them using secure storage.
/// - Use the provided SSH / PEM encoders instead of crafting ad‑hoc formats.
public struct ECDSAKey: SSHKey {
    /// The key's SSH key type representing curve / algorithm (e.g. ``KeyType/ecdsa256``).
    public let keyType: KeyType
    /// Optional trailing comment preserved when emitting OpenSSH public key strings.
    public var comment: String?
    
    internal enum PrivateKeyStorage {
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
    }
    
    internal let privateKeyStorage: PrivateKeyStorage
    
    init(p256Key: P256.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa256
        self.privateKeyStorage = .p256(p256Key)
        self.comment = comment
    }
    
    init(p384Key: P384.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa384
        self.privateKeyStorage = .p384(p384Key)
        self.comment = comment
    }
    
    init(p521Key: P521.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa521
        self.privateKeyStorage = .p521(p521Key)
        self.comment = comment
    }
    
    /// Returns the SSH wire‑format public key payload for this ECDSA key.
    ///
    /// The encoded structure is:.
    /// ```
    /// string    <key type>          (e.g. "ecdsa-sha2-nistp256")
    /// string    <curve identifier>  (e.g. "nistp256")
    /// string    <EC point (0x04 || X || Y) in uncompressed ANSI X9.63 form>
    /// ```
    /// - Returns: A `Data` value containing the SSH binary public key suitable
    ///   for inclusion in higher‑level structures (e.g. OpenSSH public key line encoding).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        
        // Encode curve identifier
        let curveIdentifier: String
        let publicKeyData: Data
        
        switch privateKeyStorage {
        case .p256(let key):
            curveIdentifier = "nistp256"
            publicKeyData = key.publicKey.x963Representation
        case .p384(let key):
            curveIdentifier = "nistp384"
            publicKeyData = key.publicKey.x963Representation
        case .p521(let key):
            curveIdentifier = "nistp521"
            publicKeyData = key.publicKey.x963Representation
        }
        
        encoder.encodeString(curveIdentifier)
        encoder.encodeData(publicKeyData)
        
        return encoder.encode()
    }
    
    /// Returns the raw private key bytes for the selected curve.
    ///
    /// For NIST curves this is the big‑endian integer `d` in fixed size per curve.
    ///
    /// - Important: Exposing raw private key material increases risk of leakage.
    ///   Avoid persisting or logging this unless absolutely necessary and secured.
    /// - Returns: Raw curve private scalar bytes.
    public func privateKeyData() -> Data {
        // Return raw private key data for now
        switch privateKeyStorage {
        case .p256(let key):
            return key.rawRepresentation
        case .p384(let key):
            return key.rawRepresentation
        case .p521(let key):
            return key.rawRepresentation
        }
    }
    
    /// Produces the OpenSSH public key line value (type + base64 + optional comment).
    ///
    /// Example output:
    /// ```text
    /// ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB... user@host
    /// ```
    ///
    /// - Returns: A UTF‑8 `String` appropriate for `authorized_keys`, `known_hosts`
    ///   (after host prefixing), or clipboard export.
    public func publicKeyString() -> String {
        let publicData = publicKeyData()
        var result = keyType.rawValue + " " + publicData.base64EncodedString()
        
        if let comment = comment {
            result += " " + comment
        }
        
        return result
    }
    
    /// Computes a fingerprint over the SSH public key data using the selected hash.
    ///
    /// The hash is computed over the binary SSH wire representation returned by
    /// ``publicKeyData()``. Formatting follows OpenSSH conventions:
    /// - MD5 + hex: colon‑delimited lower‑case hex (`aa:bb:...`)
    /// - SHA256/SHA512 + base64: `SHA256:<value>` or `SHA512:<value>` (padding removed)
    ///
    /// - Parameters:
    ///   - hash: The digest algorithm to apply.
    ///   - format: Output representation (default ``FingerprintFormat/base64``).
    /// - Returns: The fingerprint string.
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
    func sign(data: Data) throws -> Data {
        // Sign the data (CryptoKit handles hashing internally based on curve)
        let ecdsaSignature: Data
        switch privateKeyStorage {
        case .p256(let key):
            // P256 uses SHA256 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p384(let key):
            // P384 uses SHA384 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p521(let key):
            // P521 uses SHA512 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        }
        
        // Parse r and s from the signature
        let keySize: Int
        switch keyType {
        case .ecdsa256:
            keySize = 32
        case .ecdsa384:
            keySize = 48
        case .ecdsa521:
            keySize = 66
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        guard ecdsaSignature.count == keySize * 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let r = ecdsaSignature.prefix(keySize)
        let s = ecdsaSignature.suffix(keySize)
        
        // Encode in SSH format
        var sigEncoder = SSHEncoder()
        sigEncoder.encodeBigInt(r)
        sigEncoder.encodeBigInt(s)
        
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(sigEncoder.encode())
        
        return encoder.encode()
    }
    
    /// Verify a signature for `data`.
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Create a public-only version of this key and use it for verification
        let publicOnlyKey = self.publicOnlyKey() as! ECDSAPublicKey
        return try publicOnlyKey.verify(signature: signature, for: data)
    }
    
    /// Get raw signature without SSH formatting (for internal use).
    func rawSignature(for data: Data) throws -> Data {
        // Get the raw ECDSA signature
        let ecdsaSignature: Data
        switch privateKeyStorage {
        case .p256(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p384(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p521(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        }
        
        // Determine key size
        let keySize: Int
        switch keyType {
        case .ecdsa256:
            keySize = 32
        case .ecdsa384:
            keySize = 48
        case .ecdsa521:
            keySize = 66
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        guard ecdsaSignature.count == keySize * 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let r = ecdsaSignature.prefix(keySize)
        let s = ecdsaSignature.suffix(keySize)
        
        // For certificates, we need to return r,s encoded in SSH format
        // This matches what the verifier expects
        var sigEncoder = SSHEncoder()
        sigEncoder.encodeBigInt(r)
        sigEncoder.encodeBigInt(s)
        
        return sigEncoder.encode()
    }
    
    /// The key's PKCS#8 PEM representation.
    ///
    /// This delegates to CryptoKit's PKCS#8 encoder. The returned value includes:
    /// - `-----BEGIN PRIVATE KEY-----` header
    /// - Base64 body (wrapped)
    /// - `-----END PRIVATE KEY-----` footer
    ///
    /// - Note: No encryption is applied. Wrap / protect externally if storing on disk.
    public var pemRepresentation: String {
        switch privateKeyStorage {
        case .p256(let key):
            return key.pemRepresentation
        case .p384(let key):
            return key.pemRepresentation
        case .p521(let key):
            return key.pemRepresentation
        }
    }
    
    /// Verify raw signature without SSH formatting (for internal use).
    func verifyRawSignature(_ signature: Data, for data: Data) throws -> Bool {
        // Parse the SSH encoded signature (r, s components)
        var decoder = SSHDecoder(data: signature)
        let r = try decoder.decodeData()
        let s = try decoder.decodeData()
        
        switch privateKeyStorage {
        case .p256(let key):
            let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 32)
            guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        case .p384(let key):
            let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 48)
            guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        case .p521(let key):
            let raw = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 66)
            guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        }
    }
}

/// Factory utilities for generating new ECDSA private keys.
///
/// Use these static helpers instead of constructing `ECDSAKey` directly to
/// ensure consistent curve selection and future policy hooks (entropy sources,
/// auditing, defaults, etc.).
public struct ECDSAKeyGenerator {
    /// Generates a new P‑256 ECDSA private key.
    ///
    /// - Parameter comment: Optional comment stored with the key for display/export.
    /// - Returns: A freshly generated ECDSA key on the P‑256 curve.
    public static func generateP256(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P256.Signing.PrivateKey()
        return ECDSAKey(p256Key: privateKey, comment: comment)
    }
    
    /// Generates a new P‑384 ECDSA private key.
    ///
    /// - Parameter comment: Optional comment stored with the key for display/export.
    /// - Returns: A freshly generated ECDSA key on the P‑384 curve.
    public static func generateP384(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P384.Signing.PrivateKey()
        return ECDSAKey(p384Key: privateKey, comment: comment)
    }
    
    /// Generates a new P‑521 ECDSA private key.
    ///
    /// - Parameter comment: Optional comment stored with the key for display/export.
    /// - Returns: A freshly generated ECDSA key on the P‑521 curve.
    public static func generateP521(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P521.Signing.PrivateKey()
        return ECDSAKey(p521Key: privateKey, comment: comment)
    }
    
    /// Generates an ECDSA private key for the specified SSH key type.
    ///
    /// - Parameters:
    ///   - curve: One of ``KeyType/ecdsa256``, ``KeyType/ecdsa384``, ``KeyType/ecdsa521``.
    ///   - comment: Optional comment stored with the key.
    /// - Returns: A freshly generated key for the requested curve.
    /// - Throws: ``SSHKeyError/unsupportedKeyType`` if `curve` is not an ECDSA curve.
    public static func generate(curve: KeyType, comment: String? = nil) throws -> ECDSAKey {
        switch curve {
        case .ecdsa256:
            return try generateP256(comment: comment)
        case .ecdsa384:
            return try generateP384(comment: comment)
        case .ecdsa521:
            return try generateP521(comment: comment)
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
}
