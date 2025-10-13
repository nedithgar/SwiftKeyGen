import Foundation
import Crypto
import _CryptoExtras
// TODO: Wait for SE-0487: Nonexhaustive Enums
/// A flexible identifier for key serialization formats supported by SwiftKeyGen.
///
/// `KeyFormat` models logical formats used throughout the library (for example,
/// "openssh", "pem", "pkcs8", or "rfc4716"). Instead of using a closed `enum`,
/// it is a string‑backed `struct` that conforms to `RawRepresentable` and
/// `ExpressibleByStringLiteral`. This mirrors the design used by ``KeyType`` and
/// keeps the public API stable while allowing forward‑compatibility with new or
/// project‑specific formats without requiring a library update.
///
/// - Design: Mirrors ``KeyType`` by using a `RawRepresentable` wrapper so
///   unknown formats can be represented losslessly via their raw string value.
/// - Backward compatibility: Static members like ``KeyFormat/openssh`` remain
///   convenient for switching over known formats, and the single‑value
///   `Codable` representation preserves existing behavior.
/// - Forward compatibility: Unknown/future formats are preserved as‑is via
///   ``rawValue``.
///
/// ### Identifiable
///
/// ``KeyFormat`` conforms to ``Identifiable``. Its ``KeyFormat/id`` equals
/// ``KeyFormat/rawValue`` (for example, "pem", "pkcs8"). This enables stable
/// identity in SwiftUI lists and other collections.
public struct KeyFormat: RawRepresentable, Hashable, Sendable, ExpressibleByStringLiteral, Codable, CaseIterable, Identifiable {
    /// The canonical string identifier backing this value.
    public let rawValue: String
    /// A stable identifier for this key format.
    ///
    /// This is equal to ``rawValue`` (for example, "openssh", "pem"). It
    /// provides a unique, stable identity suitable for SwiftUI `List`/`ForEach`
    /// and other collection contexts.
    public var id: String { rawValue }

    /// Creates a new `KeyFormat` from a raw format string.
    /// - Parameter rawValue: The format identifier (e.g., "openssh").
    /// - Note: The value is not validated here; unknown identifiers are allowed
    ///   to support forward‑compatibility.
    public init(rawValue: String) { self.rawValue = rawValue }

    /// Creates a new `KeyFormat` from a string literal.
    public init(stringLiteral value: String) { self.rawValue = value }

    // Keep a small internal backing enum for convenient checks when needed.
    internal enum BackingKeyFormat: String { case openssh, pem, pkcs8, rfc4716 }
    internal var knownBacking: BackingKeyFormat? { BackingKeyFormat(rawValue: rawValue) }

    // Known format constants (stable API surface)
    /// OpenSSH key format (private or public as context dictates).
    ///
    /// - Note: When exporting with ``KeyConverter/exportKey(_:formats:basePath:passphrase:)``,
    ///   this format writes exactly to `basePath` (no additional extension).
    public static let openssh: KeyFormat = "openssh"
    /// PEM‑encoded key containers.
    ///
    /// - Discussion: For RSA and Ed25519, the contents may be a PKCS#8
    ///   `PRIVATE KEY` document. For ECDSA, this can use the SEC1/RFC5915
    ///   `EC PRIVATE KEY` structure to match `ssh-keygen` output.
    public static let pem: KeyFormat = "pem"
    /// PKCS#8 key serialized as a PEM document (UTF‑8 text, not DER bytes).
    public static let pkcs8: KeyFormat = "pkcs8"
    /// RFC 4716 (SSH2) public key file format.
    public static let rfc4716: KeyFormat = "rfc4716"

    /// The set of formats known to this library version.
    public static var known: [KeyFormat] { [.openssh, .pem, .pkcs8, .rfc4716] }
    /// CaseIterable conformance (known only).
    public static var allCases: [KeyFormat] { known }

    // Codable as a single string value for backward compatibility with the
    // previous enum implementation.
    public init(from decoder: Decoder) throws {
        let singleValueContainer = try decoder.singleValueContainer()
        self.rawValue = try singleValueContainer.decode(String.self)
    }

    public func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        try singleValueContainer.encode(rawValue)
    }
}

/// Stateless helpers for converting keys between formats.
///
/// ``KeyConverter`` exposes static utility functions to encode SSH keys
/// to PEM, PKCS#8, or RFC4716, and to export multiple formats to disk.
/// All operations are pure and thread‑safe.
public struct KeyConverter {
    
    // RFC4716 format constants
    private static let SSH_COM_PUBLIC_BEGIN = "---- BEGIN SSH2 PUBLIC KEY ----"
    private static let SSH_COM_PUBLIC_END = "---- END SSH2 PUBLIC KEY ----"
    
    /// Converts the given private key to a PEM‑encoded string.
    ///
    /// - Parameters:
    ///   - key: The SSH private key to serialize.
    ///   - passphrase: Optional passphrase to encrypt the PEM document
    ///     when supported by the underlying key type.
    ///     - ECDSA uses SEC1 (RFC5915) and supports encryption.
    ///     - RSA encrypted PEM is not supported and will throw.
    ///     - Ed25519 currently ignores this parameter and produces an
    ///       unencrypted PKCS#8 `PRIVATE KEY` PEM.
    /// - Returns: A PEM string such as `-----BEGIN PRIVATE KEY----- ...` or
    ///   `-----BEGIN EC PRIVATE KEY----- ...`, depending on the key type.
    /// - Throws: ``SSHKeyError/unsupportedKeyType`` for unknown key types,
    ///   or ``SSHKeyError/unsupportedOperation(_:)`` when an encrypted PEM
    ///   is requested for a key type that does not support it.
    public static func toPEM(key: any SSHKey, passphrase: String? = nil) throws -> String {
        switch key {
        case let ed25519Key as Ed25519Key:
            return try ed25519ToPEM(ed25519Key, passphrase: passphrase)
            
        case let rsaKey as RSAKey:
            return try rsaToPEM(rsaKey, passphrase: passphrase)
            
        case let ecdsaKey as ECDSAKey:
            return try ecdsaToPEM(ecdsaKey, passphrase: passphrase)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Converts the given private key to PKCS#8 as PEM data.
    ///
    /// - Parameters:
    ///   - key: The SSH private key to serialize.
    ///   - passphrase: Optional passphrase. ECDSA supports encrypted
    ///     PKCS#8 PEM; RSA encrypted PKCS#8 is not supported and will throw;
    ///     Ed25519 currently returns an unencrypted PKCS#8 PEM.
    /// - Returns: UTF‑8 `Data` containing a PEM‑encoded PKCS#8 document.
    ///   This method does not return DER bytes.
    /// - Throws: ``SSHKeyError/unsupportedKeyType`` or
    ///   ``SSHKeyError/unsupportedOperation(_:)`` depending on the key type
    ///   and `passphrase` support.
    public static func toPKCS8(key: any SSHKey, passphrase: String? = nil) throws -> Data {
        switch key {
        case let ed25519Key as Ed25519Key:
            return try ed25519ToPKCS8(ed25519Key, passphrase: passphrase)
            
        case let rsaKey as RSAKey:
            return try rsaToPKCS8(rsaKey, passphrase: passphrase)
            
        case let ecdsaKey as ECDSAKey:
            return try ecdsaToPKCS8(ecdsaKey, passphrase: passphrase)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Converts the public portion of the key to RFC 4716 format.
    ///
    /// - Parameter key: The key whose public component will be exported.
    /// - Returns: A string wrapped with RFC 4716 `BEGIN/END SSH2 PUBLIC KEY`
    ///   markers, including a `Comment:` header. The base64 body is wrapped
    ///   at 70 characters as per the specification.
    /// - Throws: Currently never throws, but declared `throws` for parity with
    ///   other conversion routines and future extensibility.
    /// - Discussion: If ``SSHKey/comment`` is `nil`, the comment defaults to
    ///   `username@hostname` using the current process information.
    public static func toRFC4716(key: any SSHKey) throws -> String {
        // Get the public key data
        let publicKeyData = key.publicKeyData()
        
        // Format the comment
        let comment = key.comment ?? "\(NSUserName())@\(ProcessInfo.processInfo.hostName)"
        
        // Build RFC4716 format
        var output = SSH_COM_PUBLIC_BEGIN + "\n"
        output += "Comment: \"\(comment)\"\n"
        
        // Base64 encode with 70-character line width
        output += publicKeyData.base64EncodedString(wrappedAt: 70) + "\n"
        
        output += SSH_COM_PUBLIC_END + "\n"
        
        return output
    }
    
    // MARK: - Ed25519 Conversion
    
    private static func ed25519ToPEM(_ key: Ed25519Key, passphrase: String?) throws -> String {
        let privateKeyData = key.privateKeyData()
        
        // Build PEM structure
        var pem = "-----BEGIN PRIVATE KEY-----\n"
        
        // Create PKCS#8 structure for Ed25519
        var pkcs8 = Data()
        
        // Version (0)
        pkcs8.append(contentsOf: [0x30, 0x2e, 0x02, 0x01, 0x00])
        
        // Algorithm identifier for Ed25519
        pkcs8.append(contentsOf: [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])
        
        // Private key
        pkcs8.append(contentsOf: [0x04, 0x22, 0x04, 0x20])
        pkcs8.append(privateKeyData)
        
        let base64 = pkcs8.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        pem += base64
        pem += "\n-----END PRIVATE KEY-----"
        
        return pem
    }
    
    private static func ed25519ToPKCS8(_ key: Ed25519Key, passphrase: String?) throws -> Data {
        let pem = try ed25519ToPEM(key, passphrase: passphrase)
        return Data(pem.utf8)
    }
    
    // MARK: - RSA Conversion
    
    private static func rsaToPEM(_ key: RSAKey, passphrase: String?) throws -> String {
        // Swift Crypto's RSA private key can export PEM directly
        if passphrase != nil {
            throw SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")
        }
        
        return key.pemRepresentation
    }
    
    private static func rsaToPKCS8(_ key: RSAKey, passphrase: String?) throws -> Data {
        // PKCS#8 wrapper for RSA
        let pem = try rsaToPEM(key, passphrase: passphrase)
        return Data(pem.utf8)
    }
    
    // MARK: - ECDSA Conversion
    
    private static func ecdsaToPEM(_ key: ECDSAKey, passphrase: String?) throws -> String {
        // PEM format for ECDSA should output SEC1/RFC5915 format to match ssh-keygen
        if let passphrase = passphrase {
            // Use encrypted PEM format
            return try key.sec1PEMRepresentation(passphrase: passphrase)
        } else {
            // Use plain PEM format
            return key.sec1PEMRepresentation
        }
    }
    
    private static func ecdsaToPKCS8(_ key: ECDSAKey, passphrase: String?) throws -> Data {
        // PKCS#8 format - use encrypted version if passphrase provided
        let pem: String
        if let passphrase = passphrase {
            // Use encrypted PKCS#8 format
            pem = try key.pkcs8PEMRepresentation(passphrase: passphrase)
        } else {
            // Use plain PKCS#8 format
            pem = key.pkcs8PEMRepresentation
        }
        
        return Data(pem.utf8)
    }
    
    /// Exports a key in one or more formats and writes each to disk.
    ///
    /// - Parameters:
    ///   - key: The SSH private key to export.
    ///   - formats: The set of formats to write.
    ///   - basePath: Base file path. For ``KeyFormat/openssh``, the file is
    ///     written exactly to `basePath`. Other formats append an extension:
    ///     `.pem` (PEM), `.p8` (PKCS#8 PEM), `.rfc` (RFC 4716 public key).
    ///   - passphrase: Optional passphrase used when a format and key type
    ///     support encryption. See ``toPEM(key:passphrase:)`` and
    ///     ``toPKCS8(key:passphrase:)`` for specifics.
    /// - Returns: A dictionary mapping each requested format to the absolute
    ///   file path written.
    /// - Throws: Errors from serialization routines or file I/O.
    /// - Note: Existing files at the resolved paths are overwritten.
    public static func exportKey(
        _ key: any SSHKey,
        formats: Set<KeyFormat>,
        basePath: String,
        passphrase: String? = nil
    ) throws -> [KeyFormat: String] {
        var results: [KeyFormat: String] = [:]
        
        for format in formats {
            let path: String
            let data: Data
            
            switch format {
            case .openssh:
                path = basePath
                data = try OpenSSHPrivateKey.serialize(
                    key: key,
                    passphrase: passphrase,
                    comment: key.comment
                )
                
            case .pem:
                path = basePath + ".pem"
                let pemString = try toPEM(key: key, passphrase: passphrase)
                data = Data(pemString.utf8)
                
            case .pkcs8:
                path = basePath + ".p8"
                data = try toPKCS8(key: key, passphrase: passphrase)
                
            case .rfc4716:
                path = basePath + ".rfc"
                let rfc4716String = try toRFC4716(key: key)
                data = Data(rfc4716String.utf8)
            default:
                throw SSHKeyError.unsupportedOperation("Unsupported or unknown export format: \(format.rawValue)")
            }
            
            try data.write(to: URL(fileURLWithPath: path))
            results[format] = path
        }
        
        return results
    }
}
