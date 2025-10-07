import Foundation
import Crypto

/// High‑level utility for performing management operations on existing private SSH keys on disk.
///
/// `KeyManager` focuses on post‑generation lifecycle tasks such as:
///  - Loading encrypted / unencrypted OpenSSH private keys (`openssh-key-v1`)
///  - Adding, changing, or removing passphrases (re‑encrypting in place)
///  - Updating or synchronizing key comments (and the companion `.pub` file when present)
///  - Lightweight introspection of key metadata *without* decrypting the private portion
///  - Verifying passphrases provided by a user (constant‑time enough for UX loops)
///
/// All methods operate on the OpenSSH private key file format. Unsupported or malformed
/// inputs surface as ``SSHKeyError`` cases. Methods that mutate files attempt to
/// preserve secure POSIX permissions (`0600` for private keys, `0644` for public keys)
/// on Apple platforms.
public struct KeyManager {
    
    /// Reads and fully decodes an OpenSSH private key from disk.
    ///
    /// This will decrypt the key material if it is passphrase‑protected. The returned
    /// value conforms to ``SSHKey`` (e.g. ``RSAKey``, ``Ed25519Key``, ``ECDSAKey``).
    ///
    /// - Note: The path may include a leading tilde (`~`) which will be expanded.
    ///
    /// - Parameters:
    ///   - path: Filesystem path to the OpenSSH private key file.
    ///   - passphrase: Optional passphrase used to decrypt the key if encrypted.
    /// - Returns: A concrete type conforming to ``SSHKey`` representing the private key.
    /// - Throws: ``SSHKeyError.invalidFormat`` if parsing fails, ``SSHKeyError.decryptionFailed``
    ///           if the passphrase is wrong, or other ``SSHKeyError`` cases for unsupported types.
    public static func readPrivateKey(
        from path: String,
        passphrase: String? = nil
    ) throws -> any SSHKey {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let data = try Data(contentsOf: URL(fileURLWithPath: expandedPath))
        return try OpenSSHPrivateKey.parse(data: data, passphrase: passphrase)
    }
    
    /// Changes, adds, or removes the passphrase protecting an existing private key.
    ///
    /// The operation reads the current key, validates the provided `oldPassphrase` (if any),
    /// and rewrites the file using the specified `newPassphrase`. Supplying `nil` for
    /// `newPassphrase` removes encryption; supplying `nil` for `oldPassphrase` assumes the
    /// key is currently unencrypted.
    ///
    /// - Parameters:
    ///   - keyPath: Path to the existing OpenSSH private key file.
    ///   - oldPassphrase: Current passphrase (if the key is encrypted).
    ///   - newPassphrase: New passphrase to apply; pass `nil` to remove encryption.
    ///   - rounds: Cost parameter for the KDF (bcrypt) when encrypting.
    /// - Throws: ``SSHKeyError.decryptionFailed`` if the old passphrase is incorrect, or other
    ///           ``SSHKeyError`` values for format / serialization issues. I/O errors are also propagated.
    public static func changePassphrase(
        keyPath: String,
        oldPassphrase: String? = nil,
        newPassphrase: String? = nil,
        rounds: Int = OpenSSHPrivateKey.DEFAULT_ROUNDS
    ) throws {
        // Read the existing key
        let key = try readPrivateKey(from: keyPath, passphrase: oldPassphrase)
        
        // Serialize with new passphrase
        let newKeyData = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: newPassphrase,
            comment: key.comment,
            rounds: rounds
        )
        
        // Write back to file with secure permissions
        let expandedPath = NSString(string: keyPath).expandingTildeInPath
        try FileManager.default.createDirectory(
            atPath: (expandedPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true,
            attributes: nil
        )
        
        try newKeyData.write(to: URL(fileURLWithPath: expandedPath))
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: expandedPath
        )
        #endif
    }
    
    /// Updates the comment embedded in an OpenSSH private key and synchronizes the matching public key file.
    ///
    /// The private key is decrypted (if necessary), its `comment` field mutated, and the key is
    /// re‑serialized preserving its current encryption state. If a sibling `<path>.pub` file exists,
    /// its trailing comment segment is also updated to stay in sync.
    ///
    /// - Parameters:
    ///   - keyPath: Path to the OpenSSH private key file.
    ///   - passphrase: Passphrase if the key is encrypted.
    ///   - newComment: Replacement comment text.
    /// - Throws: ``SSHKeyError`` cases for parse/decrypt/serialize failures or propagated I/O errors.
    public static func updateComment(
        keyPath: String,
        passphrase: String? = nil,
        newComment: String
    ) throws {
        // Read the existing key
        var key = try readPrivateKey(from: keyPath, passphrase: passphrase)
        
        // Update comment
        key.comment = newComment
        
        // Serialize with same passphrase
        let newKeyData = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: passphrase,
            comment: newComment
        )
        
        // Write back to file
        let expandedPath = NSString(string: keyPath).expandingTildeInPath
        try newKeyData.write(to: URL(fileURLWithPath: expandedPath))
        
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: expandedPath
        )
        #endif
        
        // Also update the public key file if it exists
        let publicKeyPath = expandedPath + ".pub"
        if FileManager.default.fileExists(atPath: publicKeyPath) {
            let publicKeyString = key.publicKeyString()
            try publicKeyString.write(
                to: URL(fileURLWithPath: publicKeyPath),
                atomically: true,
                encoding: .utf8
            )
            
            #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: publicKeyPath
            )
            #endif
        }
    }
    
    /// Removes encryption from a passphrase‑protected private key (convenience wrapper).
    ///
    /// Equivalent to calling ``changePassphrase(keyPath:oldPassphrase:newPassphrase:rounds:)``
    /// with `newPassphrase` = `nil`.
    ///
    /// - Parameters:
    ///   - keyPath: Path to the encrypted private key file.
    ///   - currentPassphrase: Existing passphrase required to decrypt the key.
    /// - Throws: ``SSHKeyError.decryptionFailed`` if the passphrase is wrong or other errors encountered.
    public static func removePassphrase(
        keyPath: String,
        currentPassphrase: String
    ) throws {
        try changePassphrase(
            keyPath: keyPath,
            oldPassphrase: currentPassphrase,
            newPassphrase: nil
        )
    }
    
    /// Adds encryption to an unencrypted private key (convenience wrapper).
    ///
    /// Equivalent to calling ``changePassphrase(keyPath:oldPassphrase:newPassphrase:rounds:)``
    /// with `oldPassphrase` = `nil`.
    ///
    /// - Parameters:
    ///   - keyPath: Path to the unencrypted private key file.
    ///   - newPassphrase: Passphrase to apply.
    ///   - rounds: Cost (work factor) for bcrypt based KDF.
    /// - Throws: ``SSHKeyError`` cases or underlying I/O errors.
    public static func addPassphrase(
        keyPath: String,
        newPassphrase: String,
        rounds: Int = OpenSSHPrivateKey.DEFAULT_ROUNDS
    ) throws {
        try changePassphrase(
            keyPath: keyPath,
            oldPassphrase: nil,
            newPassphrase: newPassphrase,
            rounds: rounds
        )
    }
    
    /// Verifies whether a provided passphrase can successfully decrypt the key.
    ///
    /// - Parameters:
    ///   - keyPath: Path to the private key file.
    ///   - passphrase: Candidate passphrase (or `nil` if expecting no encryption).
    /// - Returns: `true` if the key can be parsed with the passphrase; otherwise `false`.
    /// - Note: This performs a full parse/decrypt attempt; repeated use in tight loops may be expensive.
    public static func verifyPassphrase(
        keyPath: String,
        passphrase: String?
    ) -> Bool {
        do {
            _ = try readPrivateKey(from: keyPath, passphrase: passphrase)
            return true
        } catch {
            return false
        }
    }
    
    /// Extracts public metadata about a private key without decrypting its private section.
    ///
    /// This performs a partial parse of the OpenSSH `openssh-key-v1` envelope to obtain:
    ///  - Key algorithm (``KeyType``)
    ///  - Whether the private portion is encrypted
    ///  - Cipher name (if encrypted)
    ///  - Raw SSH wire‑format public key bytes (suitable for fingerprinting)
    ///
    /// Private key block decryption is intentionally skipped for performance and to allow
    /// metadata inspection prior to prompting a user for a passphrase.
    ///
    /// - Parameter keyPath: Path to the OpenSSH private key file.
    /// - Returns: A ``KeyManager/KeyInfo`` structure with parsed metadata.
    /// - Throws: ``SSHKeyError.invalidFormat`` for malformed data, ``SSHKeyError.unsupportedKeyType``
    ///           for unknown algorithms, or underlying I/O errors.
    public static func getKeyInfo(keyPath: String) throws -> KeyInfo {
        let expandedPath = NSString(string: keyPath).expandingTildeInPath
        let data = try Data(contentsOf: URL(fileURLWithPath: expandedPath))
        
        guard let pemString = String(data: data, encoding: .utf8) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Check if it's an OpenSSH key
        guard pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----") else {
            throw SSHKeyError.invalidFormat
        }
        
        // Extract base64 content
        let lines = pemString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inKey = false
        
        for line in lines {
            if line.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                inKey = true
                continue
            }
            if line.contains("-----END OPENSSH PRIVATE KEY-----") {
                break
            }
            if inKey && !line.isEmpty {
                base64Lines.append(line)
            }
        }
        
        let base64String = base64Lines.joined()
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Read and verify magic header - it's not length-prefixed
        let magicLength = "openssh-key-v1\0".count
        guard keyData.count >= magicLength else {
            throw SSHKeyError.invalidFormat
        }
        
        let magicData = keyData.subdata(in: 0..<magicLength)
        let expectedMagic = Data("openssh-key-v1\0".utf8)
        guard magicData == expectedMagic else {
            throw SSHKeyError.invalidFormat
        }
        
        // Create decoder starting after the magic header
        var decoder = SSHDecoder(data: keyData.subdata(in: magicLength..<keyData.count))
        
        // Read cipher and KDF info
        let cipherName = try decoder.decodeString()
        let kdfName = try decoder.decodeString()
        
        // Skip KDF data
        _ = try decoder.decodeData()
        
        // Read number of keys
        let numKeys = try decoder.decodeUInt32()
        guard numKeys == 1 else {
            throw SSHKeyError.invalidFormat
        }
        
        // Read public key
        let publicKeyData = try decoder.decodeData()
        
        // Parse public key to get type
        var pubKeyDecoder = SSHDecoder(data: publicKeyData)
        let keyTypeString = try pubKeyDecoder.decodeString()
        
        guard let keyType = KeyType(rawValue: keyTypeString) else {
            throw SSHKeyError.unsupportedKeyType
        }
        
        return KeyInfo(
            keyType: keyType,
            isEncrypted: kdfName != "none",
            cipherName: cipherName == "none" ? nil : cipherName,
            publicKeyData: publicKeyData
        )
    }
    
    /// Lightweight metadata describing an OpenSSH private key, produced by ``getKeyInfo(keyPath:)``.
    public struct KeyInfo {
        /// Detected key algorithm (e.g. ``KeyType/ed25519``, ``KeyType/rsa``).
        public let keyType: KeyType
        /// Indicates whether the private key blob is encrypted (KDF name not `"none"`).
        public let isEncrypted: Bool
        /// Optional cipher name (e.g. `"aes256-ctr"`) when the key is encrypted; `nil` if unencrypted or `"none"`.
        public let cipherName: String?
        /// Raw SSH wire‑format public key data (starts with the key type length + name, followed by algorithm‑specific fields).
        public let publicKeyData: Data
        
        /// OpenSSH‑style SHA‑256 fingerprint computed over ``publicKeyData``.
        ///
        /// Mirrors the output of `ssh-keygen -lf <publickey>` (the `SHA256:` base64 format without padding).
        /// Suitable for display, logging, or host key verification contexts.
        public var fingerprint: String {
            let digest = SHA256.hash(data: publicKeyData)
            let base64 = Data(digest).base64EncodedStringStrippingPadding()
            return "SHA256:" + base64
        }
    }
}
