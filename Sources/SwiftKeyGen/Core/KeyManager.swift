import Foundation
import Crypto

/// Manages operations on existing SSH keys
public struct KeyManager {
    
    /// Read a private key from file
    public static func readPrivateKey(
        from path: String,
        passphrase: String? = nil
    ) throws -> any SSHKey {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let data = try Data(contentsOf: URL(fileURLWithPath: expandedPath))
        return try OpenSSHPrivateKey.parse(data: data, passphrase: passphrase)
    }
    
    /// Change or remove the passphrase on an existing key
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
    
    /// Update the comment on an existing key
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
    
    /// Remove passphrase from a key (convenience method)
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
    
    /// Add passphrase to an unencrypted key (convenience method)
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
    
    /// Verify a passphrase for a key
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
    
    /// Get key information without decrypting the private key
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
    
    public struct KeyInfo {
        public let keyType: KeyType
        public let isEncrypted: Bool
        public let cipherName: String?
        public let publicKeyData: Data
        
        public var fingerprint: String {
            let digest = SHA256.hash(data: publicKeyData)
            let base64 = Data(digest).base64EncodedStringStrippingPadding()
            return "SHA256:" + base64
        }
    }
}
