import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// File I/O helpers for reading and writing SSH keys.
public struct KeyFileManager {
    
    /// Key file type to write.
    public enum FileType {
        case privateKey
        case publicKey
    }
    
    // Special filename for stdin/stdout
    /// Special filename that indicates stdin/stdout should be used.
    public static let STDIN_STDOUT_FILENAME = "-"
    
    /// Write a key to a file or stdout.
    /// - Parameters:
    ///   - keyPair: The key pair to write.
    ///   - path: Destination path or "-" for stdout.
    ///   - type: Whether to write the private or public key.
    public static func writeKey(_ keyPair: KeyPair, to path: String, type: FileType) throws {
        // Check for stdout
        if path == STDIN_STDOUT_FILENAME {
            try writeToStdout(keyPair, type: type)
            return
        }
        
        let url = URL(fileURLWithPath: path)
        
        switch type {
        case .privateKey:
            try writePrivateKey(keyPair, to: url)
        case .publicKey:
            try writePublicKey(keyPair, to: url)
        }
    }
    
    private static func writePrivateKey(_ keyPair: KeyPair, to url: URL, passphrase: String? = nil) throws {
        // Write in OpenSSH private key format
        let data = try OpenSSHPrivateKey.serialize(
            key: keyPair.privateKey,
            passphrase: passphrase,
            comment: keyPair.privateKey.comment
        )
        
        // Write with restricted permissions (0600)
        try writeDataSecurely(data, to: url, permissions: 0o600)
    }
    
    private static func writePublicKey(_ keyPair: KeyPair, to url: URL) throws {
        let publicKeyString = keyPair.publicKeyString
        guard let data = publicKeyString.data(using: .utf8) else {
            throw SSHKeyError.serializationFailed("Failed to encode public key string")
        }
        
        // Public keys can have more relaxed permissions (0644)
        try writeDataSecurely(data, to: url, permissions: 0o644)
    }
    
    private static func writeDataSecurely(_ data: Data, to url: URL, permissions: Int) throws {
        // Create parent directory if needed
        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        
        // Write the file
        do {
            try data.write(to: url)
        } catch {
            throw SSHKeyError.fileOperationFailed("Failed to write file: \(error.localizedDescription)")
        }
        
        // Set permissions
        if !setFilePermissions(at: url.path, permissions: permissions) {
            // Try to remove the file if we can't set proper permissions
            try? FileManager.default.removeItem(at: url)
            throw SSHKeyError.fileOperationFailed("Failed to set file permissions")
        }
    }
    
    private static func setFilePermissions(at path: String, permissions: Int) -> Bool {
        #if os(Windows)
        // Windows doesn't support POSIX permissions
        return true
        #else
        return chmod(path, mode_t(permissions)) == 0
        #endif
    }
    
    /// Generate a key pair and write both files to disk.
    ///
    /// - Parameters:
    ///   - type: Key algorithm to generate.
    ///   - privatePath: Destination for the OpenSSH private key.
    ///   - publicPath: Optional destination for the public key (defaults to `<private>.pub`).
    ///   - bits: Optional size override (RSA only).
    ///   - comment: Optional public key comment.
    ///   - passphrase: Optional passphrase to encrypt the private key on disk.
    public static func generateKeyPairFiles(type: KeyType, 
                                            privatePath: String,
                                            publicPath: String? = nil,
                                            bits: Int? = nil,
                                            comment: String? = nil,
                                            passphrase: String? = nil) throws {
        // Generate the key pair
        let keyPair = try SwiftKeyGen.generateKeyPair(type: type, bits: bits, comment: comment)
        
        // Write private key
        let privateURL = URL(fileURLWithPath: privatePath)
        try writePrivateKey(keyPair, to: privateURL, passphrase: passphrase)
        
        // Write public key (default to private path + .pub)
        let pubPath = publicPath ?? (privatePath + ".pub")
        try writeKey(keyPair, to: pubPath, type: .publicKey)
    }
    
    // MARK: - Stdin/Stdout Support
    
    /// Write key data to stdout
    public static func writeToStdout(_ keyPair: KeyPair, type: FileType) throws {
        let data: Data
        
        switch type {
        case .privateKey:
            data = try OpenSSHPrivateKey.serialize(
                key: keyPair.privateKey,
                passphrase: nil,
                comment: keyPair.privateKey.comment
            )
        case .publicKey:
            guard let publicData = keyPair.publicKeyString.data(using: .utf8) else {
                throw SSHKeyError.serializationFailed("Failed to encode public key")
            }
            data = publicData
        }
        
        // Write to stdout
        FileHandle.standardOutput.write(data)
        
        // Add newline for public keys
        if type == .publicKey {
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
    }
    
    /// Write data to stdout
    public static func writeDataToStdout(_ data: Data) {
        FileHandle.standardOutput.write(data)
    }
    
    /// Write string to stdout
    public static func writeStringToStdout(_ string: String) {
        if let data = string.data(using: .utf8) {
            FileHandle.standardOutput.write(data)
        }
    }
    
    /// Read data from stdin
    public static func readFromStdin() throws -> Data {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard !data.isEmpty else {
            throw SSHKeyError.fileOperationFailed("No data available from stdin")
        }
        return data
    }
    
    /// Read string from stdin
    public static func readStringFromStdin() throws -> String {
        let data = try readFromStdin()
        guard let string = String(data: data, encoding: .utf8) else {
            throw SSHKeyError.fileOperationFailed("Invalid UTF-8 data from stdin")
        }
        return string
    }
    
    /// Read key from file or stdin
    public static func readKeyData(from path: String) throws -> Data {
        if path == STDIN_STDOUT_FILENAME {
            return try readFromStdin()
        } else {
            return try Data(contentsOf: URL(fileURLWithPath: path))
        }
    }
}
