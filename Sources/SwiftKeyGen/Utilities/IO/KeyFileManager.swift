import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A namespace of convenience utilities for securely reading and writing SSH key
/// material (private and public) to and from the file system or standard
/// input/output streams.
///
/// Responsibilities:
/// - Securely persisting OpenSSH private keys with appropriate POSIX file
///   permissions (0600)
/// - Writing public keys with standard permissions (0644)
/// - Generating new key pairs and atomically emitting both private & public
///   key files
/// - Providing `stdin` / `stdout` passthrough for pipeline‑friendly CLI flows
/// - Normalizing error surfaces through `SSHKeyError`
///
/// All write helpers attempt to enforce least‑privilege permissions; if setting
/// permissions fails the write is treated as unsuccessful and the partially
/// written file is removed (best effort) to avoid leaving sensitive material on
/// disk with relaxed permissions.
public struct KeyFileManager {
    
    /// Identifies which portion of a key pair should be written.
    public enum FileType {
        /// The private key file (e.g. OpenSSH private key). Must be protected
        /// with restrictive permissions (0600). May be optionally passphrase
        /// encrypted at serialization time.
        case privateKey
        /// The public key file (e.g. `ssh-ed25519 AAAA... comment`). Safe for
        /// wider readability (0644).
        case publicKey
    }
    
    // MARK: Sentinel Filenames
    /// Sentinel filename indicating that standard input (for reads) or
    /// standard output (for writes) should be used instead of a filesystem
    /// path. Mirrors common Unix tool behavior (e.g. `cat -`).
    public static let STDIN_STDOUT_FILENAME = "-"
    
    /// Writes either the private or public half of a key pair to a file system
    /// location or (when `path == "-"`) to standard output.
    ///
    /// The method ensures:
    /// - Private keys are serialized in OpenSSH format (optionally encrypted
    ///   if a passphrase was supplied upstream) and written with permissions
    ///   `0600`.
    /// - Public keys are emitted in the canonical single‑line OpenSSH public
    ///   key format with permissions `0644`.
    /// - Standard output receives raw bytes directly when the sentinel path is
    ///   used.
    ///
    /// - Parameters:
    ///   - keyPair: The in‑memory key pair containing both private and public
    ///     material.
    ///   - path: Destination filesystem path or `"-"` to target stdout.
    ///   - type: Which component of the pair to write.
    /// - Throws: `SSHKeyError.serializationFailed` if encoding fails, or
    ///   `SSHKeyError.fileOperationFailed` for write / permission errors.
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
    
    /// Generates a new key pair and persists both its private and public
    /// components to disk, enforcing secure default permissions.
    ///
    /// Behavior:
    /// - Private key serialized in OpenSSH format (optionally encrypted via
    ///   provided `passphrase`) with permissions `0600`.
    /// - Public key written in standard single‑line OpenSSH form with
    ///   permissions `0644`.
    /// - If `publicPath` is omitted the path is derived by appending `.pub` to
    ///   `privatePath`.
    /// - RSA key sizes can be overridden via `bits`; other algorithms ignore
    ///   the value.
    ///
    /// - Parameters:
    ///   - type: Algorithm of key to generate (e.g. `.ed25519`, `.rsa`).
    ///   - privatePath: Destination path for the OpenSSH private key file.
    ///   - publicPath: Optional explicit destination for the public key file.
    ///   - bits: Optional RSA modulus bit length override (ignored for non‑RSA).
    ///   - comment: Optional comment embedded in the public key line and
    ///     private key metadata.
    ///   - passphrase: Optional passphrase; when present the private key is
    ///     encrypted at rest.
    /// - Throws: Propagates any error from `SwiftKeyGen.generateKeyPair` or
    ///   file serialization / permission handling (`SSHKeyError`).
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
    
    /// Writes a key (private or public) directly to standard output in the
    /// same format used for on‑disk persistence.
    ///
    /// - Parameters:
    ///   - keyPair: Source key pair whose component will be serialized.
    ///   - type: Component to emit. Public keys receive a trailing newline for
    ///     shell friendliness.
    /// - Throws: `SSHKeyError.serializationFailed` if the key cannot be
    ///   encoded.
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
    
    /// Writes raw data directly to standard output without mutation.
    ///
    /// - Parameter data: The already‑encoded bytes to stream.
    public static func writeDataToStdout(_ data: Data) {
        FileHandle.standardOutput.write(data)
    }
    
    /// Writes a UTF‑8 string to standard output (silently ignores encoding
    /// failure, which should not occur for valid Swift `String`).
    ///
    /// - Parameter string: The textual content to emit.
    public static func writeStringToStdout(_ string: String) {
        if let data = string.data(using: .utf8) {
            FileHandle.standardOutput.write(data)
        }
    }
    
    /// Reads all available bytes from standard input until EOF.
    ///
    /// - Returns: The raw data read from stdin.
    /// - Throws: `SSHKeyError.fileOperationFailed` if no data was supplied.
    public static func readFromStdin() throws -> Data {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard !data.isEmpty else {
            throw SSHKeyError.fileOperationFailed("No data available from stdin")
        }
        return data
    }
    
    /// Reads UTF‑8 text from standard input until EOF.
    ///
    /// - Returns: A `String` decoded as UTF‑8 from stdin.
    /// - Throws: `SSHKeyError.fileOperationFailed` if the stream is empty or
    ///   contains invalid UTF‑8 sequences.
    public static func readStringFromStdin() throws -> String {
        let data = try readFromStdin()
        guard let string = String(data: data, encoding: .utf8) else {
            throw SSHKeyError.fileOperationFailed("Invalid UTF-8 data from stdin")
        }
        return string
    }
    
    /// Reads raw key data either from a file path or from standard input when
    /// the sentinel `"-"` is supplied.
    ///
    /// - Parameter path: Filesystem path to read or `"-"` to target stdin.
    /// - Returns: The loaded data bytes.
    /// - Throws: Any I/O error produced by `Data(contentsOf:)` or
    ///   `readFromStdin()`.
    public static func readKeyData(from path: String) throws -> Data {
        if path == STDIN_STDOUT_FILENAME {
            return try readFromStdin()
        } else {
            return try Data(contentsOf: URL(fileURLWithPath: path))
        }
    }
}
