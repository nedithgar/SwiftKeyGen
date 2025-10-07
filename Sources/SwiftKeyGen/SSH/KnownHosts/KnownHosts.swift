import Foundation
import Crypto
import _CryptoExtras

// MARK: - Known Hosts Models & Manager

/// Utilities for parsing, managing, and verifying entries in an OpenSSH `known_hosts` file.
///
/// This file contains:
/// - ``KnownHostsEntry``: An individual line/record from a `known_hosts` file.
/// - ``KnownHostsManager``: High–level API for reading, writing, hashing, and verifying entries.
///
/// The implementation aims for compatibility with the behavior of `ssh` and `ssh-keygen`:
/// - Lines starting with `#` or blank lines are ignored.
/// - Each non‑comment line is expected to contain at least: `hostnames keytype base64data [comment...]`.
/// - Multiple host patterns may be comma‑separated on a single line.
/// - Hashed hostnames (``KnownHostsManager.hashHostnames()`` / `ssh-keygen -H`) use the legacy
///   HMAC‑SHA1 construction for interoperability (OpenSSH format: `|1|salt|hash`).
///
/// Security Notes:
/// - The project deliberately uses `Insecure.SHA1` only in this legacy context because OpenSSH
///   still relies on this specific construction for hashed host patterns. Modern cryptographic
///   decisions elsewhere should avoid SHA‑1.
/// - A host key *mismatch* (``KnownHostsManager.VerificationResult/mismatch``) should be treated
///   as a potential MITM or unexpected key rotation event and surfaced clearly to callers.

/// A single entry in an OpenSSH `known_hosts` file.
public struct KnownHostsEntry {
    /// The raw host pattern segment as parsed from the line.
    ///
    /// Can be one of:
    /// - A plain hostname: `example.com`
    /// - A bracketed host with non‑default port: `[example.com]:2222`
    /// - A comma‑separated list of host patterns
    /// - A wildcard pattern containing `*` or `?`
    /// - A hashed host marker in the OpenSSH form: `|1|salt|hash`
    ///
    /// Multiple host patterns are **not** split here; they are preserved verbatim for round‑trip
    /// fidelity. Callers that need individual patterns should split on commas when appropriate.
    public let hostPattern: String
    /// The SSH public key algorithm (e.g. ``KeyType/sshEd25519``, ``KeyType/rsa``).
    public let keyType: KeyType
    /// The raw SSH wire‑format public key blob (decoded from the base64 column).
    ///
    /// This is the same binary payload that would appear on the wire during key exchange,
    /// beginning with the algorithm name length + bytes.
    public let publicKey: Data
    /// Optional trailing comment captured after the key data (if present).
    ///
    /// Note: The current parser does **not** capture comments yet (they are discarded), but the
    /// property exists for future enhancement and API stability.
    public let comment: String?
    
    /// Creates a new ``KnownHostsEntry``.
    ///
    /// - Parameters:
    ///   - hostPattern: The host pattern or hashed host segment.
    ///   - keyType: The SSH key algorithm.
    ///   - publicKey: The decoded SSH public key blob.
    ///   - comment: Optional trailing comment.
    public init(hostPattern: String, keyType: KeyType, publicKey: Data, comment: String? = nil) {
        self.hostPattern = hostPattern
        self.keyType = keyType
        self.publicKey = publicKey
        self.comment = comment
    }
    
    /// Parses a single `known_hosts` line into a ``KnownHostsEntry``.
    ///
    /// Behavior:
    /// - Ignores blank lines and comments (lines beginning with `#`). Returns `nil` for those.
    /// - Returns `nil` for malformed or unrecognized lines instead of throwing.
    /// - Currently discards any trailing comment portion (future enhancement may restore it).
    ///
    /// - Parameter line: The raw line text (without newline terminator).
    /// - Returns: A ``KnownHostsEntry`` if the line could be parsed; otherwise `nil`.
    /// - Throws: Reserved for future error signaling (currently does **not** throw).
    public static func parse(_ line: String) throws -> KnownHostsEntry? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Skip empty lines and comments
        if trimmed.isEmpty || trimmed.hasPrefix("#") {
            return nil
        }
        
        let components = trimmed.split(separator: " ", maxSplits: 2).map(String.init)
        guard components.count >= 3 else {
            return nil
        }
        
        let hostPattern = components[0]
        let keyTypeString = components[1]
        let keyData = components[2]
        
        guard let keyType = KeyType(rawValue: keyTypeString) else {
            return nil
        }
        
        guard let publicKey = Data(base64Encoded: keyData) else {
            return nil
        }
        
        return KnownHostsEntry(
            hostPattern: hostPattern,
            keyType: keyType,
            publicKey: publicKey,
            comment: nil
        )
    }
    
    /// Serializes the entry back into OpenSSH `known_hosts` file line form.
    ///
    /// Format: `<hostPattern> <keyType> <base64(publicKey)> [comment]`
    ///
    /// - Returns: A one‑line canonical representation suitable for direct file persistence.
    public func toLine() -> String {
        var line = "\(hostPattern) \(keyType.rawValue) \(publicKey.base64EncodedString())"
        if let comment = comment {
            line += " \(comment)"
        }
        return line
    }
}

/// Read, write, and verify entries in a `known_hosts` file.
public struct KnownHostsManager {
    private let filePath: String
    
    /// Creates a manager bound to the user’s `known_hosts` file or a custom path.
    ///
    /// - Parameter filePath: Optional override path. If `nil`, defaults to `~/.ssh/known_hosts`.
    public init(filePath: String? = nil) {
        self.filePath = filePath ?? NSString(string: "~/.ssh/known_hosts").expandingTildeInPath
    }
    
    /// Reads and parses all entries from the backing `known_hosts` file.
    ///
    /// - Returns: An array of successfully parsed entries. Malformed lines are skipped.
    /// - Throws: File I/O errors if the file exists but cannot be read.
    public func readEntries() throws -> [KnownHostsEntry] {
        guard FileManager.default.fileExists(atPath: filePath) else {
            return []
        }
        
        let content = try String(contentsOfFile: filePath, encoding: .utf8)
        var entries: [KnownHostsEntry] = []
        
        for line in content.components(separatedBy: .newlines) {
            if let entry = try KnownHostsEntry.parse(line) {
                entries.append(entry)
            }
        }
        
        return entries
    }
    
    /// Appends a new host key entry (generating an appropriate host pattern when a non‑default port is provided).
    ///
    /// Behavior:
    /// - If `port` is `nil` or `22`, the host pattern is the raw hostname.
    /// - Otherwise it is formatted as `[hostname]:port` per OpenSSH conventions.
    ///
    /// - Parameters:
    ///   - hostname: The target host name.
    ///   - port: Optional port; defaults to `nil` (treated as 22 if unspecified).
    ///   - key: The SSH key whose public component will be stored.
    /// - Throws: File I/O errors when the entry cannot be appended.
    public func addHost(hostname: String, port: Int? = nil, key: any SSHKey) throws {
        let hostPattern: String
        if let port = port, port != 22 {
            hostPattern = "[\(hostname)]:\(port)"
        } else {
            hostPattern = hostname
        }
        
        let entry = KnownHostsEntry(
            hostPattern: hostPattern,
            keyType: key.keyType,
            publicKey: key.publicKeyData()
        )
        
        try addEntry(entry)
    }
    
    /// Appends a fully formed ``KnownHostsEntry`` to the file.
    ///
    /// Ensures a trailing newline exists before writing. Creates the file if it does not exist.
    ///
    /// - Parameter entry: The entry to persist.
    /// - Throws: File I/O errors if the write fails.
    public func addEntry(_ entry: KnownHostsEntry) throws {
        var content = ""
        
        if FileManager.default.fileExists(atPath: filePath) {
            content = try String(contentsOfFile: filePath, encoding: .utf8)
            if !content.hasSuffix("\n") {
                content += "\n"
            }
        }
        
        content += entry.toLine() + "\n"
        
        try content.write(toFile: filePath, atomically: true, encoding: .utf8)
    }
    
    /// Removes all entries whose `hostPattern` contains the provided hostname substring.
    ///
    /// This is a coarse filter matching any entry whose pattern text contains `hostname`.
    /// Future enhancement may perform stricter semantic matching (wildcards / hashed resolution).
    ///
    /// - Parameter hostname: The hostname substring to remove.
    /// - Throws: File I/O errors if writing the updated file fails.
    public func removeHost(_ hostname: String) throws {
        let entries = try readEntries()
        let filtered = entries.filter { entry in
            !entry.hostPattern.contains(hostname)
        }
        
        try writeEntries(filtered)
    }
    
    /// Locates entries whose host pattern matches a given hostname.
    ///
    /// Supports:
    /// - Exact matches
    /// - Bracketed `[host]:port` forms
    /// - Shell wildcards (`*`, `?`)
    /// - Hashed host patterns (`|1|salt|hash`)
    ///
    /// - Parameter hostname: The hostname being queried (without port unless bracketed form supplied in file).
    /// - Returns: All matching entries (may be empty).
    /// - Throws: File I/O errors encountered while reading.
    public func findHost(_ hostname: String) throws -> [KnownHostsEntry] {
        let entries = try readEntries()
        return entries.filter { entry in
            matchesHostPattern(entry.hostPattern, hostname: hostname)
        }
    }
    
    /// Verifies a host’s presented key against stored entries.
    ///
    /// Flow:
    /// 1. Resolves matching entries for `hostname`.
    /// 2. If none found -> ``VerificationResult/unknown``.
    /// 3. If at least one entry matches algorithm + public key bytes -> ``VerificationResult/valid``.
    /// 4. Otherwise -> ``VerificationResult/mismatch``.
    ///
    /// - Parameters:
    ///   - hostname: The remote host name (without port; matching logic accounts for patterns).
    ///   - key: The SSH key presented by the remote host.
    /// - Returns: A verification result classifying trust status.
    /// - Throws: File I/O errors while reading known hosts.
    public func verifyHost(_ hostname: String, key: any SSHKey) throws -> VerificationResult {
        let entries = try findHost(hostname)
        
        if entries.isEmpty {
            return .unknown
        }
        
        let keyData = key.publicKeyData()
        
        for entry in entries {
            if entry.keyType == key.keyType && entry.publicKey == keyData {
                return .valid
            }
        }
        
        // Host is known but key doesn't match
        return .mismatch
    }
    
    /// Rewrites the file replacing plain host patterns with OpenSSH‑style hashed hostnames.
    ///
    /// Behavior mirrors `ssh-keygen -H`:
    /// - Already hashed patterns are left untouched.
    /// - Comma‑separated host lists are hashed element‑wise and rejoined.
    /// - Uses HMAC‑SHA1 with a random 20‑byte salt (legacy OpenSSH format for interoperability).
    ///
    /// - Throws: File I/O errors if reading or writing fails.
    public func hashHostnames() throws {
        let entries = try readEntries()
        var hashedEntries: [KnownHostsEntry] = []
        
        for entry in entries {
            // Skip already hashed entries
            if entry.hostPattern.hasPrefix("|") {
                hashedEntries.append(entry)
                continue
            }
            
            // Handle comma-separated host patterns
            let hostPatterns = entry.hostPattern.split(separator: ",").map(String.init)
            var hashedPatterns: [String] = []
            
            for pattern in hostPatterns {
                hashedPatterns.append(hashHostname(pattern))
            }
            
            let hashedPattern = hashedPatterns.joined(separator: ",")
            let hashedEntry = KnownHostsEntry(
                hostPattern: hashedPattern,
                keyType: entry.keyType,
                publicKey: entry.publicKey,
                comment: entry.comment
            )
            hashedEntries.append(hashedEntry)
        }
        
        try writeEntries(hashedEntries)
    }
    
    private func writeEntries(_ entries: [KnownHostsEntry]) throws {
        let content = entries.map { $0.toLine() }.joined(separator: "\n") + "\n"
        try content.write(toFile: filePath, atomically: true, encoding: .utf8)
    }
    
    private func hashHostname(_ hostname: String) -> String {
        // Generate random salt
        let salt = Data((0..<20).map { _ in UInt8.random(in: 0...255) })
        
        // Hash hostname with salt using HMAC-SHA1
        let key = salt
        let hostData = Data(hostname.utf8)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: hostData, using: SymmetricKey(data: key))
        
        // Format: |1|base64(salt)|base64(hash)
        return "|1|\(salt.base64EncodedString())|\(Data(hmac).base64EncodedString())"
    }
    
    private func matchesHostPattern(_ pattern: String, hostname: String) -> Bool {
        // Handle hashed entries
        if pattern.hasPrefix("|") {
            return verifyHashedHost(pattern, hostname: hostname)
        }
        
        // Handle wildcards and pattern matching
        if pattern.contains("*") || pattern.contains("?") {
            return matchesWildcardPattern(pattern, hostname: hostname)
        }
        
        // Simple exact matching for unhashed entries
        return pattern == hostname || pattern == "[\(hostname)]" || pattern.hasPrefix("[\(hostname)]:")
    }
    
    private func matchesWildcardPattern(_ pattern: String, hostname: String) -> Bool {
        // Convert shell-style wildcards to regex
        var regexPattern = pattern
            .replacingOccurrences(of: ".", with: "\\.")
            .replacingOccurrences(of: "*", with: ".*")
            .replacingOccurrences(of: "?", with: ".")
        
        // Handle bracketed format [hostname]:port
        if pattern.hasPrefix("[") && pattern.contains("]:") {
            regexPattern = regexPattern
                .replacingOccurrences(of: "[", with: "\\[")
                .replacingOccurrences(of: "]", with: "\\]")
        }
        
        regexPattern = "^" + regexPattern + "$"
        
        guard let regex = try? NSRegularExpression(pattern: regexPattern, options: []) else {
            return false
        }
        
        let range = NSRange(location: 0, length: hostname.utf16.count)
        return regex.firstMatch(in: hostname, options: [], range: range) != nil
    }
    
    private func verifyHashedHost(_ hashedPattern: String, hostname: String) -> Bool {
        // Parse |1|salt|hash format
        let components = hashedPattern.split(separator: "|").map(String.init)
        guard components.count >= 3 else {
            return false
        }
        
        // Components will be ["1", "salt", "hash"] - split removes empty elements
        guard components[0] == "1",
              let salt = Data(base64Encoded: components[1]),
              let expectedHash = Data(base64Encoded: components[2]) else {
            return false
        }
        
        // Compute HMAC for hostname with given salt
        let hostData = Data(hostname.utf8)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: hostData, using: SymmetricKey(data: salt))
        
        return Data(hmac) == expectedHash
    }
    
    /// Classification of a host key verification attempt against stored `known_hosts` entries.
    public enum VerificationResult {
        /// At least one entry matched the hostname and the key’s algorithm and bytes.
        case valid
        /// Entries exist for the hostname but none matched the provided key blob.
        ///
        /// Treat as high‑risk: could indicate a MITM attempt or unexpected legitimate key rotation.
        case mismatch
        /// No entries were found for the host. Typically indicates a first‑time connection.
        case unknown
    }
}
