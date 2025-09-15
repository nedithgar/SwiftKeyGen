import Foundation
import Crypto
import _CryptoExtras

/// A single entry in an OpenSSH `known_hosts` file.
public struct KnownHostsEntry {
    /// Host pattern (hostname, `[host]:port`, wildcard, or hashed form).
    public let hostPattern: String
    /// Key algorithm for the entry.
    public let keyType: KeyType
    /// SSH wire‑format public key data.
    public let publicKey: Data
    /// Optional comment if present on the line.
    public let comment: String?
    
    public init(hostPattern: String, keyType: KeyType, publicKey: Data, comment: String? = nil) {
        self.hostPattern = hostPattern
        self.keyType = keyType
        self.publicKey = publicKey
        self.comment = comment
    }
    
    /// Parse a known_hosts line
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
    
    /// Convert to a `known_hosts` line format.
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
    
    public init(filePath: String? = nil) {
        self.filePath = filePath ?? NSString(string: "~/.ssh/known_hosts").expandingTildeInPath
    }
    
    /// Read all entries from the `known_hosts` file.
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
    
    /// Add a new host key.
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
    
    /// Add an entry to the file.
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
    
    /// Remove entries for a hostname.
    public func removeHost(_ hostname: String) throws {
        let entries = try readEntries()
        let filtered = entries.filter { entry in
            !entry.hostPattern.contains(hostname)
        }
        
        try writeEntries(filtered)
    }
    
    /// Find entries for a hostname.
    public func findHost(_ hostname: String) throws -> [KnownHostsEntry] {
        let entries = try readEntries()
        return entries.filter { entry in
            matchesHostPattern(entry.hostPattern, hostname: hostname)
        }
    }
    
    /// Check if a key matches any known host.
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
    
    /// Hash all hostnames (like `ssh-keygen -H`).
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
    
    /// Result of verifying a host’s public key against `known_hosts`.
    public enum VerificationResult {
        /// A matching entry exists for the host and key.
        case valid
        /// The host exists but the key does not match (possible MITM or rotation).
        case mismatch
        /// No entry exists for the host.
        case unknown
    }
}
