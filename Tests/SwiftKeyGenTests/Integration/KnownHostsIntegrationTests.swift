import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("Known Hosts Integration Tests", .tags(.integration))
struct KnownHostsIntegrationTests {
    
    // Helper to parse ssh-keygen public key format and return (keyType, base64Data)
    private func parseSSHPublicKey(_ pubKeyLine: String) throws -> (keyType: String, base64: String) {
        let parts = pubKeyLine.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else {
            throw SSHKeyError.invalidKeyData
        }
        return (String(parts[0]), String(parts[1]))
    }
    
    // MARK: - Parse ssh-keygen known_hosts Entries
    
    @Test("Parse ssh-keygen known_hosts plain hostname entry")
    func testParseSSHKeygenPlainHostnameEntry() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Generate a key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("test_key")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Extract public key
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            
            // Create known_hosts entry with plain hostname
            let knownHostsContent = "example.com \(keyType) \(base64Data)"
            try IntegrationTestSupporter.write(knownHostsContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            #expect(entries.count == 1)
            #expect(entries[0].hostPattern == "example.com")
            #expect(entries[0].keyType == .ed25519)
        }
    }
    
    @Test("Parse ssh-keygen known_hosts with bracketed port entry")
    func testParseSSHKeygenBracketedPortEntry() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Generate a key
            let keyPath = tempDir.appendingPathComponent("test_key")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            
            // Create known_hosts entry with bracketed hostname and non-standard port
            let knownHostsContent = "[example.com]:2222 \(keyType) \(base64Data)"
            try IntegrationTestSupporter.write(knownHostsContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            #expect(entries.count == 1)
            #expect(entries[0].hostPattern == "[example.com]:2222")
            #expect(entries[0].keyType == .rsa)
        }
    }
    
    @Test("Parse ssh-keygen known_hosts with IP address")
    func testParseSSHKeygenIPAddressEntry() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Generate a key
            let keyPath = tempDir.appendingPathComponent("test_key")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
            ])
            #expect(genResult.succeeded)
            
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            
            // Create known_hosts entries with IPv4 and IPv6 addresses
            let ipv4Entry = "192.168.1.100 \(keyType) \(base64Data)"
            let ipv6Entry = "[2001:db8::1]:22 \(keyType) \(base64Data)"
            let knownHostsContent = "\(ipv4Entry)\n\(ipv6Entry)"
            try IntegrationTestSupporter.write(knownHostsContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            #expect(entries.count == 2)
            
            let patterns = Set(entries.map { $0.hostPattern })
            #expect(patterns.contains("192.168.1.100"))
            #expect(patterns.contains("[2001:db8::1]:22"))
        }
    }
    
    @Test("Parse ssh-keygen known_hosts with hostname patterns")
    func testParseSSHKeygenHostnamePatterns() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Generate a key
            let keyPath = tempDir.appendingPathComponent("test_key")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
            ])
            #expect(genResult.succeeded)
            
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            
            // Create known_hosts entries with various patterns
            let knownHostsContent = """
            *.example.com \(keyType) \(base64Data)
            server?.example.com \(keyType) \(base64Data)
            192.168.1.* \(keyType) \(base64Data)
            """
            try IntegrationTestSupporter.write(knownHostsContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            #expect(entries.count == 3)
            
            let patterns = entries.map { $0.hostPattern }
            #expect(patterns.contains("*.example.com"))
            #expect(patterns.contains("server?.example.com"))
            #expect(patterns.contains("192.168.1.*"))
        }
    }
    
    // MARK: - Hashed Hostnames Interoperability
    
    @Test("Parse ssh-keygen hashed hostname entry")
    func testParseSSHKeygenHashedHostname() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            let keyPath = tempDir.appendingPathComponent("test_key")
            
            // Generate key
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
            ])
            #expect(genResult.succeeded)
            
            // Create initial known_hosts with plain hostname
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            let initialContent = "example.com \(keyType) \(base64Data)"
            try IntegrationTestSupporter.write(initialContent, to: knownHostsPath)
            
            // Hash the known_hosts file with ssh-keygen
            let hashResult = try IntegrationTestSupporter.runSSHKeygen([
                "-H",
                "-f", knownHostsPath.path
            ])
            #expect(hashResult.succeeded, "ssh-keygen should hash known_hosts file")
            
            // Read the hashed content
            let hashedContent = try String(contentsOf: knownHostsPath, encoding: .utf8)
            
            // Verify it contains hashed format marker
            #expect(hashedContent.contains("|1|"), "Hashed entry should contain |1| marker")
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            #expect(entries.count == 1)
            #expect(entries[0].hostPattern.hasPrefix("|1|"), "Host pattern should be hashed")
            #expect(entries[0].keyType == .ed25519)
        }
    }
    
    @Test("Our hashed hostnames readable by ssh-keygen")
    func testOurHashedHostnamesReadableBySSHKeygen() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Generate key with our implementation
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com")
            
            // Add to known_hosts with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            try manager.addHost(hostname: "example.com", key: key)
            
            // Hash with our implementation
            try manager.hashHostnames()
            
            // Verify ssh-keygen can read it
            let hashedContent = try String(contentsOf: knownHostsPath, encoding: .utf8)
            #expect(hashedContent.contains("|1|"), "Should contain hashed hostname marker")
            
            // ssh-keygen should be able to find the key (even though it's hashed)
            // Note: ssh-keygen -F needs the exact hostname to match hashed entries
            let findResult = try IntegrationTestSupporter.runSSHKeygen([
                "-F", "example.com",
                "-f", knownHostsPath.path
            ])
            #expect(findResult.succeeded, "ssh-keygen should find hashed hostname")
            #expect(findResult.stdout.contains("found"), "Output should indicate match found")
        }
    }
    
    // MARK: - ssh-keygen Reads Our known_hosts Format
    
    @Test("ssh-keygen reads our known_hosts entries")
    func testSSHKeygenReadsOurKnownHostsEntries() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Create entries with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            
            let ed25519Key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519@example.com")
            let rsaKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa@example.com")
            let ecdsaKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa@example.com")
            
            try manager.addHost(hostname: "ed25519.example.com", key: ed25519Key)
            try manager.addHost(hostname: "rsa.example.com", key: rsaKey)
            try manager.addHost(hostname: "ecdsa.example.com", key: ecdsaKey)
            try manager.addHost(hostname: "ecdsa.example.com", port: 2222, key: ecdsaKey)
            
            // Verify ssh-keygen can find each host
            for hostname in ["ed25519.example.com", "rsa.example.com", "ecdsa.example.com"] {
                let findResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-F", hostname,
                    "-f", knownHostsPath.path
                ])
                #expect(findResult.succeeded, "ssh-keygen should find \(hostname)")
                #expect(findResult.stdout.contains(hostname), "Output should contain hostname")
            }
            
            // Verify ssh-keygen can find custom port entry
            let findPortResult = try IntegrationTestSupporter.runSSHKeygen([
                "-F", "[ecdsa.example.com]:2222",
                "-f", knownHostsPath.path
            ])
            #expect(findPortResult.succeeded, "ssh-keygen should find custom port entry")
        }
    }
    
    @Test("ssh-keygen -R removes our known_hosts entry")
    func testSSHKeygenRemovesOurEntry() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Create entries with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let key1 = try SwiftKeyGen.generateKey(type: .ed25519)
            let key2 = try SwiftKeyGen.generateKey(type: .ed25519)
            
            try manager.addHost(hostname: "keep.example.com", key: key1)
            try manager.addHost(hostname: "remove.example.com", key: key2)
            
            let entriesBefore = try manager.readEntries()
            #expect(entriesBefore.count == 2)
            
            // Remove one entry with ssh-keygen
            let removeResult = try IntegrationTestSupporter.runSSHKeygen([
                "-R", "remove.example.com",
                "-f", knownHostsPath.path
            ])
            #expect(removeResult.succeeded, "ssh-keygen should remove entry")
            
            // Verify with our implementation
            let entriesAfter = try manager.readEntries()
            #expect(entriesAfter.count == 1)
            #expect(entriesAfter[0].hostPattern == "keep.example.com")
        }
    }
    
    // MARK: - Round-trip Tests
    
    @Test("Round-trip: ssh-keygen → us → ssh-keygen")
    func testRoundTripSSHKeygenToUsToSSHKeygen() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            let keyPath = tempDir.appendingPathComponent("test_key")
            
            // Generate key with ssh-keygen
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "roundtrip@example.com"
            ])
            #expect(genResult.succeeded)
            
            // Create known_hosts with ssh-keygen style content (multi-host pattern)
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            let sshKeygenContent = "host1.example.com,host2.example.com \(keyType) \(base64Data)"
            try IntegrationTestSupporter.write(sshKeygenContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            #expect(entries.count == 1)
            #expect(entries[0].hostPattern == "host1.example.com,host2.example.com")
            
            // Write it back (implicitly via readEntries/writeEntries cycle)
            // This tests that we preserve the format
            let outputPath = tempDir.appendingPathComponent("known_hosts_out")
            let outManager = KnownHostsManager(filePath: outputPath.path)
            try outManager.addEntry(entries[0])
            
            // Verify ssh-keygen can still find both hosts
            for hostname in ["host1.example.com", "host2.example.com"] {
                let findResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-F", hostname,
                    "-f", outputPath.path
                ])
                #expect(findResult.succeeded, "ssh-keygen should find \(hostname) after round-trip")
            }
        }
    }
    
    // MARK: - Comments and Whitespace Handling
    
    @Test("Parse known_hosts with comments and blank lines")
    func testParseKnownHostsWithCommentsAndBlankLines() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            let keyPath = tempDir.appendingPathComponent("test_key")
            
            // Generate key
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
            ])
            #expect(genResult.succeeded)
            
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            let pubKeyLine = try String(contentsOf: pubPath, encoding: .utf8)
            let (keyType, base64Data) = try parseSSHPublicKey(pubKeyLine)
            
            // Create known_hosts with comments and blank lines
            let knownHostsContent = """
            # This is a comment
            
            example.com \(keyType) \(base64Data)
            
            # Another comment
            test.example.com \(keyType) \(base64Data)
            
            """
            try IntegrationTestSupporter.write(knownHostsContent, to: knownHostsPath)
            
            // Parse with our implementation
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            let entries = try manager.readEntries()
            
            // Should only get the actual host entries, not comments or blank lines
            #expect(entries.count == 2)
            
            let hostPatterns = Set(entries.map { $0.hostPattern })
            #expect(hostPatterns.contains("example.com"))
            #expect(hostPatterns.contains("test.example.com"))
        }
    }
    
    // MARK: - Key Verification Parity
    
    @Test("Our verification matches ssh-keygen behavior")
    func testOurVerificationMatchesSSHKeygen() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let knownHostsPath = tempDir.appendingPathComponent("known_hosts")
            
            // Create a key and add to known_hosts
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com")
            let manager = KnownHostsManager(filePath: knownHostsPath.path)
            try manager.addHost(hostname: "example.com", key: key)
            
            // Our verification should say valid
            let ourResult = try manager.verifyHost("example.com", key: key)
            #expect(ourResult == .valid, "Our implementation should verify key as valid")
            
            // ssh-keygen -F should find the host
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-F", "example.com",
                "-f", knownHostsPath.path
            ])
            #expect(sshResult.succeeded, "ssh-keygen should find the host")
            
            // Test with wrong key
            let wrongKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "wrong@example.com")
            let ourMismatch = try manager.verifyHost("example.com", key: wrongKey)
            #expect(ourMismatch == .mismatch, "Our implementation should detect mismatch")
            
            // Test with unknown host
            let ourUnknown = try manager.verifyHost("unknown.example.com", key: key)
            #expect(ourUnknown == .unknown, "Our implementation should return unknown for new host")
            
            let sshUnknown = try IntegrationTestSupporter.runSSHKeygen([
                "-F", "unknown.example.com",
                "-f", knownHostsPath.path
            ])
            #expect(sshUnknown.failed, "ssh-keygen should not find unknown host")
        }
    }
}
