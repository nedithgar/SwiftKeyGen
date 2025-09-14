import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("KnownHosts Unit Tests", .tags(.unit))
struct KnownHostsUnitTests {

    // Helper to create a unique temp file path for known_hosts
    private func makeTempKnownHostsPath() -> String {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("known_hosts_\(UUID().uuidString)")
        return url.path
    }

    @Test("Parse valid line without comment")
    func testParseValidLineNoComment() throws {
        // Generate a minimal Ed25519 key and build a known_hosts line
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let pubB64 = key.publicKeyData().base64EncodedString()
        let line = "example.com \(KeyType.ed25519.rawValue) \(pubB64)"

        let entry = try KnownHostsEntry.parse(line)
        #expect(entry != nil)
        #expect(entry?.hostPattern == "example.com")
        #expect(entry?.keyType == .ed25519)
        #expect(entry?.publicKey == key.publicKeyData())
        #expect(entry?.comment == nil)
    }

    @Test("Parse line with trailing comment is ignored (current behavior)")
    func testParseLineWithCommentIgnored() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let pubB64 = key.publicKeyData().base64EncodedString()
        let lineWithComment = "example.com \(KeyType.ed25519.rawValue) \(pubB64) my-comment"

        // Current parser treats the third field as base64 only; with a comment it fails to decode and returns nil
        let entry = try KnownHostsEntry.parse(lineWithComment)
        #expect(entry == nil)
    }

    @Test("Parse invalid key type returns nil")
    func testParseInvalidKeyType() throws {
        let line = "example.com ssh-invalid AAAAB3NzaC1lZDI1NTE5AAAA"
        let entry = try KnownHostsEntry.parse(line)
        #expect(entry == nil)
    }

    @Test("toLine round-trips without comment")
    func testToLineRoundTripNoComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let entry = KnownHostsEntry(hostPattern: "example.com", keyType: .ed25519, publicKey: key.publicKeyData())
        let line = entry.toLine()

        let parsed = try KnownHostsEntry.parse(line)
        #expect(parsed != nil)
        #expect(parsed?.hostPattern == entry.hostPattern)
        #expect(parsed?.keyType == entry.keyType)
        #expect(parsed?.publicKey == entry.publicKey)
        #expect(parsed?.comment == nil)
    }

    @Test("Manager addHost writes default and custom port patterns")
    func testAddHostWritesPatterns() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let mgr = KnownHostsManager(filePath: path)
        let key = try SwiftKeyGen.generateKey(type: .ed25519)

        try mgr.addHost(hostname: "example.com", key: key) // default port 22 -> plain hostname
        try mgr.addHost(hostname: "example.com", port: 2222, key: key) // custom port -> bracketed

        let entries = try mgr.readEntries()
        #expect(entries.count == 2)

        // Expect both the plain and bracketed patterns to be present
        let patterns = Set(entries.map { $0.hostPattern })
        #expect(patterns.contains("example.com"))
        #expect(patterns.contains("[example.com]:2222"))

        // findHost should return both for hostname-only lookup
        let found = try mgr.findHost("example.com")
        #expect(found.count == 2)
    }

    @Test("removeHost filters all entries containing hostname substring")
    func testRemoveHost() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let mgr = KnownHostsManager(filePath: path)
        let key = try SwiftKeyGen.generateKey(type: .ed25519)

        // Add plain, bracketed (custom port), and another host
        try mgr.addHost(hostname: "example.com", key: key)
        try mgr.addHost(hostname: "example.com", port: 2200, key: key)
        try mgr.addHost(hostname: "other.net", key: key)

        // Remove by hostname; current implementation uses substring contains()
        try mgr.removeHost("example.com")
        let remaining = try mgr.readEntries()
        #expect(remaining.count == 1)
        #expect(remaining[0].hostPattern == "other.net")
    }

    @Test("Wildcard patterns: *.example.com matches subdomains, not apex")
    func testWildcardMatching() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let mgr = KnownHostsManager(filePath: path)
        let key = try SwiftKeyGen.generateKey(type: .ed25519)

        // Add a wildcard entry directly
        let entry = KnownHostsEntry(hostPattern: "*.example.com", keyType: .ed25519, publicKey: key.publicKeyData())
        try mgr.addEntry(entry)

        // Subdomain should match
        let match = try mgr.findHost("api.example.com")
        #expect(match.count == 1)
        #expect(match[0].hostPattern == "*.example.com")

        // Apex should not match this specific pattern
        let noMatch = try mgr.findHost("example.com")
        #expect(noMatch.isEmpty)
    }

    @Test("verifyHost returns unknown, mismatch, or valid appropriately")
    func testVerifyHostOutcomes() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let mgr = KnownHostsManager(filePath: path)
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519)
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519)

        // No entries yet
        #expect(try mgr.verifyHost("example.com", key: key1) == .unknown)

        // Add entry for key1
        try mgr.addHost(hostname: "example.com", key: key1)

        // Wrong key -> mismatch
        #expect(try mgr.verifyHost("example.com", key: key2) == .mismatch)

        // Correct key -> valid
        #expect(try mgr.verifyHost("example.com", key: key1) == .valid)
    }

    @Test("hashHostnames converts to |1|salt|hash and still matches hostname")
    func testHashHostnamesAndMatching() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let mgr = KnownHostsManager(filePath: path)
        let key = try SwiftKeyGen.generateKey(type: .ed25519)

        // Add a single-host entry, then hash
        try mgr.addHost(hostname: "example.com", key: key)
        try mgr.hashHostnames()

        // After hashing, the entry's hostPattern should start with |1|
        let entries = try mgr.readEntries()
        #expect(entries.count == 1)
        #expect(entries[0].hostPattern.hasPrefix("|1|"))

        // findHost and verifyHost should still work for the same hostname
        let found = try mgr.findHost("example.com")
        #expect(found.count == 1)
        #expect(found[0].keyType == .ed25519)

        #expect(try mgr.verifyHost("example.com", key: key) == .valid)
    }

    @Test("readEntries skips comments and blank lines")
    func testReadSkipsCommentsAndBlanks() throws {
        let path = makeTempKnownHostsPath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        // Prepare a file with comments and blank lines
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let pubB64 = key.publicKeyData().base64EncodedString()
        let content = [
            "# This is a comment",
            "",
            "example.com \(KeyType.ed25519.rawValue) \(pubB64)",
            "   ",
            "# Another comment"
        ].joined(separator: "\n") + "\n"

        try content.write(toFile: path, atomically: true, encoding: .utf8)

        let mgr = KnownHostsManager(filePath: path)
        let entries = try mgr.readEntries()
        #expect(entries.count == 1)
        #expect(entries[0].hostPattern == "example.com")
    }
}

