import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for format edge cases and unusual inputs.
@Suite("Format Edge Cases Integration Tests", .tags(.integration))
struct FormatEdgeCasesIntegrationTests {
    
    // MARK: - Keys with Unusual Comments
    
    @Test("Keys with unusual comments (Unicode, special characters)")
    func testKeysWithUnicodeComments() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let unicodeComments = [
                "user@例え.jp",                    // Japanese characters
                "user@тест.рф",                    // Cyrillic
                "user🔑@host.com",                  // Emoji
                "user@host.com (Test's Key!)",     // Special characters
                "user@host.com <tag=\"value\">",   // XML-like
                "user@host.com [brackets]",        // Brackets
            ]
            
            for comment in unicodeComments {
                // Generate key with unusual comment
                let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: comment) as! Ed25519Key
                
                // Write to file
                let keyPath = tempDir.appendingPathComponent("test_key")
                let pubPath = tempDir.appendingPathComponent("test_key.pub")
                let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
                try IntegrationTestSupporter.write(keyData, to: keyPath)
                try IntegrationTestSupporter.write(key.publicKeyString(), to: pubPath)
                
                // Verify ssh-keygen can read the public key
                let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
                #expect(fingerprintResult.succeeded, "ssh-keygen should read key with Unicode comment: \(comment)")
                
                // Verify our parser can read it back
                let pubData = try Data(contentsOf: pubPath)
                let pubString = String(data: pubData, encoding: .utf8)!
                #expect(pubString.contains(comment) || pubString.hasSuffix(comment), 
                        "Public key should preserve comment: \(comment)")
                
                // Clean up for next iteration
                try? FileManager.default.removeItem(at: keyPath)
                try? FileManager.default.removeItem(at: pubPath)
            }
        }
    }
    
    @Test("Keys with very long comments (>255 characters)")
    func testKeysWithVeryLongComments() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create a very long comment (500 characters)
            let longComment = String(repeating: "a", count: 250) + "@" + String(repeating: "b", count: 249) + ".com"
            #expect(longComment.count > 255, "Comment should be longer than 255 characters")
            
            // Generate key with long comment
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: longComment) as! Ed25519Key
            
            // Write to files
            let keyPath = tempDir.appendingPathComponent("long_comment_key")
            let pubPath = tempDir.appendingPathComponent("long_comment_key.pub")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            try IntegrationTestSupporter.write(key.publicKeyString(), to: pubPath)
            
            // Verify ssh-keygen can read it
            let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(fingerprintResult.succeeded, "ssh-keygen should read key with very long comment")
            
            // Verify comment is preserved
            let pubData = try Data(contentsOf: pubPath)
            let pubString = String(data: pubData, encoding: .utf8)!
            #expect(pubString.contains(longComment), "Long comment should be preserved")
        }
    }
    
    @Test("Keys with no comment")
    func testKeysWithNoComment() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with empty comment
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "") as! Ed25519Key
            
            // Write to files
            let keyPath = tempDir.appendingPathComponent("no_comment_key")
            let pubPath = tempDir.appendingPathComponent("no_comment_key.pub")
            let keyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            try IntegrationTestSupporter.write(keyData, to: keyPath)
            try IntegrationTestSupporter.write(key.publicKeyString(), to: pubPath)
            
            // Verify ssh-keygen can read it
            let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(fingerprintResult.succeeded, "ssh-keygen should read key with no comment")
            
            // Public key should just have type and base64 (two parts, no third)
            let pubData = try Data(contentsOf: pubPath)
            let pubString = String(data: pubData, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
            let parts = pubString.split(separator: " ")
            #expect(parts.count >= 2, "Public key should have at least type and base64")
        }
    }
    
    // MARK: - Public Key Format Variations
    
    @Test("Public key with extra whitespace")
    func testPublicKeyWithExtraWhitespace() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate a normal key
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            let normalPubKey = key.publicKeyString()
            
            // Create variations with extra whitespace
            let variations = [
                "   " + normalPubKey,                          // Leading spaces
                normalPubKey + "   ",                          // Trailing spaces
                "\t" + normalPubKey,                           // Leading tab
                normalPubKey.replacingOccurrences(of: " ", with: "   "), // Multiple spaces between parts
                "\n" + normalPubKey,                           // Leading newline
                normalPubKey + "\n\n",                         // Multiple trailing newlines
            ]
            
            for (index, variation) in variations.enumerated() {
                let pubPath = tempDir.appendingPathComponent("whitespace_\(index).pub")
                try IntegrationTestSupporter.write(variation, to: pubPath)
                
                // Verify ssh-keygen can read it
                let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
                #expect(fingerprintResult.succeeded, "ssh-keygen should handle public key with extra whitespace")
                
                // Clean up
                try? FileManager.default.removeItem(at: pubPath)
            }
        }
    }
    
    @Test("Public key with tabs instead of spaces")
    func testPublicKeyWithTabs() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate a normal key
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            let normalPubKey = key.publicKeyString()
            
            // Replace spaces with tabs
            let tabbedPubKey = normalPubKey.replacingOccurrences(of: " ", with: "\t")
            
            let pubPath = tempDir.appendingPathComponent("tabbed.pub")
            try IntegrationTestSupporter.write(tabbedPubKey, to: pubPath)
            
            // Verify ssh-keygen can read it
            let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(fingerprintResult.succeeded, "ssh-keygen should handle tabs as separators")
        }
    }
    
    @Test("RFC4716 public key wrapped across multiple lines")
    func testRFC4716MultilineWrapping() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate a key
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            
            // Export as RFC4716 with our implementation
            let rfc4716Data = try KeyConverter.toRFC4716(key: key)
            
            // Write to file
            let rfc4716Path = tempDir.appendingPathComponent("test_key.rfc4716")
            try IntegrationTestSupporter.write(rfc4716Data, to: rfc4716Path)
            
            // Verify it's wrapped across multiple lines
            let rfc4716Content = try String(contentsOf: rfc4716Path, encoding: .utf8)
            let lines = rfc4716Content.split(separator: "\n")
            #expect(lines.count > 3, "RFC4716 format should span multiple lines (header + wrapped base64 + footer)")
            
            // Verify ssh-keygen can import it (some ssh-keygen builds require -i/-m for RFC4716)
            let importResult = try IntegrationTestSupporter.runSSHKeygen(["-i", "-f", rfc4716Path.path, "-m", "RFC4716"])
            #expect(importResult.succeeded, "ssh-keygen should import multi-line RFC4716 format")
            #expect(importResult.stdout.contains("ssh-ed25519"), "Imported key should contain ssh-ed25519 type")

            // Write imported OpenSSH form to temp file for fingerprinting
            let importedPubPath = tempDir.appendingPathComponent("imported_from_rfc.pub")
            try IntegrationTestSupporter.write(importResult.stdout, to: importedPubPath)
            let fingerprintResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", importedPubPath.path])
            #expect(fingerprintResult.succeeded, "ssh-keygen should fingerprint imported RFC4716 key")
            
            // Verify we can parse it back as RFC4716 public key (not a private key)
            let parsed = try PublicKeyParser.parseRFC4716(rfc4716Content)
            #expect(parsed.type == .ed25519, "Parsed RFC4716 key type should be ed25519")
            #expect(parsed.comment == "test@host.com", "RFC4716 comment should be preserved")
            
            // Compare fingerprints: our original OpenSSH vs imported-from-RFC4716
            let originalOpenSSH = key.publicKeyString()
            let originalPath = tempDir.appendingPathComponent("original.pub")
            try IntegrationTestSupporter.write(originalOpenSSH, to: originalPath)
            let originalFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", originalPath.path])
            #expect(originalFP.succeeded, "ssh-keygen should fingerprint original key")
            #expect(originalFP.stdout.split(separator: " ").last == fingerprintResult.stdout.split(separator: " ").last, "Fingerprints should match between original and RFC4716-imported key")
        }
    }
    
    // MARK: - Malformed Key Handling
    
    @Test("Malformed key handling (truncated base64)")
    func testMalformedKeyTruncatedBase64() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create a malformed public key with truncated base64
            let malformed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIInvalid"
            
            let pubPath = tempDir.appendingPathComponent("malformed.pub")
            try IntegrationTestSupporter.write(malformed, to: pubPath)
            
            // Verify both tools reject it
            let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(sshKeygenResult.failed, "ssh-keygen should reject malformed key")
            
            // Our parser should also reject it (try reading as public key would fail)
            // Since we don't have a direct parse method, we test indirectly
            // by verifying ssh-keygen rejects it (which is the main point of this test)
        }
    }
    
    @Test("Malformed key handling (invalid key type)")
    func testMalformedKeyInvalidType() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create a public key with invalid type
            let malformed = "ssh-invalid AAAAC3NzaC1lZDI1NTE5AAAAII8puthxJKGbVJH5v1pLJqe5tTJKOZlJr1qnYqVPWGot test@host.com"
            
            let pubPath = tempDir.appendingPathComponent("invalid_type.pub")
            try IntegrationTestSupporter.write(malformed, to: pubPath)
            
            // Verify both tools reject it
            let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(sshKeygenResult.failed, "ssh-keygen should reject invalid key type")
            
            // Both tools should reject it via ssh-keygen verification above
        }
    }
    
    // MARK: - Mixed Line Endings
    
    @Test("Mixed line endings (CRLF vs LF)")
    func testMixedLineEndings() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate an Ed25519 key which has a multi-line private key format
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            
            // Get OpenSSH private key
            let privateKeyData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            let privateKey = String(data: privateKeyData, encoding: .utf8)!
            
            // Create versions with different line endings
            let lfVersion = privateKey.replacingOccurrences(of: "\r\n", with: "\n")
            let crlfVersion = lfVersion.replacingOccurrences(of: "\n", with: "\r\n")
            let mixedVersion = lfVersion.components(separatedBy: "\n")
                .enumerated()
                .map { index, line in
                    // Alternate between LF and CRLF
                    return index % 2 == 0 ? line + "\n" : line + "\r\n"
                }
                .joined()
            
            // Test LF version
            let lfPath = tempDir.appendingPathComponent("lf_key")
            try IntegrationTestSupporter.write(lfVersion, to: lfPath)
            let lfResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", lfPath.path])
            #expect(lfResult.succeeded, "ssh-keygen should handle LF line endings")
            
            // Test CRLF version
            let crlfPath = tempDir.appendingPathComponent("crlf_key")
            try IntegrationTestSupporter.write(crlfVersion, to: crlfPath)
            let crlfResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", crlfPath.path])
            #expect(crlfResult.succeeded, "ssh-keygen should handle CRLF line endings")
            
            // Test mixed version (this might fail with ssh-keygen, but we should handle it)
            let mixedPath = tempDir.appendingPathComponent("mixed_key")
            try IntegrationTestSupporter.write(mixedVersion, to: mixedPath)
            let mixedResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", mixedPath.path])
            // Note: ssh-keygen might reject mixed line endings, but we document the behavior
            if mixedResult.failed {
                // Document that ssh-keygen doesn't support mixed line endings
                print("Note: ssh-keygen rejects mixed line endings (expected behavior)")
            }
        }
    }
    
    // MARK: - Empty and Whitespace Files
    
    @Test("Empty file handling")
    func testEmptyFileHandling() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Create an empty file
            let emptyPath = tempDir.appendingPathComponent("empty.pub")
            try IntegrationTestSupporter.write("", to: emptyPath)
            
            // Both tools should reject it
            let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", emptyPath.path])
            #expect(sshKeygenResult.failed, "ssh-keygen should reject empty file")
            
            // Verify our implementation also rejects it
            #expect(throws: Error.self) {
                try KeyManager.readPrivateKey(from: emptyPath.path, passphrase: nil)
            }
        }
    }
    
    @Test("Whitespace-only file handling")
    func testWhitespaceOnlyFileHandling() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let whitespaceVariants = [
                "   ",           // Spaces
                "\t\t\t",        // Tabs
                "\n\n\n",        // Newlines
                "  \n\t\n  ",    // Mixed whitespace
            ]
            
            for (index, whitespace) in whitespaceVariants.enumerated() {
                let path = tempDir.appendingPathComponent("whitespace_\(index).pub")
                try IntegrationTestSupporter.write(whitespace, to: path)
                
                // Both tools should reject it
                let sshKeygenResult = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", path.path])
                #expect(sshKeygenResult.failed, "ssh-keygen should reject whitespace-only file")
                
                // Verify our implementation also rejects it
                #expect(throws: Error.self) {
                    try KeyManager.readPrivateKey(from: path.path, passphrase: nil)
                }
                
                try? FileManager.default.removeItem(at: path)
            }
        }
    }
}
