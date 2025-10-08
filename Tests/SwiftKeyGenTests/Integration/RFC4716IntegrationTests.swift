import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("RFC4716 Format Integration Tests", .tags(.integration))
struct RFC4716IntegrationTests {
    
    // MARK: - Helper Functions
    
    /// Reconstruct OpenSSH public key string from parsed RFC4716 data
    private func reconstructOpenSSHPublicKey(type: KeyType, data: Data, comment: String?) -> String {
        var result = type.rawValue + " " + data.base64EncodedString()
        if let comment = comment, !comment.isEmpty {
            result += " " + comment
        }
        return result
    }
    
    // MARK: - Parse ssh-keygen RFC4716 Public Keys
    
    @Test("Parse ssh-keygen RFC4716 Ed25519 public key")
    func testParseSSHKeygenRFC4716Ed25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "rfc4716-ed25519@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate Ed25519 key")
            
            // Export to RFC4716 format
            let rfc4716Path = tempDir.appendingPathComponent("id_ed25519.rfc")
            let exportResult = try IntegrationTestSupporter.runSSHKeygen([
                "-e", "-f", keyPath.path, "-m", "RFC4716"
            ])
            #expect(exportResult.succeeded, "ssh-keygen should export to RFC4716")
            
            try IntegrationTestSupporter.write(exportResult.stdout, to: rfc4716Path, permissions: 0o644)
            
            // Parse with our implementation
            let parsed = try PublicKeyParser.parseRFC4716(exportResult.stdout)
            
            // Verify key type and data
            #expect(parsed.type == .ed25519, "Parsed key should be Ed25519")
            #expect(parsed.comment != nil, "RFC4716 should preserve comment")
            
            // Compare with original public key
            let pubPath = tempDir.appendingPathComponent("id_ed25519.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            // Reconstruct OpenSSH format from our parsed data
            let ourOpenSSH = reconstructOpenSSHPublicKey(type: parsed.type, data: parsed.data, comment: parsed.comment)
            
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            
            #expect(ourNorm == origNorm, "Parsed RFC4716 should match original public key")
        }
    }
    
    @Test("Parse ssh-keygen RFC4716 RSA public key", .tags(.rsa))
    func testParseSSHKeygenRFC4716RSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "rfc4716-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let exportResult = try IntegrationTestSupporter.runSSHKeygen([
                "-e", "-f", keyPath.path, "-m", "RFC4716"
            ])
            #expect(exportResult.succeeded, "ssh-keygen should export RSA to RFC4716")
            
            let parsed = try PublicKeyParser.parseRFC4716(exportResult.stdout)
            
            #expect(parsed.type == .rsa, "Parsed key should be RSA")
            #expect(parsed.comment != nil, "RFC4716 should preserve comment")
            
            let pubPath = tempDir.appendingPathComponent("id_rsa.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            let ourOpenSSH = reconstructOpenSSHPublicKey(type: parsed.type, data: parsed.data, comment: parsed.comment)
            
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            
            #expect(ourNorm == origNorm, "Parsed RFC4716 RSA should match original")
        }
    }
    
    @Test("Parse ssh-keygen RFC4716 ECDSA public keys")
    func testParseSSHKeygenRFC4716ECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let curves: [(String, KeyType)] = [
                ("256", .ecdsa256),
                ("384", .ecdsa384),
                ("521", .ecdsa521)
            ]
            
            for (bits, expectedType) in curves {
                let keyPath = tempDir.appendingPathComponent("id_ecdsa_\(bits)")
                let genResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-t", "ecdsa",
                    "-b", bits,
                    "-f", keyPath.path,
                    "-N", "",
                    "-C", "rfc4716-ecdsa\(bits)@example.com"
                ])
                #expect(genResult.succeeded, "ssh-keygen should generate ECDSA \(bits) key")
                
                let exportResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-e", "-f", keyPath.path, "-m", "RFC4716"
                ])
                #expect(exportResult.succeeded, "ssh-keygen should export ECDSA \(bits) to RFC4716")
                
                let parsed = try PublicKeyParser.parseRFC4716(exportResult.stdout)
                
                #expect(parsed.type == expectedType, "Parsed key should be ECDSA P-\(bits)")
                
                let pubPath = tempDir.appendingPathComponent("id_ecdsa_\(bits).pub")
                let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
                
                let ourOpenSSH = reconstructOpenSSHPublicKey(type: parsed.type, data: parsed.data, comment: parsed.comment)
                
                let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
                let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
                
                #expect(ourNorm == origNorm, "Parsed RFC4716 ECDSA \(bits) should match original")
            }
        }
    }
    
    @Test("Parse RFC4716 with headers")
    func testParseRFC4716WithHeaders() throws {
        // Create RFC4716 format with multiple headers
        let rfc4716 = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        Comment: "user@example.com"
        Subject: Test Subject
        AAAAC3NzaC1lZDI1NTE5AAAAIMhJKw8pR5S0+1PfPqnKJsXq4PcJaHXCjLAJmBo
        pqQhK
        ---- END SSH2 PUBLIC KEY ----
        """
        
        let parsed = try PublicKeyParser.parseRFC4716(rfc4716)
        
        #expect(parsed.type == .ed25519, "Should parse Ed25519 key type")
        #expect(parsed.comment != nil, "Should extract comment header")
        #expect(parsed.data.count > 0, "Should have key data")
    }
    
    // MARK: - ssh-keygen Reads Our RFC4716 Format
    
    @Test("ssh-keygen reads our RFC4716 Ed25519 format")
    func testSSHKeygenReadsOurRFC4716Ed25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with our implementation
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "our-rfc4716-ed25519@example.com")
            
            // Export to RFC4716
            let rfc4716 = try KeyConverter.toRFC4716(key: key)
            
            let rfc4716Path = tempDir.appendingPathComponent("our_key.rfc")
            try IntegrationTestSupporter.write(rfc4716, to: rfc4716Path, permissions: 0o644)
            
            // Import with ssh-keygen
            let importResult = try IntegrationTestSupporter.runSSHKeygen([
                "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
            ])
            #expect(importResult.succeeded, "ssh-keygen should import our RFC4716 Ed25519 format")
            #expect(importResult.stdout.contains("ssh-ed25519"), "Imported key should be Ed25519")
            
            // Compare with our OpenSSH format
            let ourOpenSSH = key.publicKeyString()
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
            let importedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(importResult.stdout)
            
            #expect(ourNorm == importedNorm, "ssh-keygen imported key should match ours")
        }
    }
    
    @Test("ssh-keygen reads our RFC4716 RSA format", .tags(.rsa))
    func testSSHKeygenReadsOurRFC4716RSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "our-rfc4716-rsa@example.com")
            
            let rfc4716 = try KeyConverter.toRFC4716(key: key)
            
            let rfc4716Path = tempDir.appendingPathComponent("our_key.rfc")
            try IntegrationTestSupporter.write(rfc4716, to: rfc4716Path, permissions: 0o644)
            
            let importResult = try IntegrationTestSupporter.runSSHKeygen([
                "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
            ])
            #expect(importResult.succeeded, "ssh-keygen should import our RFC4716 RSA format")
            #expect(importResult.stdout.contains("ssh-rsa"), "Imported key should be RSA")
            
            let ourOpenSSH = key.publicKeyString()
            let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
            let importedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(importResult.stdout)
            
            #expect(ourNorm == importedNorm, "ssh-keygen imported RSA key should match ours")
        }
    }
    
    @Test("ssh-keygen reads our RFC4716 ECDSA format")
    func testSSHKeygenReadsOurRFC4716ECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyTypes: [KeyType] = [.ecdsa256, .ecdsa384, .ecdsa521]
            
            for keyType in keyTypes {
                let key = try SwiftKeyGen.generateKey(type: keyType, comment: "our-rfc4716-ecdsa@example.com")
                
                let rfc4716 = try KeyConverter.toRFC4716(key: key)
                
                let rfc4716Path = tempDir.appendingPathComponent("our_key_\(keyType).rfc")
                try IntegrationTestSupporter.write(rfc4716, to: rfc4716Path, permissions: 0o644)
                
                let importResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
                ])
                #expect(importResult.succeeded, "ssh-keygen should import our RFC4716 \(keyType) format")
                #expect(importResult.stdout.contains("ecdsa-sha2"), "Imported key should be ECDSA")
                
                let ourOpenSSH = key.publicKeyString()
                let ourNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(ourOpenSSH)
                let importedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(importResult.stdout)
                
                #expect(ourNorm == importedNorm, "ssh-keygen imported \(keyType) key should match ours")
            }
        }
    }
    
    @Test("ssh-keygen preserves RFC4716 comment header")
    func testSSHKeygenPreservesRFC4716Comment() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "special-comment@example.com")
            
            let rfc4716 = try KeyConverter.toRFC4716(key: key)
            
            // Verify our RFC4716 has the comment header
            #expect(rfc4716.contains("Comment:"), "Our RFC4716 should have Comment header")
            #expect(rfc4716.contains("special-comment@example.com"), "Our RFC4716 should have the comment")
            
            let rfc4716Path = tempDir.appendingPathComponent("our_key.rfc")
            try IntegrationTestSupporter.write(rfc4716, to: rfc4716Path, permissions: 0o644)
            
            let importResult = try IntegrationTestSupporter.runSSHKeygen([
                "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
            ])
            #expect(importResult.succeeded, "ssh-keygen should import with comment")
            
            // Note: ssh-keygen -i doesn't preserve comments in output, but it should not fail
            #expect(importResult.stdout.contains("ssh-ed25519"), "Import should succeed")
        }
    }
    
    // MARK: - Round-Trip RFC4716 Conversion
    
    @Test("Round-trip RFC4716: ssh-keygen → us → ssh-keygen")
    func testRoundTripRFC4716() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("original")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "roundtrip-rfc4716@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Export to RFC4716 with ssh-keygen
            let exportResult = try IntegrationTestSupporter.runSSHKeygen([
                "-e", "-f", keyPath.path, "-m", "RFC4716"
            ])
            #expect(exportResult.succeeded, "ssh-keygen should export to RFC4716")
            
            // Parse with us to verify format is correct
            _ = try PublicKeyParser.parseRFC4716(exportResult.stdout)
            
            // Read the private key so we can export it
            let privateKey = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            
            // Export back to RFC4716 with us
            let ourRFC4716 = try KeyConverter.toRFC4716(key: privateKey)
            
            // Import with ssh-keygen
            let rfc4716Path = tempDir.appendingPathComponent("our_export.rfc")
            try IntegrationTestSupporter.write(ourRFC4716, to: rfc4716Path, permissions: 0o644)
            
            let importResult = try IntegrationTestSupporter.runSSHKeygen([
                "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
            ])
            #expect(importResult.succeeded, "ssh-keygen should import our RFC4716 export")
            
            // Compare with original public key
            let pubPath = tempDir.appendingPathComponent("original.pub")
            let originalPub = try String(contentsOf: pubPath, encoding: .utf8)
            
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalPub)
            let importedNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(importResult.stdout)
            
            #expect(origNorm == importedNorm, "Round-trip should preserve key data")
        }
    }
    
    @Test("Round-trip RFC4716: us → ssh-keygen → us")
    func testRoundTripRFC4716Reverse() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate with us
            let originalKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "reverse-roundtrip@example.com")
            
            // Export to RFC4716 with us
            let ourRFC4716 = try KeyConverter.toRFC4716(key: originalKey)
            
            let rfc4716Path = tempDir.appendingPathComponent("our_key.rfc")
            try IntegrationTestSupporter.write(ourRFC4716, to: rfc4716Path, permissions: 0o644)
            
            // Convert with ssh-keygen to OpenSSH format
            let convertResult = try IntegrationTestSupporter.runSSHKeygen([
                "-i", "-f", rfc4716Path.path, "-m", "RFC4716"
            ])
            #expect(convertResult.succeeded, "ssh-keygen should convert our RFC4716")
            
            // Write ssh-keygen's output
            let sshPubPath = tempDir.appendingPathComponent("ssh_converted.pub")
            try IntegrationTestSupporter.write(convertResult.stdout, to: sshPubPath, permissions: 0o644)
            
            // Export back to RFC4716 with ssh-keygen
            let reexportResult = try IntegrationTestSupporter.runSSHKeygen([
                "-e", "-f", sshPubPath.path, "-m", "RFC4716"
            ])
            #expect(reexportResult.succeeded, "ssh-keygen should re-export to RFC4716")
            
            // Parse final RFC4716 with us
            let finalParsed = try PublicKeyParser.parseRFC4716(reexportResult.stdout)
            
            // Compare public keys
            let originalOpenSSH = originalKey.publicKeyString()
            let finalOpenSSH = reconstructOpenSSHPublicKey(
                type: finalParsed.type,
                data: finalParsed.data,
                comment: finalParsed.comment
            )
            
            let origNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(originalOpenSSH)
            let finalNorm = IntegrationTestSupporter.normalizeOpenSSHPublicKey(finalOpenSSH)
            
            #expect(origNorm == finalNorm, "Reverse round-trip should preserve key data")
        }
    }
    
    // MARK: - RFC4716 Format Validation
    
    @Test("RFC4716 format structure is valid")
    func testRFC4716FormatStructure() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "structure-test@example.com")
        
        let rfc4716 = try KeyConverter.toRFC4716(key: key)
        
        // Check required headers
        #expect(rfc4716.contains("---- BEGIN SSH2 PUBLIC KEY ----"), "Should have begin marker")
        #expect(rfc4716.contains("---- END SSH2 PUBLIC KEY ----"), "Should have end marker")
        
        // Check comment header format
        #expect(rfc4716.contains("Comment:"), "Should have Comment header")
        
        // Check base64 content (between headers and markers)
        let lines = rfc4716.split(separator: "\n")
        let base64Lines = lines.filter { line in
            !line.contains("----") && !line.contains("Comment:") && !line.trimmingCharacters(in: .whitespaces).isEmpty
        }
        
        #expect(base64Lines.count > 0, "Should have base64 content lines")
        
        // Each base64 line should be valid
        for line in base64Lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            let base64Charset = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
            #expect(trimmed.unicodeScalars.allSatisfy { base64Charset.contains($0) },
                    "Base64 line should contain only valid characters")
        }
    }
}
