import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("Randomart Integration Tests", .tags(.integration))
struct RandomartIntegrationTests {
    
    // MARK: - Randomart Matching
    
    @Test("Randomart matches ssh-keygen (Ed25519)")
    func testRandomartMatchesEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "randomart@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Get randomart from ssh-keygen
            let sshArtResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-v", "-f", keyPath.path
            ])
            #expect(sshArtResult.succeeded, "ssh-keygen should generate randomart")
            
            let sshRandomart = extractRandomart(from: sshArtResult.stdout)
            #expect(sshRandomart != nil, "Should extract ssh-keygen randomart")
            
            // Parse key with our implementation
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourRandomart = RandomArt.generate(for: key)
            
            // Compare randomart (should match exactly)
            #expect(ourRandomart == sshRandomart, "Randomart should match ssh-keygen's for Ed25519")
        }
    }
    
    @Test("Randomart matches ssh-keygen (RSA)", .tags(.rsa))
    func testRandomartMatchesRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "randomart-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let sshArtResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-v", "-f", keyPath.path
            ])
            #expect(sshArtResult.succeeded, "ssh-keygen should generate randomart")
            
            let sshRandomart = extractRandomart(from: sshArtResult.stdout)
            #expect(sshRandomart != nil, "Should extract ssh-keygen randomart")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourRandomart = RandomArt.generate(for: key)
            
            #expect(ourRandomart == sshRandomart, "Randomart should match ssh-keygen's for RSA")
        }
    }
    
    @Test("Randomart matches ssh-keygen (ECDSA P-256)")
    func testRandomartMatchesECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", keyPath.path,
                "-N", "",
                "-C", "randomart-ecdsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA key")
            
            let sshArtResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-v", "-f", keyPath.path
            ])
            #expect(sshArtResult.succeeded, "ssh-keygen should generate randomart")
            
            let sshRandomart = extractRandomart(from: sshArtResult.stdout)
            #expect(sshRandomart != nil, "Should extract ssh-keygen randomart")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourRandomart = RandomArt.generate(for: key)
            
            #expect(ourRandomart == sshRandomart, "Randomart should match ssh-keygen's for ECDSA")
        }
    }
    
    // MARK: - Randomart Structure Validation
    
    @Test("Randomart structure matches ssh-keygen format")
    func testRandomartStructure() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "structure@example.com")
        let randomart = RandomArt.generate(for: key)
        
        let lines = randomart.split(separator: "\n")
        
        // Should have header, 9 art lines, and footer (11 lines total)
        #expect(lines.count == 11, "Randomart should have 11 lines (header + 9 art + footer)")
        
        // Check header format: "+---[ED25519 256]---+"
        let header = String(lines[0])
        #expect(header.hasPrefix("+"), "Header should start with +")
        #expect(header.hasSuffix("+"), "Header should end with +")
        #expect(header.contains("ED25519"), "Header should contain key type")
        #expect(header.contains("256"), "Header should contain key size")
        
        // Check footer format: "+-------------------+"
        let footer = String(lines[10])
        #expect(footer.hasPrefix("+"), "Footer should start with +")
        #expect(footer.hasSuffix("+"), "Footer should end with +")
        #expect(footer.contains("---"), "Footer should contain dashes")
        
        // Check art lines (should be bordered with |)
        for i in 1..<10 {
            let line = String(lines[i])
            #expect(line.hasPrefix("|"), "Art line \(i) should start with |")
            #expect(line.hasSuffix("|"), "Art line \(i) should end with |")
            #expect(line.count == 19, "Art line should be 19 characters (| + 17 chars + |)")
        }
    }
    
    @Test("Randomart uses correct character set")
    func testRandomartCharacterSet() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "charset@example.com")
        let randomart = RandomArt.generate(for: key)
        
        // Valid characters in randomart (from OpenSSH augmentation_string)
        let validChars = " .o+=*BOX@%&#/^SE"
        let validSet = CharacterSet(charactersIn: validChars + "|\n+-[]0123456789EDCRSAP")
        
        for char in randomart.unicodeScalars {
            #expect(validSet.contains(char), "Randomart should only contain valid characters")
        }
    }
    
    @Test("Randomart is deterministic for same key")
    func testRandomartDeterministic() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "deterministic@example.com")
        
        // Generate randomart multiple times
        let art1 = RandomArt.generate(for: key)
        let art2 = RandomArt.generate(for: key)
        let art3 = RandomArt.generate(for: key)
        
        #expect(art1 == art2, "Randomart should be identical for same key (1 vs 2)")
        #expect(art2 == art3, "Randomart should be identical for same key (2 vs 3)")
    }
    
    @Test("Randomart differs for different keys")
    func testRandomartDiffersForDifferentKeys() throws {
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519, comment: "key1@example.com")
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519, comment: "key2@example.com")
        
        let art1 = RandomArt.generate(for: key1)
        let art2 = RandomArt.generate(for: key2)
        
        #expect(art1 != art2, "Randomart should differ for different keys")
    }
    
    // MARK: - Bubble Babble Matching
    
    @Test("Bubble babble matches ssh-keygen (Ed25519)")
    func testBubbleBabbleMatchesEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "bubblebabble@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Get bubble babble from ssh-keygen
            let sshBubbleResult = try IntegrationTestSupporter.runSSHKeygen([
                "-B", "-f", keyPath.path
            ])
            #expect(sshBubbleResult.succeeded, "ssh-keygen should generate bubble babble")
            
            let sshBubble = extractBubbleBabble(from: sshBubbleResult.stdout)
            #expect(sshBubble != nil, "Should extract ssh-keygen bubble babble")
            
            // Get our bubble babble
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourBubble = key.fingerprint(hash: .sha256, format: .bubbleBabble)
            
            // Normalize by removing any prefix
            let sshBubbleClean = sshBubble?.replacingOccurrences(of: "xubem-", with: "")
            let ourBubbleClean = ourBubble.replacingOccurrences(of: "xubem-", with: "")
            
            #expect(sshBubbleClean == ourBubbleClean, "Bubble babble should match ssh-keygen's for Ed25519")
        }
    }
    
    @Test("Bubble babble matches ssh-keygen (RSA)", .tags(.rsa))
    func testBubbleBabbleMatchesRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "bubblebabble-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let sshBubbleResult = try IntegrationTestSupporter.runSSHKeygen([
                "-B", "-f", keyPath.path
            ])
            #expect(sshBubbleResult.succeeded, "ssh-keygen should generate bubble babble")
            
            let sshBubble = extractBubbleBabble(from: sshBubbleResult.stdout)
            #expect(sshBubble != nil, "Should extract ssh-keygen bubble babble")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourBubble = key.fingerprint(hash: .sha256, format: .bubbleBabble)
            
            let sshBubbleClean = sshBubble?.replacingOccurrences(of: "xubem-", with: "")
            let ourBubbleClean = ourBubble.replacingOccurrences(of: "xubem-", with: "")
            
            #expect(sshBubbleClean == ourBubbleClean, "Bubble babble should match ssh-keygen's for RSA")
        }
    }
    
    @Test("Bubble babble matches ssh-keygen (ECDSA)")
    func testBubbleBabbleMatchesECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let curves = [
                ("256", KeyType.ecdsa256),
                ("384", KeyType.ecdsa384),
                ("521", KeyType.ecdsa521)
            ]
            
            for (bits, _) in curves {
                let keyPath = tempDir.appendingPathComponent("id_ecdsa_\(bits)")
                let genResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-t", "ecdsa",
                    "-b", bits,
                    "-f", keyPath.path,
                    "-N", "",
                    "-C", "bubblebabble-ecdsa\(bits)@example.com"
                ])
                #expect(genResult.succeeded, "ssh-keygen should generate ECDSA \(bits) key")
                
                let sshBubbleResult = try IntegrationTestSupporter.runSSHKeygen([
                    "-B", "-f", keyPath.path
                ])
                #expect(sshBubbleResult.succeeded, "ssh-keygen should generate bubble babble")
                
                let sshBubble = extractBubbleBabble(from: sshBubbleResult.stdout)
                #expect(sshBubble != nil, "Should extract ssh-keygen bubble babble for ECDSA \(bits)")
                
                let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
                let ourBubble = key.fingerprint(hash: .sha256, format: .bubbleBabble)
                
                let sshBubbleClean = sshBubble?.replacingOccurrences(of: "xubem-", with: "")
                let ourBubbleClean = ourBubble.replacingOccurrences(of: "xubem-", with: "")
                
                #expect(sshBubbleClean == ourBubbleClean, "Bubble babble should match for ECDSA \(bits)")
            }
        }
    }
    
    // MARK: - Bubble Babble Format Validation
    
    @Test("Bubble babble format structure")
    func testBubbleBabbleFormatStructure() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "bubble-format@example.com")
        let bubble = key.fingerprint(hash: .sha256, format: .bubbleBabble)
        
        // Should have hyphen-separated parts
        let parts = bubble.split(separator: "-")
        #expect(parts.count > 0, "Bubble babble should have hyphen-separated parts")
        
        // Each part should follow vowel-consonant pattern
        let vowels = CharacterSet(charactersIn: "aeiouy")
        // OpenSSH bubblebabble uses a sentinel 'x' at the start and end.
        // Consonant set for core positions (excluding 'x' which only appears as sentinel in first/last parts).
        let coreConsonants = CharacterSet(charactersIn: "bcdfghklmnprstvz")
        let xSet = CharacterSet(charactersIn: "x")

        for (idx, part) in parts.enumerated() {
            let chars = Array(part.lowercased())
            guard chars.count == 5 else { continue }

            let isFirst = idx == 0
            let isLast = idx == parts.count - 1

            // First part begins with the leading sentinel 'x'
            if isFirst {
                #expect(xSet.contains(chars[0].unicodeScalars.first!), "First part should start with sentinel 'x'")
            } else {
                #expect(coreConsonants.contains(chars[0].unicodeScalars.first!), "First char should be consonant")
            }

            #expect(vowels.contains(chars[1].unicodeScalars.first!), "Second char should be vowel")

            // Last part may have 'x' in the middle when the digest length is even (per OpenSSH algorithm)
            if isLast && xSet.contains(chars[2].unicodeScalars.first!) {
                // allowed: sentinel 'x' in middle of last part
            } else {
                #expect(coreConsonants.contains(chars[2].unicodeScalars.first!), "Third char should be consonant")
            }

            #expect(vowels.contains(chars[3].unicodeScalars.first!), "Fourth char should be vowel")

            // Last part ends with trailing sentinel 'x'
            if isLast {
                #expect(xSet.contains(chars[4].unicodeScalars.first!), "Fifth char of last part should be sentinel 'x'")
            } else {
                #expect(coreConsonants.contains(chars[4].unicodeScalars.first!), "Fifth char should be consonant")
            }
        }
    }
    
    @Test("Bubble babble is deterministic")
    func testBubbleBabbleDeterministic() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "bubble-det@example.com")
        
        let bubble1 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
        let bubble2 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
        let bubble3 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
        
        #expect(bubble1 == bubble2, "Bubble babble should be identical (1 vs 2)")
        #expect(bubble2 == bubble3, "Bubble babble should be identical (2 vs 3)")
    }
    
    @Test("Bubble babble differs for different keys")
    func testBubbleBabbleDiffersForDifferentKeys() throws {
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519, comment: "bubble1@example.com")
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519, comment: "bubble2@example.com")
        
        let bubble1 = key1.fingerprint(hash: .sha256, format: .bubbleBabble)
        let bubble2 = key2.fingerprint(hash: .sha256, format: .bubbleBabble)
        
        #expect(bubble1 != bubble2, "Bubble babble should differ for different keys")
    }
    
    // MARK: - Helper Methods
    
    /// Extract randomart from ssh-keygen -lv output
    /// Format includes the art box between +---- lines
    private func extractRandomart(from output: String) -> String? {
        let lines = output.split(separator: "\n")
        
        // Find start and end of randomart
        guard let startIndex = lines.firstIndex(where: { $0.hasPrefix("+---[") }) else { return nil }
        guard let endIndex = lines[startIndex...].firstIndex(where: { $0.hasPrefix("+---") && !$0.contains("[") }) else { return nil }
        
        // Extract randomart lines
        let artLines = lines[startIndex...endIndex]
        return artLines.joined(separator: "\n")
    }
    
    /// Extract bubble babble from ssh-keygen -B output
    /// Format: "256 xubem-dydek-kysom-... comment (ED25519)"
    private func extractBubbleBabble(from output: String) -> String? {
        let lines = output.split(separator: "\n")
        guard let line = lines.first else { return nil }
        
        let parts = line.split(separator: " ")
        
        // Find the bubble babble part (starts with x, contains hyphens)
        guard let bubblePart = parts.first(where: { $0.hasPrefix("x") && $0.contains("-") }) else { return nil }
        
        return String(bubblePart)
    }
}
