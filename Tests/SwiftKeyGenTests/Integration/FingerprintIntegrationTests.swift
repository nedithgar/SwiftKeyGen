import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("Fingerprint Integration Tests", .tags(.integration))
struct FingerprintIntegrationTests {
    
    // MARK: - SHA256 Fingerprint Matching
    
    @Test("SHA256 fingerprint matches ssh-keygen (Ed25519)")
    func testSHA256FingerprintEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "fingerprint-test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate Ed25519 key")
            
            // Get fingerprint from ssh-keygen
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha256"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate fingerprint")
            
            // Extract fingerprint (format: "256 SHA256:xxxxxxxxxxx comment (ED25519)")
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA256")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen fingerprint")
            
            // Parse key with our implementation
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha256, format: .base64)
            
            // Remove "SHA256:" prefix from our fingerprint if present
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA256:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA256 fingerprints should match for Ed25519")
        }
    }
    
    @Test("SHA256 fingerprint matches ssh-keygen (RSA)", .tags(.slow))
    func testSHA256FingerprintRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "fingerprint-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha256"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA256")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha256, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA256:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA256 fingerprints should match for RSA")
        }
    }
    
    @Test("SHA256 fingerprint matches ssh-keygen (ECDSA P-256)")
    func testSHA256FingerprintECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "256",
                "-f", keyPath.path,
                "-N", "",
                "-C", "fingerprint-ecdsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha256"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA256")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha256, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA256:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA256 fingerprints should match for ECDSA")
        }
    }
    
    // MARK: - SHA512 Fingerprint Matching
    
    @Test("SHA512 fingerprint matches ssh-keygen (Ed25519)")
    func testSHA512FingerprintEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "sha512-test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate Ed25519 key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha512"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate SHA512 fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA512")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen SHA512 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha512, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA512:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA512 fingerprints should match for Ed25519")
        }
    }
    
    @Test("SHA512 fingerprint matches ssh-keygen (RSA)", .tags(.slow))
    func testSHA512FingerprintRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "sha512-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha512"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate SHA512 fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA512")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen SHA512 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha512, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA512:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA512 fingerprints should match for RSA")
        }
    }
    
    @Test("SHA512 fingerprint matches ssh-keygen (ECDSA)")
    func testSHA512FingerprintECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "384",
                "-f", keyPath.path,
                "-N", "",
                "-C", "sha512-ecdsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha512"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate SHA512 fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA512")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen SHA512 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha512, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA512:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "SHA512 fingerprints should match for ECDSA")
        }
    }
    
    // MARK: - MD5 Fingerprint Matching
    
    @Test("MD5 fingerprint matches ssh-keygen (Ed25519)")
    func testMD5FingerprintEd25519() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "md5-test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate Ed25519 key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "md5"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate MD5 fingerprint")
            
            // MD5 format: "256 MD5:xx:xx:xx:xx:... comment (ED25519)"
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "MD5")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen MD5 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .md5, format: .hex)
            
            // Our format should already be in colon-separated hex
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "MD5:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "MD5 fingerprints should match for Ed25519")
        }
    }
    
    @Test("MD5 fingerprint matches ssh-keygen (RSA)", .tags(.slow))
    func testMD5FingerprintRSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_rsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", keyPath.path,
                "-N", "",
                "-C", "md5-rsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate RSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "md5"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate MD5 fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "MD5")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen MD5 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .md5, format: .hex)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "MD5:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "MD5 fingerprints should match for RSA")
        }
    }
    
    @Test("MD5 fingerprint matches ssh-keygen (ECDSA)")
    func testMD5FingerprintECDSA() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ecdsa")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ecdsa",
                "-b", "521",
                "-f", keyPath.path,
                "-N", "",
                "-C", "md5-ecdsa@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate ECDSA key")
            
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "md5"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should generate MD5 fingerprint")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "MD5")
            #expect(sshFingerprint != nil, "Should extract ssh-keygen MD5 fingerprint")
            
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .md5, format: .hex)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "MD5:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "MD5 fingerprints should match for ECDSA")
        }
    }
    
    // MARK: - Fingerprint from Different Sources
    
    @Test("Fingerprint from private key matches public key")
    func testFingerprintFromPrivateAndPublicKey() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let keyPath = tempDir.appendingPathComponent("id_ed25519")
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "source-test@example.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Get fingerprint from private key
            let privResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", keyPath.path, "-E", "sha256"
            ])
            #expect(privResult.succeeded, "Should get fingerprint from private key")
            
            // Get fingerprint from public key
            let pubPath = tempDir.appendingPathComponent("id_ed25519.pub")
            let pubResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", pubPath.path, "-E", "sha256"
            ])
            #expect(pubResult.succeeded, "Should get fingerprint from public key")
            
            let privFingerprint = extractFingerprint(from: privResult.stdout, algorithm: "SHA256")
            let pubFingerprint = extractFingerprint(from: pubResult.stdout, algorithm: "SHA256")
            
            #expect(privFingerprint == pubFingerprint, "Fingerprints from private and public key should match")
            
            // Our implementation should also match
            let key = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let ourFingerprint = key.fingerprint(hash: .sha256, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA256:", with: "")
            
            #expect(privFingerprint == ourFingerprintClean, "Our fingerprint should match ssh-keygen's")
        }
    }
    
    @Test("Fingerprint from public key file matches our computation")
    func testFingerprintFromPublicKeyFile() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate with our implementation
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "our-key@example.com")
            
            // Write public key
            let pubPath = tempDir.appendingPathComponent("our_key.pub")
            try IntegrationTestSupporter.write(key.publicKeyString(), to: pubPath, permissions: 0o644)
            
            // Get fingerprint from ssh-keygen
            let sshResult = try IntegrationTestSupporter.runSSHKeygen([
                "-l", "-f", pubPath.path, "-E", "sha256"
            ])
            #expect(sshResult.succeeded, "ssh-keygen should compute fingerprint from our public key")
            
            let sshFingerprint = extractFingerprint(from: sshResult.stdout, algorithm: "SHA256")
            let ourFingerprint = key.fingerprint(hash: .sha256, format: .base64)
            let ourFingerprintClean = ourFingerprint.replacingOccurrences(of: "SHA256:", with: "")
            
            #expect(sshFingerprint == ourFingerprintClean, "Fingerprints should match from public key file")
        }
    }
    
    // MARK: - Fingerprint Format Consistency
    
    @Test("Fingerprint format has correct prefix")
    func testFingerprintFormatPrefix() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "format-test@example.com")
        
        let sha256 = key.fingerprint(hash: .sha256, format: .base64)
        #expect(sha256.hasPrefix("SHA256:"), "SHA256 fingerprint should have correct prefix")
        
        let sha512 = key.fingerprint(hash: .sha512, format: .base64)
        #expect(sha512.hasPrefix("SHA512:"), "SHA512 fingerprint should have correct prefix")
        
        let md5 = key.fingerprint(hash: .md5, format: .hex)
        #expect(md5.contains(":"), "MD5 fingerprint should contain colons")
        
        // MD5 should be in format xx:xx:xx:xx:...
        let md5Parts = md5.replacingOccurrences(of: "MD5:", with: "").split(separator: ":")
        #expect(md5Parts.count == 16, "MD5 should have 16 hex pairs")
        for part in md5Parts {
            #expect(part.count == 2, "Each MD5 part should be 2 hex digits")
        }
    }
    
    @Test("Base64 fingerprint encoding is valid")
    func testBase64FingerprintEncoding() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "encoding-test@example.com")
        
        let sha256 = key.fingerprint(hash: .sha256, format: .base64)
        let sha256Clean = sha256.replacingOccurrences(of: "SHA256:", with: "")
        
        // Base64 should only contain valid characters
        let base64Charset = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        #expect(sha256Clean.unicodeScalars.allSatisfy { base64Charset.contains($0) }, 
                "SHA256 fingerprint should be valid base64")
        
        // Should not have padding for SHA256 (32 bytes = 43 base64 chars without padding)
        #expect(!sha256Clean.hasSuffix("="), "SHA256 fingerprint should not have padding")
    }
    
    // MARK: - Helper Methods
    
    /// Extract fingerprint from ssh-keygen output
    /// Format: "256 SHA256:xxxxxxxxxxx comment (ED25519)"
    /// or: "2048 MD5:xx:xx:xx:... comment (RSA)"
    private func extractFingerprint(from output: String, algorithm: String) -> String? {
        let lines = output.split(separator: "\n")
        guard let line = lines.first(where: { $0.contains(algorithm) }) else { return nil }
        
        let parts = line.split(separator: " ")
        guard let fingerprintPart = parts.first(where: { $0.contains(algorithm + ":") }) else { return nil }
        
        // Remove "SHA256:" or "MD5:" prefix
        return String(fingerprintPart).replacingOccurrences(of: algorithm + ":", with: "")
    }
}
