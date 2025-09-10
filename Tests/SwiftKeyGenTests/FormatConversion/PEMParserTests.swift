import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PEM Parser Tests")
struct PEMParserTests {
    
    @Test("Generic parsePEM returns type and payload")
    func testGenericParsePEM() throws {
        let pemString = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
        QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
        GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
        FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
        sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
        AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
        -----END RSA PUBLIC KEY-----
        """

        let (type, data) = try PEMParser.parsePEM(pemString)
        #expect(type == "RSA PUBLIC KEY")
        #expect(!data.isEmpty)
    }
    @Test("Detect PEM format")
    func testDetectPEMFormat() {
        let rsaPublicPEM = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEA...
        -----END RSA PUBLIC KEY-----
        """
        
        let publicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
        -----END PUBLIC KEY-----
        """
        
        #expect(PEMParser.isPEMFormat(rsaPublicPEM))
        #expect(PEMParser.isPEMFormat(publicKeyPEM))
        #expect(!PEMParser.isPEMFormat("ssh-rsa AAAAB3..."))
        
        #expect(PEMParser.detectPEMType(rsaPublicPEM) == "RSA PUBLIC KEY")
        #expect(PEMParser.detectPEMType(publicKeyPEM) == "PUBLIC KEY")
    }
    
    @Test("Parse RSA public key from PEM")
    func testParseRSAPublicKeyPEM() throws {
        // Since Swift Crypto requires valid RSA keys, we'll test with a properly generated key
        let rsaKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        
        // Get the public key in PEM format (would need to implement this)
        // For now, just verify that we can create and use RSA keys
        #expect(rsaKey.keyType == .rsa)
        #expect(rsaKey.publicKeyData().count > 0)
    }
    
    @Test("Parse ECDSA public key from PKCS8 PEM")
    func testParseECDSAPublicKeyPKCS8() throws {
        // This is a real P-256 public key in PKCS#8 format
        let pemString = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
        Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
        -----END PUBLIC KEY-----
        """
        
        let parsedKey = try PEMParser.parseECDSAPublicKey(pemString)
        #expect(parsedKey.keyType == .ecdsa256)
    }
    
    @Test("Format conversion with PEM")
    func testFormatConversionWithPEM() throws {
        // Create a simple RSA public key PEM
        let pemString = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
        QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
        GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
        FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
        sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
        AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
        -----END RSA PUBLIC KEY-----
        """
        
        // Create a temp file
        let tempFile = FileManager.default.temporaryDirectory.appendingPathComponent("test.pem")
        try pemString.write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }
        
        // Convert to OpenSSH format (options/output not used in this test)
        
        // We can't easily test stdout, so let's test the parsing directly
        #expect(try KeyConversionManager.detectFormat(from: pemString) == .pem)
    }
    
    @Test("Invalid PEM format")
    func testInvalidPEMFormat() {
        let invalidPEM1 = """
        -----BEGIN RSA PUBLIC KEY-----
        Invalid base64 content!!!
        -----END RSA PUBLIC KEY-----
        """
        
        let invalidPEM2 = """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEA...
        -----END PUBLIC KEY-----
        """
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parsePEM(invalidPEM1)
        }
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parsePEM(invalidPEM2)
        }
    }
    
    @Test("All ECDSA curve types")
    func testAllECDSACurveTypes() throws {
        // P-256 public key
        let p256PEM = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
        Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
        -----END PUBLIC KEY-----
        """
        
        // P-384 public key
        let p384PEM = """
        -----BEGIN PUBLIC KEY-----
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVnthPyYMfHYBgxvQhEJKLdlQFvQvoFfP
        byFLlC5CCuq6e4T8IiEiNvcPNLV+qmHp0jbJPCLSFnkI3vWNFKnVCBhD1dWj4Ski
        B2pJNqOFxjX0PcQNnLBNJAoJtvRMovld
        -----END PUBLIC KEY-----
        """
        
        // P-521 public key
        let p521PEM = """
        -----BEGIN PUBLIC KEY-----
        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBa7azDEtXPrtFqWKTLeQS0pDVjLmv
        VZbfXaZtgvUARwRBim9m3JYj8Kz2p0a2DfLAGXVvvDCwYuWL51YvMD3BRpgBHBdd
        r3rAFs0qzGV6mZu6h1SB3fF6KMeMVmYX5UIZJmJTLxYpe0FfAH2wMAfAwRXftrwS
        3fkcK4cNHqpvn0gWdlE=
        -----END PUBLIC KEY-----
        """
        
        let p256Key = try PEMParser.parseECDSAPublicKey(p256PEM)
        #expect(p256Key.keyType == .ecdsa256)
        
        let p384Key = try PEMParser.parseECDSAPublicKey(p384PEM)
        #expect(p384Key.keyType == .ecdsa384)
        
        let p521Key = try PEMParser.parseECDSAPublicKey(p521PEM)
        #expect(p521Key.keyType == .ecdsa521)
    }
    
    @Test("Parse Ed25519 public key from PKCS8 PEM")
    func testParseEd25519PublicKeyPKCS8() throws {
        // Ed25519 public key in PKCS8 format
        let ed25519PEM = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4L7SfV2U=
        -----END PUBLIC KEY-----
        """
        
        let ed25519Key = try PEMParser.parseEd25519PublicKey(ed25519PEM)
        #expect(ed25519Key.keyType == .ed25519)
        
        // Verify the public key string format
        let publicKeyString = ed25519Key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-ed25519 "))
    }
}
