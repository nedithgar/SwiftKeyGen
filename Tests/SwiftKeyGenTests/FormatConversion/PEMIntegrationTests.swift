import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PEM Integration Tests")
struct PEMIntegrationTests {
    
    @Test("Convert PEM RSA to OpenSSH format")
    func testConvertPEMRSAToOpenSSH() throws {
        // Real RSA public key in PEM format
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
        
        // Parse the PEM key
        let rsaKey = try PEMParser.parseRSAPublicKey(pemString)
        
        // Get OpenSSH format
        let opensshFormat = rsaKey.publicKeyString()
        
        // Verify it starts with ssh-rsa
        #expect(opensshFormat.hasPrefix("ssh-rsa "))
        
        // Verify we can parse it back
        let (keyType, keyData, _) = try KeyParser.parsePublicKey(opensshFormat)
        #expect(keyType == .rsa)
        #expect(!keyData.isEmpty)
    }
    
    @Test("Convert PKCS8 ECDSA to OpenSSH format")
    func testConvertPKCS8ECDSAToOpenSSH() throws {
        // Real P-256 key in PKCS8 format
        let pkcs8String = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
        Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
        -----END PUBLIC KEY-----
        """
        
        // Parse the PKCS8 key
        let ecdsaKey = try PEMParser.parseECDSAPublicKey(pkcs8String)
        
        // Get OpenSSH format
        let opensshFormat = ecdsaKey.publicKeyString()
        
        // Verify it starts with ecdsa-sha2-nistp256
        #expect(opensshFormat.hasPrefix("ecdsa-sha2-nistp256 "))
        
        // Verify we can parse it back
        let (keyType, keyData, _) = try KeyParser.parsePublicKey(opensshFormat)
        #expect(keyType == .ecdsa256)
        #expect(!keyData.isEmpty)
    }
    
    @Test("Full conversion workflow")
    func testFullConversionWorkflow() throws {
        // Test data in different formats
        let testKeys = [
            // RSA PEM
            (format: KeyFormat.pem, content: """
            -----BEGIN RSA PUBLIC KEY-----
            MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
            QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
            GCufmBPkNPPmiWwxWKIQqRoKELnGHEOhm3IsJGE2auOiY2Jbc6aY3bA1U4dliGRz
            FCMEm4j7xr0a7HTQ1Cp7s5g7FTfIdcaBZscCKN7DQ8F6pJ0T8B5OkKkHe8XJ9krG
            sWNcEC6VMpNQQfiBr3dt9AH3MmWGqNW7SwvJdL8jIvP1qTr3le8rOqg4vBGg4taG
            AwfYI8jiKyw6TRx8k7FY8rwIx3x0LqEDNQIDAQAB
            -----END RSA PUBLIC KEY-----
            """),
            
            // ECDSA PKCS8
            (format: KeyFormat.pkcs8, content: """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
            Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
            -----END PUBLIC KEY-----
            """)
        ]
        
        for (format, content) in testKeys {
            // Detect format
            let detectedFormat = try KeyConversionManager.detectFormat(from: content)
            #expect(detectedFormat == format || (format == .pem && detectedFormat == .pem) || (format == .pkcs8 && detectedFormat == .pkcs8))
            
            // Test conversion to RFC4716
            let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: tempDir) }
            
            let inputFile = tempDir.appendingPathComponent("input.pem")
            let outputFile = tempDir.appendingPathComponent("output.rfc")
            
            try content.write(to: inputFile, atomically: true, encoding: .utf8)
            
            let options = KeyConversionManager.ConversionOptions(
                toFormat: .rfc4716,
                fromFormat: format,
                input: inputFile.path,
                output: outputFile.path
            )
            
            try KeyConversionManager.convertKey(options: options)
            
            // Verify output file exists
            #expect(FileManager.default.fileExists(atPath: outputFile.path))
            
            // Read and verify RFC4716 format
            let outputContent = try String(contentsOfFile: outputFile.path, encoding: .utf8)
            #expect(KeyParser.isRFC4716Format(outputContent))
        }
    }
    
    @Test("Convert PKCS8 Ed25519 to OpenSSH format")
    func testConvertPKCS8Ed25519ToOpenSSH() throws {
        // Real Ed25519 public key in PKCS8 format
        let pkcs8String = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4L7SfV2U=
        -----END PUBLIC KEY-----
        """
        
        // Create temp files
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        
        let inputFile = tempDir.appendingPathComponent("ed25519.pkcs8")
        let outputFile = tempDir.appendingPathComponent("ed25519.pub")
        
        try pkcs8String.write(to: inputFile, atomically: true, encoding: .utf8)
        
        // Convert to OpenSSH format
        let options = KeyConversionManager.ConversionOptions(
            toFormat: .openssh,
            fromFormat: .pkcs8,
            input: inputFile.path,
            output: outputFile.path
        )
        
        try KeyConversionManager.convertKey(options: options)
        
        // Verify output
        #expect(FileManager.default.fileExists(atPath: outputFile.path))
        
        let outputContent = try String(contentsOfFile: outputFile.path, encoding: .utf8)
        #expect(outputContent.hasPrefix("ssh-ed25519 "))
        
        // Verify we can parse it back
        let (keyType, keyData, _) = try KeyParser.parsePublicKey(outputContent.trimmingCharacters(in: .whitespacesAndNewlines))
        #expect(keyType == .ed25519)
        #expect(!keyData.isEmpty)
    }
}