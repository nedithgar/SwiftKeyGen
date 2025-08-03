import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("RSA PEM Encoding Tests")
struct RSAPEMTests {
    
    @Test("Generate RSA key and export as PEM")
    func testRSAPEMGeneration() throws {
        // Generate a 2048-bit RSA key
        let key = try RSAKeyGenerator.generate(bits: 2048, comment: "test@example.com")
        
        // Get PEM representation
        let pem = try key.privateKey.pkcs1PEMRepresentation()
        
        // Verify PEM format
        #expect(pem.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
        #expect(pem.hasSuffix("-----END RSA PRIVATE KEY-----\n"))
        
        // Extract base64 content
        let lines = pem.split(separator: "\n")
        #expect(lines.count >= 3)
        #expect(lines[0] == "-----BEGIN RSA PRIVATE KEY-----")
        #expect(lines[lines.count - 1] == "-----END RSA PRIVATE KEY-----")
        
        // Verify base64 content can be decoded
        let base64Content = lines[1..<lines.count-1].joined()
        let derData = Data(base64Encoded: base64Content)
        #expect(derData != nil)
        
        // Verify DER structure starts with SEQUENCE tag
        if let derData = derData {
            #expect(derData[0] == 0x30) // SEQUENCE tag
        }
    }
    
    @Test("Generate RSA public key PEM")
    func testRSAPublicKeyPEM() throws {
        // Generate a 2048-bit RSA key
        let key = try RSAKeyGenerator.generate(bits: 2048, comment: "test@example.com")
        
        // Get public key PEM representation
        let publicPEM = try key.privateKey.publicKey.pkcs1PEMRepresentation()
        
        // Verify PEM format
        #expect(publicPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        #expect(publicPEM.hasSuffix("-----END PUBLIC KEY-----\n"))
        
        // Extract base64 content
        let lines = publicPEM.split(separator: "\n")
        #expect(lines.count >= 3)
        
        // Verify base64 content can be decoded
        let base64Content = lines[1..<lines.count-1].joined()
        let derData = Data(base64Encoded: base64Content)
        #expect(derData != nil)
        
        // Verify DER structure starts with SEQUENCE tag
        if let derData = derData {
            #expect(derData[0] == 0x30) // SEQUENCE tag
        }
    }
    
    @Test("RSA key sizes in PEM format")
    func testVariousKeySizePEM() throws {
        let keySizes = [1024, 2048, 3072, 4096]
        
        for keySize in keySizes {
            let key = try RSAKeyGenerator.generate(bits: keySize)
            let pem = try key.privateKey.pkcs1PEMRepresentation()
            
            // PEM should be valid
            #expect(pem.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
            #expect(pem.hasSuffix("-----END RSA PRIVATE KEY-----\n"))
            
            // Larger keys should produce longer PEM strings
            let lines = pem.split(separator: "\n")
            let base64Content = lines[1..<lines.count-1].joined()
            
            // Rough estimate: key size in bytes * 4/3 for base64
            let expectedMinLength = (keySize / 8) * 4 / 3
            #expect(base64Content.count > expectedMinLength)
        }
    }
    
    @Test("SwiftKeyGen PEM conversion methods")
    func testSwiftKeyGenPEMConversion() throws {
        // Generate RSA key
        let key = try RSAKeyGenerator.generate(bits: 2048, comment: "test@example.com")
        
        // Test private key PEM conversion
        let privatePEM = try SwiftKeyGen.rsaToPEM(key)
        #expect(privatePEM.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
        
        // Test public key PEM conversion
        let publicPEM = try SwiftKeyGen.rsaPublicKeyToPEM(key)
        #expect(publicPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
    }
    
    @Test("RSAKey pemRepresentation property")
    func testRSAKeyPEMProperty() throws {
        // Generate RSA key
        let key = try RSAKeyGenerator.generate(bits: 2048, comment: "test@example.com")
        
        // Test pemRepresentation property
        let pem = key.pemRepresentation
        #expect(!pem.isEmpty)
        #expect(pem.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
    }
}