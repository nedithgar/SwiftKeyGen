import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Suite("PEM Private Key Import Tests")
struct PEMPrivateKeyImportTests {
    
    @Test("Parse RSA private key from PEM")
    func testParseRSAPrivateKey() throws {
        // Generate a 2048-bit RSA key for testing (our implementation only supports 2048, 3072, 4096)
        let rsaKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "test@example.com") as! RSAKey
        
        // Convert to PEM format
        let pemString = try KeyConverter.toPEM(key: rsaKey)
        
        // Parse the PEM back
        let parsedKey = try PEMParser.parseRSAPrivateKey(pemString)
        
        // Verify it can be used for operations
        let testData = Data("test message".utf8)
        let signature = try parsedKey.sign(data: testData)
        
        // Verify the signature
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid == true)
        
        // Verify public key export works
        let publicKeyString = parsedKey.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-rsa"))
    }
    
    @Test("Ed25519 PEM parsing supported")
    func testEd25519PEMSupported() throws {
        // Ed25519 PEM support is available in Swift Crypto
        let ed25519PrivateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIGLGzqMx9D4yHQbFSzLAcplQAJ8cEm1lrN9ujhHLVKUa
        -----END PRIVATE KEY-----
        """
        
        // This should work
        let key = try PEMParser.parseEd25519PrivateKey(ed25519PrivateKeyPEM)
        #expect(key.keyType == .ed25519)
        
        // Test that encrypted PEM is not supported
        #expect(throws: SSHKeyError.self) {
            _ = try PEMParser.parseEd25519PrivateKey(ed25519PrivateKeyPEM, passphrase: "password")
        }
    }
    
    @Test("Parse ECDSA private key from PEM")
    func testParseECDSAPrivateKey() throws {
        // Simple test with a known ECDSA P-256 private key
        let ecdsaPrivateKeyPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIIGLlamZU9Z83D3g8VsmdqKhu5u47L4RjSXNe3zxQNXPoAoGCCqGSM49
        AwEHoUQDQgAECpyx7ELpzJzPdF4MvH08bvn1Y4vxcxVR7Sk7qCryPniGkGQyNkNE
        d3P3jLw5bFFQdRHLdN7B1C4RRcjXiT9nOg==
        -----END EC PRIVATE KEY-----
        """
        
        // Parse the private key
        let ecdsaKey = try PEMParser.parseECDSAPrivateKey(ecdsaPrivateKeyPEM)
        
        // Verify public key export works
        let publicKeyString = ecdsaKey.publicKeyString()
        #expect(publicKeyString.hasPrefix("ecdsa-sha2-nistp256"))
    }
}