import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto
import _CryptoExtras

@Suite("Insecure RSA Test")
struct InsecureRSATest {
    
    @Test("RSA Key Generation")
    func testRSAKeyGeneration() throws {
        // Generate a small RSA key pair for testing (512 bits is insecure but fast for tests)
        let (privateKey, publicKey) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        
        #expect(publicKey.bitSize >= 512)
        #expect(privateKey.bitSize >= 512)
        #expect(publicKey.e == privateKey.e)
        #expect(publicKey.n == privateKey.n)
    }
    
    @Test("RSA Encryption/Decryption", .disabled("Fix padding issue"))
    func testRSAEncryptionDecryption() throws {
        let (privateKey, publicKey) = try Insecure.RSA.generateKeyPair(bitSize: 1024)
        
        guard let plaintext = "Hello, RSA!".data(using: .utf8) else {
            Issue.record("Failed to convert string to data")
            return
        }
        
        // Encrypt with public key
        let ciphertext = try Insecure.RSA.encrypt(plaintext, with: publicKey)
        
        // Decrypt with private key
        let decrypted = try Insecure.RSA.decrypt(ciphertext, with: privateKey)
        
        #expect(decrypted == plaintext)
    }
    
    @Test("RSA Signing/Verification", .disabled("Fix signing issue"))
    func testRSASigningVerification() throws {
        let (privateKey, publicKey) = try Insecure.RSA.generateKeyPair(bitSize: 1024)
        
        guard let message = "Sign this message".data(using: .utf8) else {
            Issue.record("Failed to convert string to data")
            return
        }
        
        // Sign with private key
        let signature = try Insecure.RSA.sign(message, with: privateKey)
        
        // Verify with public key
        let isValid = try Insecure.RSA.verify(signature, for: message, with: publicKey)
        
        #expect(isValid == true)
        
        // Verify with wrong message should fail
        guard let wrongMessage = "Wrong message".data(using: .utf8) else {
            Issue.record("Failed to convert string to data")
            return
        }
        let isInvalid = try Insecure.RSA.verify(signature, for: wrongMessage, with: publicKey)
        
        #expect(isInvalid == false)
    }
    
    @Test("RSA Component Extraction from PEM")
    func testRSAComponentExtraction() throws {
        // Test with our own generated key first
        let (_, publicKey) = try Insecure.RSA.generateKeyPair(bitSize: 1024)
        
        // The bit size might be slightly less due to leading zeros
        #expect(publicKey.bitSize >= 1020)
        #expect(publicKey.bitSize <= 1024)
        #expect(publicKey.e == 65537)
        
        // Test extracting from modulus and exponent data
        let reconstructedKey = try Insecure.RSA.PublicKey(
            modulus: publicKey.modulusData,
            exponent: publicKey.exponentData
        )
        
        #expect(reconstructedKey.n == publicKey.n)
        #expect(reconstructedKey.e == publicKey.e)
    }
}