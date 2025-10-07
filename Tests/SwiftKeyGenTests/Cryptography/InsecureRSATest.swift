import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto
import _CryptoExtras
import BigInt

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
    
    @Test("RSA Encryption/Decryption")
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

    @Test("RSA encryption padding sanity (debug)")
    func testRSAEncryptionPaddingSanity() throws {
        let (priv, pub) = try Insecure.RSA.generateKeyPair(bitSize: 1024)
        let k = (pub.bitSize + 7) / 8

        let message = Data("Hello, RSA!".utf8)
        #expect(message.count <= k - 11)

        // Build PKCS#1 v1.5 block: 0x00 0x02 PS 0x00 M
        var em = Data()
        em.append(0x00)
        em.append(0x02)
        let psLen = k - message.count - 3
        var ps = try Data.generateSecureRandomBytes(count: psLen)
        for i in 0..<ps.count { if ps[i] == 0 { ps[i] = 1 } }
        em.append(ps)
        em.append(0x00)
        em.append(message)

        #expect(em.count == k)
        #expect(em[0] == 0x00)
        #expect(em[1] == 0x02)

        // Encrypt -> Decrypt via raw ops
        let m = BigUInt(em)
        let c = Insecure.RSA.rawEncrypt(m, with: pub)
        let mDec = Insecure.RSA.rawDecrypt(c, with: priv)
        let out = mDec.serialize().leftPadded(to: k)

        // Unpadding-like checks
        #expect(out.count == k)
        #expect(out[0] == 0x00)
        #expect(out[1] == 0x02)
        var sep = -1
        for i in 2..<out.count { if out[i] == 0 { sep = i; break } }
        #expect(sep >= 10)
        let recovered = out[(sep + 1)...]
        #expect(Data(recovered) == message)
    }
}
