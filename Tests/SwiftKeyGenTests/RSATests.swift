import Testing
import Foundation
@testable import SwiftKeyGen

struct RSATests {
    
    @Test func generateRSAKey() throws {
        // Generate a 2048-bit RSA key
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa@example.com") as! RSAKey
        
        // Verify key type
        #expect(key.keyType == .rsa)
        #expect(key.comment == "rsa@example.com")
        
        // Verify public key format
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-rsa "))
        #expect(publicKeyString.hasSuffix(" rsa@example.com"))
        
        // Verify public key data
        let publicKeyData = key.publicKeyData()
        #expect(publicKeyData.count > 0)
        
        // Decode and verify the public key structure
        var decoder = SSHDecoder(data: publicKeyData)
        let keyType = try decoder.decodeString()
        #expect(keyType == "ssh-rsa")
        
        let exponent = try decoder.decodeData()
        let modulus = try decoder.decodeData()
        
        // RSA exponent is typically 65537 (0x010001)
        #expect(exponent.count > 0)
        
        // Modulus should be approximately 256 bytes for 2048-bit key
        #expect(modulus.count >= 255 && modulus.count <= 257)
    }
    
    @Test func generateDifferentKeySizes() throws {
        // Test various key sizes supported by CryptoExtras
        let sizes = [2048, 3072, 4096]
        
        for size in sizes {
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: size) as! RSAKey
            let publicKeyData = key.publicKeyData()
            
            var decoder = SSHDecoder(data: publicKeyData)
            _ = try decoder.decodeString() // skip key type
            _ = try decoder.decodeData()   // skip exponent
            let modulus = try decoder.decodeData()
            
            // Modulus size should match key size (in bytes)
            let expectedSize = size / 8
            #expect(modulus.count >= expectedSize - 1 && modulus.count <= expectedSize + 1)
        }
    }
    
    @Test func rsaFingerprint() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        
        // Test fingerprints
        let sha256Fingerprint = key.fingerprint(hash: .sha256)
        #expect(sha256Fingerprint.hasPrefix("SHA256:"))
        
        let md5Fingerprint = key.fingerprint(hash: .md5, format: .hex)
        #expect(md5Fingerprint.contains(":"))
    }
    
    @Test func invalidKeySize() throws {
        // Test invalid key sizes according to OpenSSH standards
        let invalidSizes = [
            512,    // Too small (< 1024)
            768,    // Too small (< 1024)
            1023,   // Not a multiple of 8
            1025,   // Not a multiple of 8
            16385,  // Too large (> 16384)
            32768   // Too large (> 16384)
        ]
        
        for size in invalidSizes {
            do {
                _ = try SwiftKeyGen.generateKey(type: .rsa, bits: size) as! RSAKey
                Issue.record("Expected error for invalid key size \(size)")
            } catch SSHKeyError.invalidKeySize(_, _) {
                // Expected error
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }
    
    @Test func arbitraryKeySizes() throws {
        // Test various arbitrary key sizes that are now supported
        let validSizes = [
            1024,   // Minimum allowed
            1536,   // Non-standard size
            1792,   // Non-standard size
            2048,   // Standard size (CryptoExtras)
            2560,   // Non-standard size
            3072,   // Standard size (CryptoExtras)
            3584,   // Non-standard size
            4096,   // Standard size (CryptoExtras)
            4608,   // Non-standard size
            8192,   // Large key
            16384   // Maximum allowed
        ]
        
        for size in validSizes {
            let key = try SwiftKeyGen.generateKey(type: .rsa, bits: size, comment: "test-\(size)") as! RSAKey
            
            // Verify key was generated
            #expect(key.comment == "test-\(size)")
            
            // Verify public key can be exported
            let publicKeyString = key.publicKeyString()
            #expect(publicKeyString.hasPrefix("ssh-rsa"))
            #expect(publicKeyString.contains("test-\(size)"))
            
            // Verify key size by checking the public key data
            let publicData = key.publicKeyData()
            #expect(publicData.count > 0)
            
            // Basic fingerprint test
            let fingerprint = key.fingerprint(hash: .sha256)
            #expect(fingerprint.hasPrefix("SHA256:"))
        }
    }
}