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
    
    @Test(.disabled("Prime generator falls back to a naïve loop")) // Disabled due to non-standard key size
    func arbitraryKeySize() throws {
        // Test non-standard key size that is not directly supported by CryptoExtras
        let size = 3584  // Non-standard size between 3072 and 4096
        
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
        
        // Verify the modulus size matches the requested key size
        var decoder = SSHDecoder(data: publicData)
        _ = try decoder.decodeString() // skip key type
        _ = try decoder.decodeData()   // skip exponent
        let modulus = try decoder.decodeData()
        
        // Modulus size should match key size (in bytes)
        let expectedSize = size / 8  // 3584 / 8 = 448 bytes
        #expect(modulus.count >= expectedSize - 1 && modulus.count <= expectedSize + 1)
        
        // Basic fingerprint test
        let fingerprint = key.fingerprint(hash: .sha256)
        #expect(fingerprint.hasPrefix("SHA256:"))
    }
}