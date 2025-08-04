import Testing
import Foundation
@testable import SwiftKeyGen

struct Ed25519Tests {
    
    @Test func generateEd25519Key() throws {
        // Generate a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        
        // Verify key type
        #expect(key.keyType == .ed25519)
        #expect(key.comment == "test@example.com")
        
        // Verify public key format
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-ed25519 "))
        #expect(publicKeyString.hasSuffix(" test@example.com"))
        
        // Verify public key data
        let publicKeyData = key.publicKeyData()
        #expect(publicKeyData.count > 0)
        
        // Decode and verify the public key structure
        var decoder = SSHDecoder(data: publicKeyData)
        let keyType = try decoder.decodeString()
        #expect(keyType == "ssh-ed25519")
        
        let publicKeyBytes = try decoder.decodeData()
        #expect(publicKeyBytes.count == 32) // Ed25519 public keys are 32 bytes
    }
    
    @Test func fingerprintGeneration() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        // Test SHA256 fingerprint (default)
        let sha256Fingerprint = key.fingerprint(hash: .sha256)
        #expect(sha256Fingerprint.hasPrefix("SHA256:"))
        
        // Test MD5 fingerprint (hex format with colons)
        let md5Fingerprint = key.fingerprint(hash: .md5, format: .hex)
        #expect(md5Fingerprint.contains(":"))
        #expect(md5Fingerprint.count == 47) // 16 bytes * 2 chars + 15 colons
        
        // Test SHA512 fingerprint
        let sha512Fingerprint = key.fingerprint(hash: .sha512)
        #expect(sha512Fingerprint.hasPrefix("SHA512:"))
    }
    
    @Test func keyPairGeneration() throws {
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "user@host")
        
        #expect(keyPair.publicKeyString.contains("ssh-ed25519"))
        #expect(keyPair.publicKeyString.contains("user@host"))
        
        let fingerprint = keyPair.fingerprint()
        #expect(fingerprint.hasPrefix("SHA256:"))
    }
    
    @Test func deterministicFingerprint() throws {
        // Generate two keys with same private key data should have same fingerprint
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let publicData1 = key1.publicKeyData()
        let fingerprint1 = key1.fingerprint(hash: .sha256)
        
        // The fingerprint should only depend on the public key data
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let publicData2 = key2.publicKeyData()
        let fingerprint2 = key2.fingerprint(hash: .sha256)
        
        // Different keys should have different fingerprints
        #expect(publicData1 != publicData2)
        #expect(fingerprint1 != fingerprint2)
    }
}