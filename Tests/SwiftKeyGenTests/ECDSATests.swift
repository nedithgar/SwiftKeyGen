import Testing
import Foundation
@testable import SwiftKeyGen

struct ECDSATests {
    
    @Test func generateECDSAP256Key() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa-p256@example.com") as! ECDSAKey
        
        // Verify key type
        #expect(key.keyType == .ecdsa256)
        #expect(key.comment == "ecdsa-p256@example.com")
        
        // Verify public key format
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(publicKeyString.hasSuffix(" ecdsa-p256@example.com"))
        
        // Decode and verify the public key structure
        let publicKeyData = key.publicKeyData()
        var decoder = SSHDecoder(data: publicKeyData)
        
        let keyType = try decoder.decodeString()
        #expect(keyType == "ecdsa-sha2-nistp256")
        
        let curveIdentifier = try decoder.decodeString()
        #expect(curveIdentifier == "nistp256")
        
        let publicKeyBytes = try decoder.decodeData()
        // P-256 public keys in x963 format are 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
        #expect(publicKeyBytes.count == 65)
        #expect(publicKeyBytes[0] == 0x04) // Uncompressed point indicator
    }
    
    @Test func generateECDSAP384Key() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384) as! ECDSAKey
        
        #expect(key.keyType == .ecdsa384)
        
        let publicKeyData = key.publicKeyData()
        var decoder = SSHDecoder(data: publicKeyData)
        
        let keyType = try decoder.decodeString()
        #expect(keyType == "ecdsa-sha2-nistp384")
        
        let curveIdentifier = try decoder.decodeString()
        #expect(curveIdentifier == "nistp384")
        
        let publicKeyBytes = try decoder.decodeData()
        // P-384 public keys in x963 format are 97 bytes (0x04 + 48 bytes X + 48 bytes Y)
        #expect(publicKeyBytes.count == 97)
    }
    
    @Test func generateECDSAP521Key() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521) as! ECDSAKey
        
        #expect(key.keyType == .ecdsa521)
        
        let publicKeyData = key.publicKeyData()
        var decoder = SSHDecoder(data: publicKeyData)
        
        let keyType = try decoder.decodeString()
        #expect(keyType == "ecdsa-sha2-nistp521")
        
        let curveIdentifier = try decoder.decodeString()
        #expect(curveIdentifier == "nistp521")
        
        let publicKeyBytes = try decoder.decodeData()
        // P-521 public keys in x963 format are 133 bytes (0x04 + 66 bytes X + 66 bytes Y)
        #expect(publicKeyBytes.count == 133)
    }
    
    @Test func ecdsaFingerprints() throws {
        let curves: [KeyType] = [.ecdsa256, .ecdsa384, .ecdsa521]
        
        for curve in curves {
            let key = try SwiftKeyGen.generateKey(type: curve) as! ECDSAKey
            
            let sha256Fingerprint = key.fingerprint(hash: .sha256)
            #expect(sha256Fingerprint.hasPrefix("SHA256:"))
            
            let md5Fingerprint = key.fingerprint(hash: .md5, format: .hex)
            #expect(md5Fingerprint.contains(":"))
        }
    }
    
    @Test func generateAllCurvesViaSwiftKeyGen() throws {
        // Test generating through the main API
        let curves: [KeyType] = [.ecdsa256, .ecdsa384, .ecdsa521]
        
        for curve in curves {
            let keyPair = try SwiftKeyGen.generateKeyPair(type: curve, comment: "test")
            #expect(keyPair.publicKeyString.contains(curve.rawValue))
            #expect(keyPair.publicKeyString.contains("test"))
        }
    }
}