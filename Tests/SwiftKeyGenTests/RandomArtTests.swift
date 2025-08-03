import Testing
import Foundation
@testable import SwiftKeyGen

struct RandomArtTests {
    
    @Test func generateRandomArt() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let art = RandomArt.generate(for: key)
        
        // Verify structure
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11) // Header + 9 rows + footer
        
        guard lines.count >= 11 else {
            Issue.record("Random art has incorrect number of lines: \(lines.count)")
            return
        }
        
        // Verify header contains key type
        #expect(lines[0].contains("[ED25519 256]"))
        
        // Verify borders
        #expect(lines[0].hasPrefix("+"))
        #expect(lines[0].hasSuffix("+"))
        #expect(lines[10].hasPrefix("+"))
        #expect(lines[10].hasSuffix("+"))
        
        // Verify field rows
        for i in 1...9 {
            #expect(lines[i].hasPrefix("|"))
            #expect(lines[i].hasSuffix("|"))
            #expect(lines[i].count == 19) // |<17 chars>|
        }
        
        // Verify S and E markers exist
        let fieldContent = lines[1...9].joined()
        #expect(fieldContent.contains("S"))
        #expect(fieldContent.contains("E"))
    }
    
    @Test func differentKeysProduceDifferentArt() throws {
        let key1 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let key2 = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        
        let art1 = RandomArt.generate(for: key1)
        let art2 = RandomArt.generate(for: key2)
        
        #expect(art1 != art2)
    }
    
    @Test func generateFromFingerprint() throws {
        // Test with MD5 fingerprint
        let md5Fingerprint = "43:51:43:a1:b5:fc:8b:b7:0a:3a:a9:b1:0f:66:73:a8"
        let art = RandomArt.generate(from: md5Fingerprint, keyType: "RSA", keySize: 2048)
        
        #expect(art.contains("[RSA 2048]"))
        
        // Verify the art is generated
        let lines = art.split(separator: "\n")
        #expect(lines.count == 11)
    }
    
    @Test func differentKeyTypes() throws {
        let keyTypes: [(KeyType, String, Int)] = [
            (.ed25519, "ED25519", 256),
            (.ecdsa256, "ECDSA", 256),
            (.ecdsa384, "ECDSA", 384),
            (.ecdsa521, "ECDSA", 521)
        ]
        
        for (keyType, expectedName, expectedSize) in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let art = RandomArt.generate(for: key)
            
            #expect(art.contains("[\(expectedName) \(expectedSize)]"))
        }
    }
    
    @Test func printExample() throws {
        // Generate and print an example for visual verification
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "example@test.com") as! Ed25519Key
        let art = RandomArt.generate(for: key)
        
        print("\nExample RandomArt for Ed25519 key:")
        print(art)
        print("\nFingerprint: \(key.fingerprint(hash: .sha256))")
        
        // Basic validation
        #expect(art.contains("S") && art.contains("E"))
    }
}