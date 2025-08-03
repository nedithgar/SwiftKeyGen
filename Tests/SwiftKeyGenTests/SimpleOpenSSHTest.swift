import Testing
import Foundation
@testable import SwiftKeyGen

struct SimpleOpenSSHTest {
    
    @Test func basicSerializationTest() throws {
        print("Starting basic serialization test")
        
        // Generate a simple Ed25519 key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test") as! Ed25519Key
        print("Generated key")
        
        // Try to serialize without passphrase
        do {
            let serialized = try OpenSSHPrivateKey.serialize(key: key)
            print("Serialized key successfully")
            print("Serialized data length: \(serialized.count)")
            
            if let str = String(data: serialized, encoding: .utf8) {
                print("First 100 chars: \(str.prefix(100))")
            }
        } catch {
            print("Serialization failed: \(error)")
            throw error
        }
    }
}