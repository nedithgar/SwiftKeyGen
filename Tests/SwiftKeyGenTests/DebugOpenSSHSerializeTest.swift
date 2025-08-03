import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug OpenSSH Serialize")
struct DebugOpenSSHSerializeTest {
    
    @Test("Debug serialize step by step")
    func debugSerializeStepByStep() throws {
        // Generate a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        
        print("Generated key type: \(key.keyType.rawValue)")
        print("Key comment: \(key.comment ?? "nil")")
        print("Public key string: \(key.publicKeyString())")
        
        // Try to serialize
        do {
            let serializedData = try OpenSSHPrivateKey.serialize(key: key)
            print("Serialization succeeded")
            print("Serialized data length: \(serializedData.count)")
            
            // Convert to string to check format
            if let serializedString = String(data: serializedData, encoding: .utf8) {
                print("Serialized string preview:")
                print(serializedString.prefix(100))
                print("...")
                print(serializedString.suffix(100))
            }
        } catch {
            print("Serialization failed with error: \(error)")
            throw error
        }
    }
}