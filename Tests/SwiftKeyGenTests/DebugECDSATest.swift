import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug ECDSA Test")
struct DebugECDSATest {
    
    @Test("Debug P384 serialization")
    func debugP384() throws {
        // Generate P384 key
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "test") as! ECDSAKey
        
        print("Key type: \(key.keyType)")
        
        // Check the private key storage
        var rawKeyData: Data? = nil
        switch key.privateKeyStorage {
        case .p256(let k):
            print("P256 - raw: \(k.rawRepresentation.count) bytes")
            rawKeyData = k.rawRepresentation
        case .p384(let k):
            print("P384 - raw: \(k.rawRepresentation.count) bytes")
            print("P384 - x963: \(k.publicKey.x963Representation.count) bytes")
            rawKeyData = k.rawRepresentation
            print("P384 raw key first byte: 0x\(String(format: "%02x", k.rawRepresentation[0]))")
            print("P384 raw key has high bit set: \(k.rawRepresentation[0] & 0x80 != 0)")
        case .p521(let k):
            print("P521 - raw: \(k.rawRepresentation.count) bytes")
            rawKeyData = k.rawRepresentation
        }
        
        // Try to serialize
        do {
            let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            print("Serialization successful! \(serialized.count) bytes")
            
            // Convert to string to inspect
            if let str = String(data: serialized, encoding: .utf8) {
                print("First 200 chars: \(String(str.prefix(200)))")
            }
            
            // Try to parse back
            do {
                let parsed = try OpenSSHPrivateKey.parse(data: serialized) as! ECDSAKey
                print("Parsing successful!")
                print("Parsed key type: \(parsed.keyType)")
                
                // Compare public keys
                print("Original public key data count: \(key.publicKeyData().count)")
                print("Parsed public key data count: \(parsed.publicKeyData().count)")
                print("Public keys match: \(key.publicKeyData() == parsed.publicKeyData())")
            } catch {
                print("Parse error: \(error)")
                throw error
            }
        } catch {
            print("Serialize error: \(error)")
            throw error
        }
    }
}
