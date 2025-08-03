import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug OpenSSH Tests")
struct DebugOpenSSHTests {
    
    @Test("Debug serialization format")
    func testDebugSerialization() throws {
        // Generate a simple key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test") as! Ed25519Key
        
        // Serialize it
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Print the serialized data
        if let string = String(data: serializedData, encoding: .utf8) {
            print("=== Serialized Key ===")
            print(string)
            print("=== End ===")
        }
        
        // Extract base64 portion
        let serializedString = String(data: serializedData, encoding: .utf8)!
        let lines = serializedString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inKey = false
        
        for line in lines {
            print("Line: '\(line)'")
            if line.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                inKey = true
                continue
            }
            if line.contains("-----END OPENSSH PRIVATE KEY-----") {
                break
            }
            if inKey && !line.isEmpty {
                base64Lines.append(line)
            }
        }
        
        print("Base64 lines: \(base64Lines)")
        let base64String = base64Lines.joined()
        print("Base64 string length: \(base64String.count)")
        
        // Try to decode base64
        guard let keyData = Data(base64Encoded: base64String) else {
            throw NSError(domain: "Test", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to decode base64"])
        }
        
        print("Decoded data length: \(keyData.count)")
        
        // Check magic header
        let magicLength = "openssh-key-v1\0".count
        print("Magic length: \(magicLength)")
        print("First \(magicLength) bytes: \(Array(keyData.prefix(magicLength)))")
        
        if let magicString = String(data: keyData.prefix(magicLength), encoding: .utf8) {
            print("Magic string: '\(magicString)'")
        }
        
        // Try parsing
        do {
            let parsed = try OpenSSHPrivateKey.parse(data: serializedData)
            print("Successfully parsed key of type: \(parsed.keyType)")
        } catch {
            print("Parse error: \(error)")
        }
    }
}