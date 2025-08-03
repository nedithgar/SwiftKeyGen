import Testing
import Foundation
@testable import SwiftKeyGen

struct DebugSerializationTest {
    @Test("Debug serialization format")
    func testDebugSerialization() throws {
        // Generate a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        
        // Serialize the key
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Convert to string to see the format
        let keyString = String(data: keyData, encoding: .utf8) ?? "Invalid UTF8"
        print("Serialized key format:")
        print(keyString)
        
        // Check if it has proper PEM markers
        #expect(keyString.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        #expect(keyString.contains("-----END OPENSSH PRIVATE KEY-----"))
        
        // Extract base64 content
        let lines = keyString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inKey = false
        
        for line in lines {
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
        
        print("Base64 lines: \(base64Lines.count)")
        let base64String = base64Lines.joined()
        print("Base64 length: \(base64String.count)")
        
        // Try to decode base64
        guard let decodedData = Data(base64Encoded: base64String) else {
            Issue.record("Failed to decode base64")
            return
        }
        
        print("Decoded data length: \(decodedData.count)")
        
        // Check magic header
        let magicString = "openssh-key-v1\0"
        let magicData = Data(magicString.utf8)
        print("Expected magic: \(magicData.hexString)")
        print("Actual first bytes: \(decodedData.prefix(magicData.count).hexString)")
    }
}

extension Data {
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}