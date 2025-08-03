import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug OpenSSH Parse")
struct DebugOpenSSHParseTest {
    
    @Test("Debug parse step by step")
    func debugParseStepByStep() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        print("Original key type: \(key.keyType.rawValue)")
        print("Original comment: \(key.comment ?? "nil")")
        print("Original public key: \(key.publicKeyString())")
        
        // Try to parse
        do {
            let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData)
            print("Parsing succeeded")
            print("Parsed key type: \(parsedKey.keyType.rawValue)")
            print("Parsed comment: \(parsedKey.comment ?? "nil")")
            print("Parsed public key: \(parsedKey.publicKeyString())")
        } catch {
            print("Parsing failed with error: \(error)")
            
            // Let's debug the parsing process
            print("\nDebugging parse process...")
            
            // Convert data to string
            guard let pemString = String(data: serializedData, encoding: .utf8) else {
                print("Failed to convert data to string")
                throw error
            }
            print("PEM string starts with BEGIN: \(pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))")
            print("PEM string ends with END: \(pemString.contains("-----END OPENSSH PRIVATE KEY-----"))")
            
            // Extract base64 content
            let lines = pemString.components(separatedBy: .newlines)
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
            
            let base64String = base64Lines.joined()
            print("Base64 string length: \(base64String.count)")
            
            guard let keyData = Data(base64Encoded: base64String) else {
                print("Failed to decode base64")
                throw error
            }
            print("Decoded data length: \(keyData.count)")
            
            // Check magic
            let magicLength = "openssh-key-v1\0".count
            if keyData.count >= magicLength {
                let magicBytes = keyData.prefix(magicLength)
                let magic = String(data: magicBytes, encoding: .utf8) ?? "invalid"
                print("Magic header: \(magic.debugDescription)")
                print("Magic bytes: \(magicBytes.map { String(format: "%02x", $0) }.joined(separator: " "))")
                
                let expectedMagic = Data("openssh-key-v1\0".utf8)
                print("Expected magic bytes: \(expectedMagic.map { String(format: "%02x", $0) }.joined(separator: " "))")
            } else {
                print("Data too short for magic header")
            }
            
            throw error
        }
    }
}