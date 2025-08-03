import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug OpenSSH Parse Method")
struct DebugOpenSSHParseMethodTest {
    
    @Test("Call parse method directly")
    func callParseMethodDirectly() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        print("=== Original Key ===")
        print("Type: \(key.keyType.rawValue)")
        print("Comment: \(key.comment ?? "nil")")
        print("Public key: \(key.publicKeyString())")
        
        print("\n=== Attempting to parse ===")
        
        do {
            let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData)
            print("✅ Parsing succeeded!")
            print("Parsed type: \(parsedKey.keyType.rawValue)")
            print("Parsed comment: \(parsedKey.comment ?? "nil")")
            print("Parsed public key: \(parsedKey.publicKeyString())")
        } catch let error as SSHKeyError {
            print("❌ Parsing failed with SSHKeyError: \(error)")
            
            // Let's trace through the parse method manually
            print("\n=== Manual trace ===")
            
            // Check if we can at least decode the PEM
            guard let pemString = String(data: serializedData, encoding: .utf8) else {
                print("Failed at PEM string conversion")
                throw error
            }
            print("✓ PEM string conversion successful")
            
            // Check PEM markers
            let hasBegin = pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
            let hasEnd = pemString.contains("-----END OPENSSH PRIVATE KEY-----")
            print("✓ Has BEGIN marker: \(hasBegin)")
            print("✓ Has END marker: \(hasEnd)")
            
            if !hasBegin || !hasEnd {
                print("Failed at PEM marker check")
                throw error
            }
            
            // Extract base64
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
            print("✓ Base64 string length: \(base64String.count)")
            
            guard let keyData = Data(base64Encoded: base64String) else {
                print("Failed at base64 decoding")
                throw error
            }
            print("✓ Base64 decoded, data length: \(keyData.count)")
            
            // The error must be after this point
            print("\nError occurred after base64 decoding, likely in binary parsing")
            
            throw error
        } catch {
            print("❌ Parsing failed with unexpected error: \(error)")
            throw error
        }
    }
}