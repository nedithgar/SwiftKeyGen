import Testing
import Foundation
@testable import SwiftKeyGen

struct DetailedParsingTest {
    @Test("Detailed parsing test")
    func testDetailedParsing() throws {
        // Generate a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        
        // Serialize the key
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Print the key for debugging
        let keyString = String(data: keyData, encoding: .utf8)!
        print("Generated key:")
        print(keyString)
        
        // Save to file
        let tempDir = FileManager.default.temporaryDirectory
        let keyPath = tempDir.appendingPathComponent("test_key_\(UUID().uuidString)")
        try keyData.write(to: keyPath)
        
        print("\nKey saved to: \(keyPath.path)")
        
        // Try to read it back
        do {
            let parsedKey = try KeyManager.readPrivateKey(from: keyPath.path)
            print("Successfully parsed key!")
            print("Key type: \(parsedKey.keyType)")
            print("Comment: \(parsedKey.comment ?? "nil")")
        } catch {
            print("Failed to parse key: \(error)")
            
            // Try parsing directly
            do {
                let directParsed = try OpenSSHPrivateKey.parse(data: keyData, passphrase: nil)
                print("Direct parsing succeeded!")
            } catch {
                print("Direct parsing also failed: \(error)")
            }
        }
        
        // Clean up
        try? FileManager.default.removeItem(at: keyPath)
    }
}