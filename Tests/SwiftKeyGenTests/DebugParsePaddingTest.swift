import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug Parse Padding")
struct DebugParsePaddingTest {
    
    @Test("Debug padding validation")
    func debugPaddingValidation() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Manually parse to check padding
        guard let pemString = String(data: serializedData, encoding: .utf8) else {
            throw SSHKeyError.invalidFormat
        }
        
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
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Skip to the encrypted section
        var offset = 15 // magic
        var decoder = SSHDecoder(data: keyData.subdata(in: offset..<keyData.count))
        
        _ = try decoder.decodeString() // cipher
        _ = try decoder.decodeString() // kdf
        _ = try decoder.decodeData() // kdf data
        _ = try decoder.decodeUInt32() // num keys
        _ = try decoder.decodeData() // public key
        
        // Get encrypted section
        let encryptedLength = try decoder.decodeUInt32()
        let encryptedData = try decoder.decodeBytes(count: Int(encryptedLength))
        
        print("Encrypted section length: \(encryptedLength)")
        
        // Parse the inner section
        var privateDecoder = SSHDecoder(data: Data(encryptedData))
        
        let check1 = try privateDecoder.decodeUInt32()
        let check2 = try privateDecoder.decodeUInt32()
        print("Check values: \(check1) == \(check2)")
        
        let keyType = try privateDecoder.decodeString()
        print("Key type: \(keyType)")
        
        let publicKeyData = try privateDecoder.decodeData()
        print("Public key data length: \(publicKeyData.count)")
        
        let privateKeyData = try privateDecoder.decodeData()
        print("Private key data length: \(privateKeyData.count)")
        
        let comment = try privateDecoder.decodeString()
        print("Comment: \(comment)")
        
        // Check padding
        print("\nPadding check:")
        print("Remaining bytes: \(privateDecoder.remaining)")
        print("Block size for 'none' cipher: 8")
        print("Total decrypted length: \(encryptedData.count)")
        print("Length % 8 = \(encryptedData.count % 8)")
        
        if privateDecoder.remaining > 0 {
            let paddingBytes = try privateDecoder.decodeBytes(count: privateDecoder.remaining)
            print("Padding bytes: \(paddingBytes.map { String(format: "%02x", $0) }.joined(separator: " "))")
            print("Expected: \(Array(1...paddingBytes.count).map { String(format: "%02x", $0) }.joined(separator: " "))")
            
            // Check if padding is correct
            for (index, byte) in paddingBytes.enumerated() {
                let expected = UInt8((index + 1) & 0xff)
                if byte != expected {
                    print("❌ Padding mismatch at index \(index): got \(byte), expected \(expected)")
                }
            }
        }
        
        // Try the actual parse method
        print("\n=== Attempting actual parse ===")
        do {
            let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData)
            print("✅ Parse succeeded!")
            print("Parsed key type: \(parsedKey.keyType)")
        } catch {
            print("❌ Parse failed: \(error)")
        }
    }
}