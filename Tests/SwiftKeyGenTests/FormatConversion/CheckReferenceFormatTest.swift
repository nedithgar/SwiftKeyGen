import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Check Reference Format")
struct CheckReferenceFormatTest {
    
    @Test("Understand reference format")
    func understandReferenceFormat() throws {
        // From the reference code, Ed25519 private key format is:
        // 1. Public key data as SSH buffer (length-prefixed)
        // 2. Private key data as SSH buffer containing:
        //    - 32 bytes private key
        //    - 32 bytes public key
        
        // Generate our key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Parse to the private section
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
        
        // Skip to private section
        var decoder = SSHDecoder(data: keyData.subdata(in: 15..<keyData.count))
        _ = try decoder.decodeString() // cipher
        _ = try decoder.decodeString() // kdf
        _ = try decoder.decodeData() // kdf data
        _ = try decoder.decodeUInt32() // num keys
        _ = try decoder.decodeData() // public key
        
        let encryptedLength = try decoder.decodeUInt32()
        let encryptedData = try decoder.decodeBytes(count: Int(encryptedLength))
        
        var privateDecoder = SSHDecoder(data: Data(encryptedData))
        _ = try privateDecoder.decodeUInt32() // check1
        _ = try privateDecoder.decodeUInt32() // check2
        _ = try privateDecoder.decodeString() // key type
        
        // Now we're at the Ed25519 private key data
        print("=== Ed25519 Private Key Format ===")
        
        // According to reference:
        // 1. Read public key as buffer
        let pubKeyData = try privateDecoder.decodeData()
        print("Public key buffer length: \(pubKeyData.count)")
        print("Public key data: \(pubKeyData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        
        // 2. Read private key as buffer (should be 64 bytes)
        let privKeyData = try privateDecoder.decodeData()
        print("\nPrivate key buffer length: \(privKeyData.count)")
        print("First 32 bytes (private): \(privKeyData.prefix(32).map { String(format: "%02x", $0) }.joined(separator: " "))")
        print("Last 32 bytes (public): \(privKeyData.suffix(32).map { String(format: "%02x", $0) }.joined(separator: " "))")
        
        // Check if the public keys match
        if privKeyData.count == 64 {
            let embeddedPublic = privKeyData.suffix(32)
            if embeddedPublic == pubKeyData {
                print("\n✅ Embedded public key matches the separate public key")
            } else {
                print("\n❌ Public keys don't match!")
            }
        }
        
        // Comment
        let comment = try privateDecoder.decodeString()
        print("\nComment: \(comment)")
    }
}