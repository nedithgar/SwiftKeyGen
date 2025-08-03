import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug Step By Step Parse")
struct DebugStepByStepParseTest {
    
    @Test("Parse with checkpoints")
    func parseWithCheckpoints() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        print("=== SERIALIZATION ===")
        print("Original public key: \(key.publicKeyString())")
        
        // Manual parse to find the issue
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
        
        print("\n=== PARSING ===")
        
        // Parse magic header
        let magicLength = 15
        let magicData = keyData.subdata(in: 0..<magicLength)
        print("✓ Magic header verified")
        
        // Create decoder for the rest
        var decoder = SSHDecoder(data: keyData.subdata(in: magicLength..<keyData.count))
        
        // Read cipher and KDF
        let cipherName = try decoder.decodeString()
        let kdfName = try decoder.decodeString()
        print("✓ Cipher: \(cipherName), KDF: \(kdfName)")
        
        // Read KDF data
        let kdfData = try decoder.decodeData()
        print("✓ KDF data length: \(kdfData.count)")
        
        // Read number of keys
        let numKeys = try decoder.decodeUInt32()
        print("✓ Number of keys: \(numKeys)")
        
        // Read public key
        let publicKeyData = try decoder.decodeData()
        print("✓ Public key data length: \(publicKeyData.count)")
        
        // Decode the public key to verify it
        var pubDecoder = SSHDecoder(data: publicKeyData)
        let pubKeyType = try pubDecoder.decodeString()
        let pubKeyBytes = try pubDecoder.decodeData()
        print("  - Public key type: \(pubKeyType)")
        print("  - Public key bytes: \(pubKeyBytes.count)")
        
        // Read encrypted length
        let encryptedLength = try decoder.decodeUInt32()
        print("✓ Encrypted data length: \(encryptedLength)")
        
        // Check remaining data
        print("  - Decoder remaining: \(decoder.remaining)")
        print("  - Expected: \(Int(encryptedLength))")
        
        if decoder.remaining < Int(encryptedLength) {
            print("❌ Not enough data remaining!")
            print("  - Total key data length: \(keyData.count)")
            print("  - Current position estimate: \(keyData.count - decoder.remaining)")
            throw SSHKeyError.invalidFormat
        }
        
        // Read encrypted data
        let encryptedData = try decoder.decodeBytes(count: Int(encryptedLength))
        print("✓ Read encrypted data")
        
        // Since no passphrase, encrypted data is the decrypted data
        let decryptedData = Data(encryptedData)
        
        // Parse private section
        var privateDecoder = SSHDecoder(data: decryptedData)
        
        // Check bytes
        let check1 = try privateDecoder.decodeUInt32()
        let check2 = try privateDecoder.decodeUInt32()
        print("✓ Check bytes: \(check1) == \(check2)")
        
        // Key type
        let keyType = try privateDecoder.decodeString()
        print("✓ Private key type: \(keyType)")
        
        // For Ed25519, read the key data
        let privPubKeyData = try privateDecoder.decodeData()
        print("✓ Private public key data: \(privPubKeyData.count) bytes")
        
        let privKeyData = try privateDecoder.decodeData()
        print("✓ Private key data: \(privKeyData.count) bytes")
        
        // Comment
        let comment = try privateDecoder.decodeString()
        print("✓ Comment: \(comment)")
        
        // Check padding
        print("✓ Remaining for padding: \(privateDecoder.remaining) bytes")
        
        var paddingIndex = 1
        while privateDecoder.remaining > 0 {
            let pad = try privateDecoder.decodeBytes(count: 1)[0]
            if pad != UInt8(paddingIndex & 0xff) {
                print("❌ Invalid padding at index \(paddingIndex): expected \(paddingIndex & 0xff), got \(pad)")
                throw SSHKeyError.invalidFormat
            }
            paddingIndex += 1
        }
        print("✓ Padding verified")
        
        print("\n✅ Manual parse successful!")
    }
}