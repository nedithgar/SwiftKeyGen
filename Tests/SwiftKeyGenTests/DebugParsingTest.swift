import Testing
import Foundation
@testable import SwiftKeyGen

struct DebugParsingTest {
    @Test("Debug parsing step by step")
    func testDebugParsing() throws {
        // Generate a key
        let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "test@example.com")
        let key = keyPair.privateKey
        
        // Serialize the key
        let keyData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Convert to string
        let keyString = String(data: keyData, encoding: .utf8)!
        
        // Extract base64
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
        
        let base64String = base64Lines.joined()
        guard let decodedData = Data(base64Encoded: base64String) else {
            Issue.record("Failed to decode base64")
            return
        }
        
        print("Decoded data length: \(decodedData.count)")
        
        var decoder = SSHDecoder(data: decodedData)
        
        // Read magic header
        let magicLength = "openssh-key-v1\0".count
        let magicBytes = try decoder.decodeBytes(count: magicLength)
        let magic = Data(magicBytes)
        print("Magic: \(String(data: magic, encoding: .utf8) ?? "invalid")")
        
        // Read cipher and KDF
        let cipherName = try decoder.decodeString()
        let kdfName = try decoder.decodeString()
        print("Cipher: \(cipherName), KDF: \(kdfName)")
        
        // Read KDF data
        let kdfData = try decoder.decodeData()
        print("KDF data length: \(kdfData.count)")
        
        // Read number of keys
        let numKeys = try decoder.decodeUInt32()
        print("Number of keys: \(numKeys)")
        
        // Read public key
        let publicKeyData = try decoder.decodeData()
        print("Public key data length: \(publicKeyData.count)")
        
        // Read encrypted length
        let encryptedLength = try decoder.decodeUInt32()
        print("Encrypted section length: \(encryptedLength)")
        print("Remaining bytes: \(decoder.remaining)")
        
        if decoder.remaining < Int(encryptedLength) {
            print("ERROR: Not enough bytes remaining! Expected \(encryptedLength), have \(decoder.remaining)")
            return
        }
        
        // Read encrypted data
        let encryptedData = try decoder.decodeBytes(count: Int(encryptedLength))
        print("Successfully read encrypted data")
        
        // Decode the private section
        var privateDecoder = SSHDecoder(data: Data(encryptedData))
        
        // Check bytes
        let check1 = try privateDecoder.decodeUInt32()
        let check2 = try privateDecoder.decodeUInt32()
        print("Check bytes: \(check1) == \(check2) ? \(check1 == check2)")
        
        // Key type
        let keyType = try privateDecoder.decodeString()
        print("Private key type: \(keyType)")
        
        // For Ed25519: public key, then private key
        let pubKey = try privateDecoder.decodeData()
        print("Public key in private section: \(pubKey.count) bytes")
        
        let privKey = try privateDecoder.decodeData()
        print("Private key data: \(privKey.count) bytes")
        
        // Comment
        let comment = try privateDecoder.decodeString()
        print("Comment: '\(comment)'")
        
        // Check padding
        print("Remaining bytes for padding: \(privateDecoder.remaining)")
        var paddingIndex = 1
        while privateDecoder.remaining > 0 {
            let pad = try privateDecoder.decodeBytes(count: 1)[0]
            print("Padding byte \(paddingIndex): \(pad) (expected: \(paddingIndex & 0xff))")
            if pad != UInt8(paddingIndex & 0xff) {
                print("ERROR: Invalid padding!")
            }
            paddingIndex += 1
        }
    }
}