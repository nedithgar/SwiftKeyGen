import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Debug OpenSSH Detailed")
struct DebugOpenSSHDetailedTest {
    
    @Test("Debug detailed parse")
    func debugDetailedParse() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Convert to string and decode base64
        guard let pemString = String(data: serializedData, encoding: .utf8) else {
            throw SSHKeyError.invalidFormat
        }
        
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
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidFormat
        }
        
        print("Total key data length: \(keyData.count)")
        
        // Manual parsing
        var offset = 0
        
        // 1. Magic header (15 bytes, not length-prefixed)
        let magicLength = 15
        let magicData = keyData.subdata(in: 0..<magicLength)
        print("Magic: \(String(data: magicData, encoding: .utf8)?.debugDescription ?? "invalid")")
        offset = magicLength
        
        // Create decoder for the rest
        var decoder = SSHDecoder(data: keyData.subdata(in: offset..<keyData.count))
        
        // 2. Cipher name (length-prefixed string)
        do {
            let cipherName = try decoder.decodeString()
            print("Cipher: \(cipherName)")
        } catch {
            print("Failed to decode cipher name: \(error)")
            // Let's look at the raw bytes
            let nextBytes = keyData.subdata(in: offset..<min(offset + 20, keyData.count))
            print("Next bytes: \(nextBytes.map { String(format: "%02x", $0) }.joined(separator: " "))")
            
            // Try to decode the length manually
            if keyData.count >= offset + 4 {
                let lengthData = keyData.subdata(in: offset..<offset+4)
                let length = lengthData.withUnsafeBytes { bytes in
                    return UInt32(bigEndian: bytes.load(as: UInt32.self))
                }
                print("String length: \(length)")
                
                if keyData.count >= offset + 4 + Int(length) {
                    let stringData = keyData.subdata(in: offset+4..<offset+4+Int(length))
                    print("String data: \(String(data: stringData, encoding: .utf8) ?? "invalid")")
                }
            }
            throw error
        }
    }
}