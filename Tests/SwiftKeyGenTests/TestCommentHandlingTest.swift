import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Test Comment Handling")
struct TestCommentHandlingTest {
    
    @Test("Check comment preservation")
    func checkCommentPreservation() throws {
        // Generate key with comment
        let originalComment = "test@example.com"
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: originalComment) as! Ed25519Key
        
        print("Original key comment: \(key.comment ?? "nil")")
        
        // Serialize
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Try to parse
        do {
            let parsedKey = try OpenSSHPrivateKey.parse(data: serializedData)
            print("Parse succeeded!")
            print("Parsed key comment: \(parsedKey.comment ?? "nil")")
            
            // Compare
            #expect(parsedKey.comment == originalComment)
        } catch {
            print("Parse failed: \(error)")
            
            // Let's check what comment is stored in the serialized data
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
            
            // Parse to comment
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
            _ = try privateDecoder.decodeData() // public key
            _ = try privateDecoder.decodeData() // private key
            
            let storedComment = try privateDecoder.decodeString()
            print("Comment in serialized data: \(storedComment)")
            
            throw error
        }
    }
}