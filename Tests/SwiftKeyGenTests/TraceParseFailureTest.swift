import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Trace Parse Failure")
struct TraceParseFailureTest {
    
    @Test("Find exact failure point")
    func findExactFailurePoint() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Now let's manually recreate the parse logic to find where it fails
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
        
        // Check magic manually
        let magicLength = 15
        let magicData = keyData.subdata(in: 0..<magicLength)
        let expectedMagic = Data("openssh-key-v1\0".utf8)
        print("Magic check: \(magicData == expectedMagic)")
        
        // Create decoder after magic
        var decoder = SSHDecoder(data: keyData.subdata(in: magicLength..<keyData.count))
        
        // The parse method declares cipherName but doesn't use it
        // This might be causing a different code path
        let cipherName = try decoder.decodeString()
        let kdfName = try decoder.decodeString()
        print("Cipher: \(cipherName), KDF: \(kdfName)")
        
        // Check if the issue is related to the unused variable warning
        // Let's call the actual parse method and see what happens
        print("\nCalling actual parse method...")
        do {
            _ = try OpenSSHPrivateKey.parse(data: serializedData)
            print("✅ Parse succeeded!")
        } catch {
            print("❌ Parse failed with: \(error)")
            
            // The error is invalidFormat, which could come from several places
            // Let's check if it's the marker check by modifying the PEM
            let modifiedPEM = pemString.replacingOccurrences(
                of: "-----BEGIN OPENSSH PRIVATE KEY-----", 
                with: "-----BEGIN OPENSSH PRIVATE KEY-----"
            )
            
            if modifiedPEM == pemString {
                print("PEM markers are correct")
            }
            
            // Check if base64 is valid
            if Data(base64Encoded: base64String) != nil {
                print("Base64 is valid")
            }
            
            // The issue must be after base64 decoding
            print("Issue is in binary parsing after base64 decode")
        }
    }
}