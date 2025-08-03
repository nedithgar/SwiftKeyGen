import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Detailed Parse Tests")
struct DetailedParseTests {
    
    @Test("Step by step parse")
    func testStepByStepParse() throws {
        // Generate and serialize a key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test") as! Ed25519Key
        let serializedData = try OpenSSHPrivateKey.serialize(key: key)
        
        // Manual parsing
        guard let pemString = String(data: serializedData, encoding: .utf8) else {
            throw NSError(domain: "Test", code: 1)
        }
        
        print("PEM contains BEGIN: \(pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))")
        print("PEM contains END: \(pemString.contains("-----END OPENSSH PRIVATE KEY-----"))")
        
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
        print("Base64 string: \(base64String.prefix(50))...")
        
        guard let keyData = Data(base64Encoded: base64String) else {
            throw NSError(domain: "Test", code: 2)
        }
        
        print("Key data length: \(keyData.count)")
        
        var decoder = SSHDecoder(data: keyData)
        
        // Read magic header
        let magicLength = "openssh-key-v1\0".count
        print("Expecting magic length: \(magicLength)")
        print("Decoder has \(decoder.remaining) bytes remaining")
        
        let magicBytes = try decoder.decodeBytes(count: magicLength)
        let magic = Data(magicBytes)
        print("Read magic bytes: \(magicBytes)")
        
        if let magicStr = String(data: magic, encoding: .utf8) {
            print("Magic string: '\(magicStr)'")
            print("Magic matches: \(magicStr == "openssh-key-v1\0")")
        }
        
        // Continue with cipher/kdf
        print("After magic, decoder has \(decoder.remaining) bytes remaining")
        
        let cipherName = try decoder.decodeString()
        print("Cipher name: '\(cipherName)'")
        
        let kdfName = try decoder.decodeString()
        print("KDF name: '\(kdfName)'")
    }
}