import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Instrumented Parse Test")
struct InstrumentedParseTest {
    
    @Test("Find exact parse failure line")
    func findExactParseFailureLine() throws {
        // Generate and serialize
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test") as! Ed25519Key
        let data = try OpenSSHPrivateKey.serialize(key: key)
        
        // Try the actual parse first
        do {
            _ = try OpenSSHPrivateKey.parse(data: data)
            print("Parse succeeded!")
        } catch {
            print("Parse failed with: \(error)")
            
            // Now let's instrument each step
            guard let pemString = String(data: data, encoding: .utf8) else {
                print("Failed at: Convert to string")
                return
            }
            
            guard pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----") && 
                  pemString.contains("-----END OPENSSH PRIVATE KEY-----") else {
                print("Failed at: PEM marker check")
                return
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
            guard let keyData = Data(base64Encoded: base64String) else {
                print("Failed at: Base64 decode")
                return
            }
            
            // Magic check
            let magicLength = 15
            guard keyData.count >= magicLength else {
                print("Failed at: Magic length check")
                return
            }
            
            let magicData = keyData.subdata(in: 0..<magicLength)
            let expectedMagic = Data("openssh-key-v1\0".utf8)
            guard magicData == expectedMagic else {
                print("Failed at: Magic comparison")
                return
            }
            
            var decoder = SSHDecoder(data: keyData.subdata(in: magicLength..<keyData.count))
            
            // Decode each field
            do {
                let cipherName = try decoder.decodeString()
                let kdfName = try decoder.decodeString()
                let kdfData = try decoder.decodeData()
                
                let numKeys = try decoder.decodeUInt32()
                guard numKeys == 1 else {
                    print("Failed at: numKeys check (got \(numKeys))")
                    return
                }
                
                let publicKeyData = try decoder.decodeData()
                
                let encryptedLength = try decoder.decodeUInt32()
                guard decoder.remaining >= Int(encryptedLength) else {
                    print("Failed at: encrypted length check")
                    print("  Expected: \(encryptedLength), Remaining: \(decoder.remaining)")
                    return
                }
                
                let encryptedData = try decoder.decodeBytes(count: Int(encryptedLength))
                
                // Parse private section
                var privateDecoder = SSHDecoder(data: Data(encryptedData))
                
                let check1 = try privateDecoder.decodeUInt32()
                let check2 = try privateDecoder.decodeUInt32()
                guard check1 == check2 else {
                    print("Failed at: check bytes (got \(check1) != \(check2))")
                    return
                }
                
                let keyType = try privateDecoder.decodeString()
                
                // Ed25519 specific
                let pubKey = try privateDecoder.decodeData()
                let privKey = try privateDecoder.decodeData()
                let comment = try privateDecoder.decodeString()
                
                print("Successfully parsed all fields!")
                print("Remaining for padding: \(privateDecoder.remaining)")
                
                // Check padding
                var paddingIndex = 1
                while privateDecoder.remaining > 0 {
                    let pad = try privateDecoder.decodeBytes(count: 1)[0]
                    if pad != UInt8(paddingIndex & 0xff) {
                        print("Failed at: padding check")
                        print("  Index: \(paddingIndex), Expected: \(paddingIndex & 0xff), Got: \(pad)")
                        return
                    }
                    paddingIndex += 1
                }
                
                print("All checks passed in manual parse!")
                print("The error must be in something else...")
                
            } catch {
                print("Failed during decoding with: \(error)")
            }
        }
    }
}