import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Isolate Parse Failure")
struct IsolateParseFailureTest {
    
    @Test("Try to isolate the exact failure")
    func isolateExactFailure() throws {
        // Generate and serialize
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test") as! Ed25519Key
        let data = try OpenSSHPrivateKey.serialize(key: key)
        
        // Now let's try parsing with a modified version
        do {
            _ = try OpenSSHPrivateKey.parse(data: data)
            print("Parse succeeded!")
        } catch let error as SSHKeyError {
            print("Parse failed with SSHKeyError: \(error)")
            
            // Check which specific error
            switch error {
            case .invalidFormat:
                print("Error is invalidFormat")
                // This could come from multiple places in the parse method
                // Let's try to narrow it down by testing each check
                
                // Test 1: PEM format
                if let pemString = String(data: data, encoding: .utf8) {
                    if pemString.contains("-----BEGIN OPENSSH PRIVATE KEY-----") &&
                       pemString.contains("-----END OPENSSH PRIVATE KEY-----") {
                        print("✓ PEM markers are correct")
                    }
                }
                
                // Test 2: Base64
                if let pemString = String(data: data, encoding: .utf8) {
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
                    if Data(base64Encoded: base64String) != nil {
                        print("✓ Base64 decoding works")
                    }
                }
                
                print("Error must be after base64 decode in the binary parsing")
                
            case .invalidPassphrase:
                print("Error is invalidPassphrase")
            case .passphraseRequired:
                print("Error is passphraseRequired")
            case .unsupportedKeyType:
                print("Error is unsupportedKeyType")
            case .invalidKeyData:
                print("Error is invalidKeyData")
            default:
                print("Error is: \(error)")
            }
        } catch {
            print("Parse failed with unexpected error: \(error)")
        }
    }
}