import Testing
import Foundation
@testable import SwiftKeyGen

struct CompareRealSSHKey {
    @Test("Compare with real SSH key")
    func testCompareWithRealSSHKey() throws {
        // This is a test Ed25519 key generated with:
        // ssh-keygen -t ed25519 -f test_key -N "" -C "test@example.com"
        let realSSHKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBt5QetJQ8QH1C1dVhI6wqJSSsb1UVKbwQhFjPLeRGJMAAAAJhMCadETAmn
        RAAAAAtzc2gtZWQyNTUxOQAAACBt5QetJQ8QH1C1dVhI6wqJSSsb1UVKbwQhFjPLeRGJMA
        AAAEDbpuLhSq2OMQF3PO0m3/pJAFmBYh5pLdh+wYnWdPPLBm3lB60lDxAfULV1WEjrColJ
        KxvVRUpvBCEWM8t5EYkwAAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
        -----END OPENSSH PRIVATE KEY-----
        """
        
        // Parse the real key
        let realKeyData = Data(realSSHKey.utf8)
        do {
            let parsedKey = try OpenSSHPrivateKey.parse(data: realKeyData, passphrase: nil)
            print("Successfully parsed real SSH key!")
            print("Key type: \(parsedKey.keyType)")
            print("Comment: \(parsedKey.comment ?? "nil")")
        } catch {
            print("Failed to parse real SSH key: \(error)")
            
            // Let's debug this
            let lines = realSSHKey.components(separatedBy: .newlines)
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
                if inKey && !line.isEmpty && !line.trimmingCharacters(in: .whitespaces).isEmpty {
                    base64Lines.append(line.trimmingCharacters(in: .whitespaces))
                }
            }
            
            let base64String = base64Lines.joined()
            print("Base64 string: \(base64String)")
            
            if let decodedData = Data(base64Encoded: base64String) {
                print("Decoded length: \(decodedData.count)")
                print("First 16 bytes: \(decodedData.prefix(16).hexString)")
            }
        }
    }
}

// Extension already defined in another test file