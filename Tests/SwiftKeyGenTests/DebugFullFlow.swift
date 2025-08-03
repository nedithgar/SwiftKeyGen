import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Debug full encryption flow")
func debugFullFlow() throws {
    let testData = Data("Hello, World!".utf8)
    let passphrase = "test123"
    let cipher = PEMEncryption.PEMCipher.aes128CBC
    
    print("=== Encryption Process ===")
    print("Original data: \(String(data: testData, encoding: .utf8)!)")
    print("Data length: \(testData.count)")
    
    // Encrypt
    let (encryptedData, iv) = try PEMEncryption.encrypt(
        data: testData,
        passphrase: passphrase,
        cipher: cipher
    )
    
    print("\nReturned IV: \(iv.hexEncodedString())")
    print("Returned IV length: \(iv.count) bytes")
    print("Encrypted data length: \(encryptedData.count) bytes")
    
    // Format as PEM
    let pem = PEMEncryption.formatEncryptedPEM(
        type: "TEST KEY",
        encryptedData: encryptedData,
        cipher: cipher,
        salt: iv
    )
    
    print("\n=== Generated PEM ===")
    print(pem)
    
    // Extract DEK-Info
    let lines = pem.components(separatedBy: CharacterSet.newlines)
    if let dekLine = lines.first(where: { $0.hasPrefix("DEK-Info:") }) {
        let components = dekLine.replacingOccurrences(of: "DEK-Info: ", with: "").split(separator: ",")
        if components.count == 2 {
            print("\nDEK-Info IV hex: \(components[1])")
            print("DEK-Info IV length: \(components[1].count) characters")
        }
    }
}