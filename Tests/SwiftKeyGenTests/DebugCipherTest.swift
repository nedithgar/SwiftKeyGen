import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Debug cipher issues")
func debugCipherIssues() throws {
    let key = try ECDSAKeyGenerator.generateP256(comment: "cipher-debug")
    let passphrase = "test123"
    
    // Test each cipher
    for cipher in PEMEncryption.PEMCipher.allCases {
        print("=== Testing \(cipher.rawValue) ===")
        
        do {
            let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase, cipher: cipher)
            print("Generated PEM:")
            print(encryptedPEM)
            
            // Write to file
            let tempDir = FileManager.default.temporaryDirectory
            let testId = UUID().uuidString
            let keyPath = tempDir.appendingPathComponent("cipher_\(cipher.rawValue)_\(testId).pem").path
            
            try encryptedPEM.write(toFile: keyPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
            
            // Try to decrypt with openssl
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = [
                "ec",
                "-in", keyPath,
                "-passin", "pass:\(passphrase)",
                "-text",
                "-noout"
            ]
            
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            
            try process.run()
            process.waitUntilExit()
            
            if process.terminationStatus == 0 {
                print("✅ OpenSSL decryption successful")
            } else {
                print("❌ OpenSSL decryption failed")
                let error = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                print("Error: \(error)")
            }
            
            // Cleanup
            try? FileManager.default.removeItem(atPath: keyPath)
            
        } catch {
            print("❌ Failed to generate encrypted PEM: \(error)")
        }
        
        print("")
    }
}