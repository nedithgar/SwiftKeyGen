import Testing
@testable import SwiftKeyGen
import Foundation

@Test("ssh-keygen cipher support")
func sshKeygenCipherTest() throws {
    let key = try ECDSAKeyGenerator.generateP256(comment: "ssh-cipher-test")
    let passphrase = "test123"
    let tempDir = FileManager.default.temporaryDirectory
    
    for cipher in PEMEncryption.PEMCipher.allCases {
        print("=== Testing \(cipher.rawValue) with ssh-keygen ===")
        
        let testId = UUID().uuidString
        let keyPath = tempDir.appendingPathComponent("ssh_cipher_\(testId).pem").path
        
        // Export with specific cipher
        let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase, cipher: cipher)
        try encryptedPEM.write(toFile: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
        
        // Try with ssh-keygen
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-f", keyPath,
            "-y",  // Extract public key
            "-P", passphrase
        ]
        
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        
        try process.run()
        process.waitUntilExit()
        
        if process.terminationStatus == 0 {
            print("✅ ssh-keygen supports \(cipher.rawValue)")
            let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            print("Public key: \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
        } else {
            print("❌ ssh-keygen does NOT support \(cipher.rawValue)")
            let error = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            print("Error: \(error)")
        }
        
        // Also test with openssl for comparison
        let opensslProcess = Process()
        opensslProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        opensslProcess.arguments = [
            "ec",
            "-in", keyPath,
            "-passin", "pass:\(passphrase)",
            "-pubout"
        ]
        
        let opensslOutputPipe = Pipe()
        opensslProcess.standardOutput = opensslOutputPipe
        opensslProcess.standardError = Pipe()
        
        try opensslProcess.run()
        opensslProcess.waitUntilExit()
        
        if opensslProcess.terminationStatus == 0 {
            print("✅ OpenSSL supports \(cipher.rawValue)")
        }
        
        // Cleanup
        try? FileManager.default.removeItem(atPath: keyPath)
        print("")
    }
}