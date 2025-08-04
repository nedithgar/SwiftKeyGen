import Testing
@testable import SwiftKeyGen
import Foundation

@Test("P521 encryption test")
func p521EncryptionTest() throws {
    let key = try ECDSAKeyGenerator.generateP521(comment: "p521-test")
    let passphrase = "test123"
    
    print("=== Testing P521 key encryption ===")
    
    // Try unencrypted first
    let unencryptedPEM = key.sec1PEMRepresentation
    print("Unencrypted PEM:")
    print(unencryptedPEM)
    
    // Write and test with openssl
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let plainPath = tempDir.appendingPathComponent("p521_plain_\(testId).pem").path
    
    try unencryptedPEM.write(toFile: plainPath, atomically: true, encoding: .utf8)
    
    let opensslProcess = Process()
    opensslProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    opensslProcess.arguments = [
        "ec",
        "-in", plainPath,
        "-text",
        "-noout"
    ]
    
    try opensslProcess.run()
    opensslProcess.waitUntilExit()
    
    if opensslProcess.terminationStatus == 0 {
        print("✅ OpenSSL can read unencrypted P521 key")
    } else {
        print("❌ OpenSSL cannot read unencrypted P521 key")
    }
    
    // Now try encrypted
    let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    print("\nEncrypted PEM:")
    print(encryptedPEM)
    
    let encPath = tempDir.appendingPathComponent("p521_enc_\(testId).pem").path
    try encryptedPEM.write(toFile: encPath, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: encPath)
    
    // Test with ssh-keygen
    let sshProcess = Process()
    sshProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    sshProcess.arguments = [
        "-f", encPath,
        "-y",
        "-P", passphrase
    ]
    
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    sshProcess.standardOutput = outputPipe
    sshProcess.standardError = errorPipe
    
    try sshProcess.run()
    sshProcess.waitUntilExit()
    
    if sshProcess.terminationStatus == 0 {
        print("✅ ssh-keygen can decrypt P521 key")
        let output = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        print("Public key: \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
    } else {
        print("❌ ssh-keygen cannot decrypt P521 key")
        let error = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        print("Error: \(error)")
    }
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: plainPath)
    try? FileManager.default.removeItem(atPath: encPath)
}