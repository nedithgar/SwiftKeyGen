import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Debug PEM format")
func debugPEMFormat() throws {
    let key = try ECDSAKeyGenerator.generateP256(comment: "debug-test")
    let passphrase = "test123"
    
    // Export encrypted PEM
    let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    print("=== Generated Encrypted PEM ===")
    print(encryptedPEM)
    print("=== End PEM ===")
    
    // Write to temp file
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let pemPath = tempDir.appendingPathComponent("debug_\(testId).pem").path
    
    try encryptedPEM.write(toFile: pemPath, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pemPath)
    
    // Try to decrypt with openssl
    let opensslProcess = Process()
    opensslProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    opensslProcess.arguments = [
        "ec",
        "-in", pemPath,
        "-passin", "pass:\(passphrase)",
        "-text",
        "-noout"
    ]
    
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    opensslProcess.standardOutput = outputPipe
    opensslProcess.standardError = errorPipe
    
    try opensslProcess.run()
    opensslProcess.waitUntilExit()
    
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
    
    print("=== OpenSSL Output ===")
    print(String(data: outputData, encoding: .utf8) ?? "")
    print("=== OpenSSL Error ===")
    print(String(data: errorData, encoding: .utf8) ?? "")
    print("Exit status: \(opensslProcess.terminationStatus)")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: pemPath)
}

@Test("Debug unencrypted PEM")
func debugUnencryptedPEM() throws {
    let key = try ECDSAKeyGenerator.generateP256(comment: "debug-unencrypted")
    
    // Export unencrypted PEM
    let unencryptedPEM = key.sec1PEMRepresentation
    print("=== Generated Unencrypted PEM ===")
    print(unencryptedPEM)
    print("=== End PEM ===")
    
    // Write to temp file
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let pemPath = tempDir.appendingPathComponent("debug_plain_\(testId).pem").path
    
    try unencryptedPEM.write(toFile: pemPath, atomically: true, encoding: .utf8)
    
    // Try to read with openssl
    let opensslProcess = Process()
    opensslProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    opensslProcess.arguments = [
        "ec",
        "-in", pemPath,
        "-text",
        "-noout"
    ]
    
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    opensslProcess.standardOutput = outputPipe
    opensslProcess.standardError = errorPipe
    
    try opensslProcess.run()
    opensslProcess.waitUntilExit()
    
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
    
    print("=== OpenSSL Output ===")
    print(String(data: outputData, encoding: .utf8) ?? "")
    print("=== OpenSSL Error ===")
    print(String(data: errorData, encoding: .utf8) ?? "")
    print("Exit status: \(opensslProcess.terminationStatus)")
    
    // Also try with ssh-keygen
    let sshProcess = Process()
    sshProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    sshProcess.arguments = [
        "-f", pemPath,
        "-y"  // Extract public key
    ]
    
    let sshOutputPipe = Pipe()
    let sshErrorPipe = Pipe()
    sshProcess.standardOutput = sshOutputPipe
    sshProcess.standardError = sshErrorPipe
    
    try sshProcess.run()
    sshProcess.waitUntilExit()
    
    print("=== ssh-keygen Output ===")
    print(String(data: sshOutputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
    print("=== ssh-keygen Error ===")
    print(String(data: sshErrorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
    print("Exit status: \(sshProcess.terminationStatus)")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: pemPath)
}