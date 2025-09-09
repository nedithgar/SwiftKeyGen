import Testing
@testable import SwiftKeyGen
import Foundation

@Test("ssh-keygen compatibility - decrypt our encrypted PEM")
func testSSHKeygenCanDecryptOurPEM() throws {
    // Generate a test key
    let key = try ECDSAKeyGenerator.generateP256(comment: "integration-test")
    let passphrase = "test123"
    
    // Create temporary directory
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let ourKeyPath = tempDir.appendingPathComponent("our_key_\(testId).pem").path
    
    // Export our encrypted PEM
    let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    try encryptedPEM.write(toFile: ourKeyPath, atomically: true, encoding: .utf8)
    
    // Fix file permissions
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ourKeyPath)
    
    // Use ssh-keygen to extract public key from our encrypted private key
    // This verifies ssh-keygen can decrypt and read our format
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = [
        "-f", ourKeyPath,
        "-y",  // Extract public key
        "-P", passphrase  // Provide passphrase
    ]
    
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = errorPipe
    
    try process.run()
    process.waitUntilExit()
    
    // Check exit status
    #expect(process.terminationStatus == 0, "ssh-keygen should successfully decrypt our PEM file")
    
    // Read output
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: outputData, encoding: .utf8) ?? ""
    
    // Verify output contains valid public key
    #expect(output.contains("ecdsa-sha2-nistp256"), "Output should contain ECDSA public key")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: ourKeyPath)
}

@Test("ssh-keygen compatibility - decrypt our encrypted PKCS8")
func testSSHKeygenCanDecryptOurPKCS8() throws {
    // Generate a test key
    let key = try ECDSAKeyGenerator.generateP384(comment: "pkcs8-test")
    let passphrase = "secret456"
    
    // Create temporary directory
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let ourKeyPath = tempDir.appendingPathComponent("our_key_\(testId).p8").path
    
    // Export our encrypted PKCS8
    let encryptedPKCS8 = try key.pkcs8PEMRepresentation(passphrase: passphrase)
    try encryptedPKCS8.write(toFile: ourKeyPath, atomically: true, encoding: .utf8)
    
    // Fix file permissions
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: ourKeyPath)
    
    // Use ssh-keygen to extract public key from our encrypted private key
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = [
        "-f", ourKeyPath,
        "-y",  // Extract public key
        "-P", passphrase  // Provide passphrase
    ]
    
    let outputPipe = Pipe()
    let errorPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = errorPipe
    
    try process.run()
    process.waitUntilExit()
    
    // Check exit status
    #expect(process.terminationStatus == 0, "ssh-keygen should successfully decrypt our PKCS8 file")
    
    // Read output
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: outputData, encoding: .utf8) ?? ""
    
    // Verify output contains valid public key
    #expect(output.contains("ecdsa-sha2-nistp384"), "Output should contain ECDSA P-384 public key")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: ourKeyPath)
}

@Test("Compare key formats with ssh-keygen")
func testCompareFormatsWithSSHKeygen() throws {
    // Generate a key with ssh-keygen
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let sshKeyPath = tempDir.appendingPathComponent("ssh_key_\(testId)").path
    let passphrase = "compare123"
    
    // Generate ECDSA key with ssh-keygen
    let genProcess = Process()
    genProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    genProcess.arguments = [
        "-t", "ecdsa",
        "-b", "256",
        "-f", sshKeyPath,
        "-N", passphrase,  // Passphrase
        "-C", "ssh-keygen-test"
    ]
    
    // Provide input for prompts
    let inputPipe = Pipe()
    genProcess.standardInput = inputPipe
    inputPipe.fileHandleForWriting.write("y\n".data(using: .utf8)!)  // Overwrite if exists
    
    try genProcess.run()
    genProcess.waitUntilExit()
    
    #expect(genProcess.terminationStatus == 0, "ssh-keygen should generate key successfully")
    
    // Export to PEM format with ssh-keygen
    let pemPath = tempDir.appendingPathComponent("ssh_key_\(testId).pem").path
    let pemProcess = Process()
    pemProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    pemProcess.arguments = [
        "-p",  // Change passphrase
        "-f", sshKeyPath,
        "-m", "PEM",
        "-P", passphrase,  // Old passphrase
        "-N", passphrase   // New passphrase (same)
    ]
    
    // Create a copy of the key for conversion
    let pemKeyPath = sshKeyPath + ".pem"
    try FileManager.default.copyItem(atPath: sshKeyPath, toPath: pemKeyPath)
    
    // Apply conversion on the copy
    pemProcess.arguments = [
        "-p",  // Change passphrase/format
        "-f", pemKeyPath,
        "-m", "PEM",
        "-P", passphrase,  // Old passphrase
        "-N", passphrase   // New passphrase (same)
    ]
    
    try pemProcess.run()
    pemProcess.waitUntilExit()
    
    // Move the converted file to the expected location
    try FileManager.default.moveItem(atPath: pemKeyPath, toPath: pemPath)
    
    // Read the PEM file and verify structure
    let pemContent = try String(contentsOfFile: pemPath, encoding: .utf8)
    #expect(pemContent.contains("BEGIN EC PRIVATE KEY"), "ssh-keygen PEM should be SEC1 format")
    #expect(pemContent.contains("Proc-Type: 4,ENCRYPTED"), "ssh-keygen PEM should be encrypted")
    #expect(pemContent.contains("DEK-Info:"), "ssh-keygen PEM should have DEK-Info header")
    
    // Export to PKCS8 format with ssh-keygen
    let pkcs8Path = tempDir.appendingPathComponent("ssh_key_\(testId).p8").path
    
    // Create a copy of the key for conversion
    let pkcs8KeyPath = sshKeyPath + ".pkcs8"
    try FileManager.default.copyItem(atPath: sshKeyPath, toPath: pkcs8KeyPath)
    
    let pkcs8Process = Process()
    pkcs8Process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    pkcs8Process.arguments = [
        "-p",  // Change passphrase/format
        "-f", pkcs8KeyPath,
        "-m", "PKCS8",
        "-P", passphrase,  // Old passphrase
        "-N", passphrase   // New passphrase (same)
    ]
    
    try pkcs8Process.run()
    pkcs8Process.waitUntilExit()
    
    // Move the converted file to the expected location
    try FileManager.default.moveItem(atPath: pkcs8KeyPath, toPath: pkcs8Path)
    
    // Read the PKCS8 file and verify structure
    let pkcs8Content = try String(contentsOfFile: pkcs8Path, encoding: .utf8)
    #expect(pkcs8Content.contains("BEGIN ENCRYPTED PRIVATE KEY"), "ssh-keygen PKCS8 should be encrypted")
    #expect(!pkcs8Content.contains("Proc-Type"), "PKCS8 should not have PEM encryption headers")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: sshKeyPath)
    try? FileManager.default.removeItem(atPath: sshKeyPath + ".pub")
    try? FileManager.default.removeItem(atPath: pemPath)
    try? FileManager.default.removeItem(atPath: pkcs8Path)
}

@Test("Test different cipher support")
func testDifferentCipherCompatibility() throws {
    let key = try ECDSAKeyGenerator.generateP521(comment: "cipher-test")
    let passphrase = "cipherpass"
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    
    // Test each cipher
    for cipher in PEMEncryption.PEMCipher.allCases {
        let keyPath = tempDir.appendingPathComponent("cipher_\(cipher.rawValue)_\(testId).pem").path
        
        // Export with specific cipher
        let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase, cipher: cipher)
        try encryptedPEM.write(toFile: keyPath, atomically: true, encoding: .utf8)
        
        // Fix file permissions
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
        
        // Verify ssh-keygen can decrypt
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-f", keyPath,
            "-y",  // Extract public key
            "-P", passphrase
        ]
        
        let outputPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = Pipe()
        
        try process.run()
        process.waitUntilExit()
        
        #expect(process.terminationStatus == 0, "ssh-keygen should decrypt \(cipher.rawValue)")
        
        // Cleanup
        try? FileManager.default.removeItem(atPath: keyPath)
    }
}

@Test("Verify public key consistency")
func testPublicKeyConsistency() throws {
    // Generate key with our implementation
    let key = try ECDSAKeyGenerator.generateP256(comment: "consistency-test")
    let passphrase = "consistent"
    
    // Get our public key in OpenSSH format
    let publicKeyData = key.publicKeyData()
    let base64 = publicKeyData.base64EncodedString()
    let ourPublicKey = "ecdsa-sha2-nistp256 \(base64) \(key.comment ?? "")"
    
    // Export encrypted PEM
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let pemPath = tempDir.appendingPathComponent("key_\(testId).pem").path
    
    let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    try encryptedPEM.write(toFile: pemPath, atomically: true, encoding: .utf8)
    
    // Fix file permissions
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pemPath)
    
    // Extract public key using ssh-keygen
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = [
        "-f", pemPath,
        "-y",
        "-P", passphrase
    ]
    
    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    
    try process.run()
    process.waitUntilExit()
    
    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let sshKeygenPublicKey = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    
    // Compare public keys (ignoring comment which might differ)
    let ourKeyPart = ourPublicKey.split(separator: " ").prefix(2).joined(separator: " ")
    let sshKeyPart = sshKeygenPublicKey.split(separator: " ").prefix(2).joined(separator: " ")
    
    #expect(ourKeyPart == sshKeyPart, "Public keys should match")
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: pemPath)
}
