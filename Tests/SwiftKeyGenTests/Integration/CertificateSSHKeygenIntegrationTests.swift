import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Verify Ed25519 certificate with ssh-keygen", .tags(.integration, .slow))
func testSSHKeygenVerificationEd25519Certificate() throws {
    let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let caKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-ca@example.com") as! Ed25519Key
    let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

    let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
    let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
    try caPrivateKeyData.write(to: caPrivateKeyPath)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: caPrivateKeyPath.path)

    let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
    try caKey.publicKeyString().write(to: caPublicKeyPath, atomically: true, encoding: .utf8)

    let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
    try userKey.publicKeyString().write(to: userPublicKeyPath, atomically: true, encoding: .utf8)

    let cert = try CertificateAuthority.signCertificate(
        publicKey: userKey,
        caKey: caKey,
        keyId: "test-user",
        principals: ["charlie", "test.example.com"],
        certificateType: .user
    )

    let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
    try cert.publicKeyString().write(to: certPath, atomically: true, encoding: .utf8)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-L", "-f", certPath.path]
    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = outputPipe
    try process.run()
    process.waitUntilExit()

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: outputData, encoding: .utf8) ?? ""
    #expect(process.terminationStatus == 0, "ssh-keygen failed to read certificate")
    #expect(output.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
    #expect(output.contains("Key ID: \"test-user\""))
    #expect(output.contains("charlie"))
    #expect(output.contains("test.example.com"))

    let verifyProcess = Process()
    verifyProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    verifyProcess.arguments = ["-L", "-f", certPath.path]
    let verifyPipe = Pipe()
    verifyProcess.standardOutput = verifyPipe
    verifyProcess.standardError = verifyPipe
    try verifyProcess.run()
    verifyProcess.waitUntilExit()
    let verifyData = verifyPipe.fileHandleForReading.readDataToEndOfFile()
    let verifyOutput = String(data: verifyData, encoding: .utf8) ?? ""
    #expect(verifyOutput.contains("Signing CA: ED25519"))

    let principals = tempDir.appendingPathComponent("principals")
    try "charlie\ntest.example.com\n".write(to: principals, atomically: true, encoding: .utf8)

    let checkProcess = Process()
    checkProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    checkProcess.arguments = ["-L", "-f", certPath.path, "-n", "charlie"]
    let checkPipe = Pipe()
    checkProcess.standardOutput = checkPipe
    checkProcess.standardError = checkPipe
    try checkProcess.run()
    checkProcess.waitUntilExit()
    #expect(checkProcess.terminationStatus == 0, "Certificate validation failed")
}

@Test("Verify RSA certificate with ssh-keygen", .tags(.integration, .slow))
func testSSHKeygenVerificationRSACertificate() throws {
    let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDir) }

    let caKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-ca@example.com") as! RSAKey
    let userKey = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@example.com") as! Ed25519Key

    let caPrivateKeyPath = tempDir.appendingPathComponent("ca_key")
    let caPrivateKeyData = try OpenSSHPrivateKey.serialize(key: caKey, passphrase: nil)
    try caPrivateKeyData.write(to: caPrivateKeyPath)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: caPrivateKeyPath.path)

    let caPublicKeyPath = tempDir.appendingPathComponent("ca_key.pub")
    try caKey.publicKeyString().write(to: caPublicKeyPath, atomically: true, encoding: .utf8)

    let userPublicKeyPath = tempDir.appendingPathComponent("user_key.pub")
    try userKey.publicKeyString().write(to: userPublicKeyPath, atomically: true, encoding: .utf8)

    let cert = try CertificateAuthority.signCertificate(
        publicKey: userKey,
        caKey: caKey,
        keyId: "test-rsa-user",
        principals: ["alice", "rsa.example.com"],
        certificateType: .user,
        signatureAlgorithm: "rsa-sha2-512"
    )

    let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
    try cert.publicKeyString().write(to: certPath, atomically: true, encoding: .utf8)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    process.arguments = ["-L", "-f", certPath.path]
    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = outputPipe
    try process.run()
    process.waitUntilExit()

    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: outputData, encoding: .utf8) ?? ""
    #expect(process.terminationStatus == 0, "ssh-keygen failed to read certificate")
    #expect(output.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"))
    #expect(output.contains("Key ID: \"test-rsa-user\""))
    #expect(output.contains("alice"))
    #expect(output.contains("rsa.example.com"))

    let verifyProcess = Process()
    verifyProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    verifyProcess.arguments = ["-L", "-f", certPath.path]
    let verifyPipe = Pipe()
    verifyProcess.standardOutput = verifyPipe
    verifyProcess.standardError = verifyPipe
    try verifyProcess.run()
    verifyProcess.waitUntilExit()
    let verifyData = verifyPipe.fileHandleForReading.readDataToEndOfFile()
    let verifyOutput = String(data: verifyData, encoding: .utf8) ?? ""
    #expect(verifyOutput.contains("Signing CA: RSA"))

    let principals = tempDir.appendingPathComponent("principals")
    try "alice\nrsa.example.com\n".write(to: principals, atomically: true, encoding: .utf8)

    let checkProcess = Process()
    checkProcess.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    checkProcess.arguments = ["-L", "-f", certPath.path, "-n", "alice"]
    let checkPipe = Pipe()
    checkProcess.standardOutput = checkPipe
    checkProcess.standardError = checkPipe
    try checkProcess.run()
    checkProcess.waitUntilExit()
    #expect(checkProcess.terminationStatus == 0, "Certificate validation failed")
}

