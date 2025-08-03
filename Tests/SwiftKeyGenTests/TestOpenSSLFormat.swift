import Testing
@testable import SwiftKeyGen
import Foundation

@Test("Test OpenSSL encrypted PEM generation")
func testOpenSSLPEMGeneration() throws {
    // Create a test key with openssl
    let tempDir = FileManager.default.temporaryDirectory
    let testId = UUID().uuidString
    let keyPath = tempDir.appendingPathComponent("openssl_key_\(testId).pem").path
    let passphrase = "test123"
    
    // Generate key with openssl
    let genProcess = Process()
    genProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    genProcess.arguments = [
        "ecparam",
        "-genkey",
        "-name", "prime256v1",
        "-out", keyPath
    ]
    
    try genProcess.run()
    genProcess.waitUntilExit()
    
    #expect(genProcess.terminationStatus == 0)
    
    // Encrypt the key
    let encryptedPath = tempDir.appendingPathComponent("openssl_encrypted_\(testId).pem").path
    let encProcess = Process()
    encProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
    encProcess.arguments = [
        "ec",
        "-in", keyPath,
        "-out", encryptedPath,
        "-aes128",
        "-passout", "pass:\(passphrase)"
    ]
    
    try encProcess.run()
    encProcess.waitUntilExit()
    
    #expect(encProcess.terminationStatus == 0)
    
    // Read the encrypted PEM
    let encryptedPEM = try String(contentsOfFile: encryptedPath)
    print("=== OpenSSL Generated Encrypted PEM ===")
    print(encryptedPEM)
    
    // Extract DEK-Info
    let lines = encryptedPEM.components(separatedBy: .newlines)
    if let dekLine = lines.first(where: { $0.hasPrefix("DEK-Info:") }) {
        print("DEK-Info line: \(dekLine)")
        let components = dekLine.replacingOccurrences(of: "DEK-Info: ", with: "").split(separator: ",")
        if components.count == 2 {
            print("Cipher: \(components[0])")
            print("Salt/IV hex: \(components[1])")
            print("Salt/IV length: \(components[1].count) characters")
        }
    }
    
    // Now compare with our format
    let key = try ECDSAKeyGenerator.generateP256(comment: "our-test")
    let ourPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    print("\n=== Our Generated Encrypted PEM ===")
    print(ourPEM)
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: keyPath)
    try? FileManager.default.removeItem(atPath: encryptedPath)
}