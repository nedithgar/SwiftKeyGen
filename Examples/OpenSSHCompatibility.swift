#!/usr/bin/env swift

import Foundation
import SwiftKeyGen

/// This example demonstrates OpenSSH compatibility by:
/// 1. Generating keys with SwiftKeyGen
/// 2. Comparing the public key format with ssh-keygen output

func testOpenSSHCompatibility() throws {
    print("SwiftKeyGen - OpenSSH Compatibility Test")
    print("========================================\n")
    
    // Test Ed25519
    print("Ed25519 Key Generation:")
    let ed25519Key = try SwiftKeyGen.generateKeyPair(
        type: .ed25519,
        comment: "swiftkeygen-test@example.com"
    )
    print("Public key: \(ed25519Key.publicKeyString)")
    print("Fingerprint: \(ed25519Key.fingerprint())\n")
    
    // Test RSA
    print("RSA Key Generation (3072 bits):")
    let rsaKey = try SwiftKeyGen.generateKeyPair(
        type: .rsa,
        bits: 3072,
        comment: "swiftkeygen-rsa@example.com"
    )
    print("Public key: \(rsaKey.publicKeyString.prefix(50))...")
    print("Fingerprint: \(rsaKey.fingerprint())\n")
    
    // Test ECDSA
    print("ECDSA P-256 Key Generation:")
    let ecdsaKey = try SwiftKeyGen.generateKeyPair(
        type: .ecdsa256,
        comment: "swiftkeygen-ecdsa@example.com"
    )
    print("Public key: \(ecdsaKey.publicKeyString.prefix(50))...")
    print("Fingerprint: \(ecdsaKey.fingerprint())\n")
    
    // Save keys to temporary files for testing
    let tempDir = FileManager.default.temporaryDirectory
    let testKeyPath = tempDir.appendingPathComponent("swiftkeygen_test").path
    
    print("Saving keys to temporary files...")
    try KeyFileManager.generateKeyPairFiles(
        type: .ed25519,
        privatePath: testKeyPath,
        comment: "test@swiftkeygen"
    )
    
    print("Private key saved to: \(testKeyPath)")
    print("Public key saved to: \(testKeyPath).pub\n")
    
    // Read and display the public key
    if let publicKeyContent = try? String(contentsOfFile: testKeyPath + ".pub", encoding: .utf8) {
        print("Public key file content:")
        print(publicKeyContent)
    }
    
    // Demonstrate key parsing
    print("Key Parsing Example:")
    let sampleKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfG0Zqnz3mF5PZwQN3qjN9Xk8w3x7v8Zqnz3mF5PZwQ test@example"
    
    if let detectedType = KeyParser.detectKeyType(from: sampleKey) {
        print("Detected key type: \(detectedType.algorithmName)")
        
        do {
            let fingerprint = try KeyParser.fingerprint(from: sampleKey)
            print("Calculated fingerprint: \(fingerprint)")
        } catch {
            print("Error calculating fingerprint: \(error)")
        }
    }
    
    // Clean up
    try? FileManager.default.removeItem(atPath: testKeyPath)
    try? FileManager.default.removeItem(atPath: testKeyPath + ".pub")
}

// Run the test
do {
    try testOpenSSHCompatibility()
} catch {
    print("Error: \(error)")
}
