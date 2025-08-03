import Foundation
import SwiftKeyGen

// Example 1: Generate Ed25519 key pair and save to files
func generateEd25519Example() throws {
    print("Generating Ed25519 key pair...")
    
    // Generate key pair with comment
    let keyPair = try SwiftKeyGen.generateKeyPair(
        type: .ed25519,
        comment: "user@example.com"
    )
    
    // Display fingerprint
    let fingerprint = keyPair.fingerprint(hash: .sha256)
    print("Key fingerprint: \(fingerprint)")
    
    // Write to files (similar to ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519)
    let homeDir = FileManager.default.homeDirectoryForCurrentUser
    let sshDir = homeDir.appendingPathComponent(".ssh")
    let privatePath = sshDir.appendingPathComponent("id_ed25519_swift").path
    
    try KeyFileManager.generateKeyPairFiles(
        type: .ed25519,
        privatePath: privatePath,
        comment: "user@example.com"
    )
    
    print("Keys saved to:")
    print("  Private: \(privatePath)")
    print("  Public:  \(privatePath).pub")
}

// Example 2: Generate key in memory and get public key string
func inMemoryExample() throws {
    print("\nGenerating Ed25519 key in memory...")
    
    let key = try SwiftKeyGen.generateKey(
        type: .ed25519,
        comment: "test-key"
    )
    
    // Get public key in OpenSSH format
    let publicKeyString = key.publicKeyString()
    print("Public key:")
    print(publicKeyString)
    
    // Get fingerprints in different formats
    let sha256Fingerprint = key.fingerprint(hash: .sha256)
    let md5Fingerprint = key.fingerprint(hash: .md5)
    let bubbleBabble = key.fingerprint(hash: .sha256, format: .bubbleBabble)
    
    print("\nFingerprints:")
    print("  SHA256: \(sha256Fingerprint)")
    print("  MD5:    \(md5Fingerprint)")
    print("  Bubble: \(bubbleBabble)")
}

// Run examples
do {
    try generateEd25519Example()
    try inMemoryExample()
} catch {
    print("Error: \(error)")
}