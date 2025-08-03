import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Minimal Round Trip Test")
struct MinimalRoundTripTest {
    
    @Test("Simplest round trip")
    func simplestRoundTrip() throws {
        // Create the simplest possible key
        let key = try Ed25519KeyGenerator.generate(comment: "")
        
        print("=== SERIALIZE ===")
        let serialized = try OpenSSHPrivateKey.serialize(key: key)
        print("Serialized \(serialized.count) bytes")
        
        print("\n=== PARSE ===")
        do {
            let parsed = try OpenSSHPrivateKey.parse(data: serialized)
            print("✅ Parse succeeded!")
            print("Key type: \(parsed.keyType)")
            print("Comment: '\(parsed.comment ?? "")'")
        } catch {
            print("❌ Parse failed: \(error)")
            
            // Let's check if it's a simple key with no comment
            let keyNoComment = try Ed25519KeyGenerator.generate(comment: nil)
            let serializedNoComment = try OpenSSHPrivateKey.serialize(key: keyNoComment)
            
            print("\n=== TRY WITHOUT COMMENT ===")
            do {
                let parsedNoComment = try OpenSSHPrivateKey.parse(data: serializedNoComment)
                print("✅ Parse without comment succeeded!")
                print("Comment: '\(parsedNoComment.comment ?? "nil")'")
            } catch {
                print("❌ Parse without comment also failed: \(error)")
            }
        }
    }
    
    @Test("Test with OpenSSH tool")
    func testWithOpenSSHTool() throws {
        // Generate a key and save it to a temp file
        let key = try Ed25519KeyGenerator.generate(comment: "test")
        let serialized = try OpenSSHPrivateKey.serialize(key: key)
        
        let tempDir = FileManager.default.temporaryDirectory
        let keyPath = tempDir.appendingPathComponent("test_key_\(UUID().uuidString)")
        
        try serialized.write(to: keyPath)
        defer { try? FileManager.default.removeItem(at: keyPath) }
        
        // Set proper permissions
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath.path)
        
        print("Wrote key to: \(keyPath.path)")
        
        // Try to use ssh-keygen to verify the key
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-y", "-f", keyPath.path]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        
        if process.terminationStatus == 0 {
            print("✅ ssh-keygen successfully read our key!")
            print("Public key: \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
        } else {
            print("❌ ssh-keygen failed to read our key")
            print("Error: \(output)")
        }
    }
}