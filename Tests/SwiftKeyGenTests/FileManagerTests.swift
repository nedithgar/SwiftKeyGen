import Testing
import Foundation
@testable import SwiftKeyGen

struct FileManagerTests {
    
    @Test func writeKeyPairToFiles() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let privateKeyPath = tempDir.appendingPathComponent("test_key").path
        let publicKeyPath = privateKeyPath + ".pub"
        
        // Clean up any existing files
        try? FileManager.default.removeItem(atPath: privateKeyPath)
        try? FileManager.default.removeItem(atPath: publicKeyPath)
        
        // Generate and write key pair
        try KeyFileManager.generateKeyPairFiles(
            type: .ed25519,
            privatePath: privateKeyPath,
            comment: "test@swift"
        )
        
        // Verify files exist
        #expect(FileManager.default.fileExists(atPath: privateKeyPath))
        #expect(FileManager.default.fileExists(atPath: publicKeyPath))
        
        // Verify public key content
        let publicKeyData = try Data(contentsOf: URL(fileURLWithPath: publicKeyPath))
        let publicKeyString = String(data: publicKeyData, encoding: .utf8)!
        
        #expect(publicKeyString.hasPrefix("ssh-ed25519"))
        #expect(publicKeyString.contains("test@swift"))
        
        // Verify file permissions (on Unix systems)
        #if !os(Windows)
        let privateAttrs = try FileManager.default.attributesOfItem(atPath: privateKeyPath)
        let publicAttrs = try FileManager.default.attributesOfItem(atPath: publicKeyPath)
        
        if let privatePerm = privateAttrs[.posixPermissions] as? NSNumber {
            #expect(privatePerm.int16Value == 0o600)
        }
        
        if let publicPerm = publicAttrs[.posixPermissions] as? NSNumber {
            #expect(publicPerm.int16Value == 0o644)
        }
        #endif
        
        // Clean up
        try? FileManager.default.removeItem(atPath: privateKeyPath)
        try? FileManager.default.removeItem(atPath: publicKeyPath)
    }
    
    @Test func customPublicKeyPath() throws {
        let tempDir = FileManager.default.temporaryDirectory
        let privateKeyPath = tempDir.appendingPathComponent("id_ed25519").path
        let customPublicPath = tempDir.appendingPathComponent("custom_public.pub").path
        
        // Clean up any existing files
        try? FileManager.default.removeItem(atPath: privateKeyPath)
        try? FileManager.default.removeItem(atPath: customPublicPath)
        
        // Generate with custom public key path
        try KeyFileManager.generateKeyPairFiles(
            type: .ed25519,
            privatePath: privateKeyPath,
            publicPath: customPublicPath
        )
        
        // Verify custom path was used
        #expect(FileManager.default.fileExists(atPath: customPublicPath))
        #expect(!FileManager.default.fileExists(atPath: privateKeyPath + ".pub"))
        
        // Clean up
        try? FileManager.default.removeItem(atPath: privateKeyPath)
        try? FileManager.default.removeItem(atPath: customPublicPath)
    }
}