import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("AES-GCM Integration Tests", .tags(.integration, .critical))
struct AESGCMIntegrationTests {
    @Test("AES-GCM with OpenSSH key encryption")
    func testAESGCMWithOpenSSHKey() throws {
        // Generate a test key
        let key = try Ed25519KeyGenerator.generate(comment: "test@aesgcm")
        
        // Test with both AES-GCM ciphers
        let ciphers: [OpenSSHPrivateKey.EncryptionCipher] = [.aes128gcm, .aes256gcm]
        
        for cipher in ciphers {
            // Serialize with passphrase
            let passphrase = "testpass123"
            let serialized = try OpenSSHPrivateKey.serialize(
                key: key,
                passphrase: passphrase,
                comment: key.comment,
                cipher: cipher
            )
            
            // Parse it back
            let parsed = try OpenSSHPrivateKey.parse(
                data: serialized,
                passphrase: passphrase
            )
            
            // Verify the keys match
            #expect(parsed.publicKeyData() == key.publicKeyData())
            #expect(parsed.keyType == key.keyType)
        }
    }
}
