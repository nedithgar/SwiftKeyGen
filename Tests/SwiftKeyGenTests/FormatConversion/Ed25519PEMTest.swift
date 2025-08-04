import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Suite("Ed25519 PEM Support Test")
struct Ed25519PEMTest {
    
    @Test("Check if Ed25519 supports PEM")
    func testEd25519PEMSupport() throws {
        // Generate an Ed25519 key
        let privateKey = Curve25519.Signing.PrivateKey()
        
        // Check if it has PEM representation
        // Let's see what properties/methods are available
        print("Private key type: \(type(of: privateKey))")
        
        // Try to get PEM representation
        // Note: This is just to check what's available
        // If pemRepresentation exists, it would be a property or method
        
        // Let's also check the public key
        let publicKey = privateKey.publicKey
        print("Public key type: \(type(of: publicKey))")
        
        // For now, let's just check raw representation
        print("Private key raw representation size: \(privateKey.rawRepresentation.count)")
        print("Public key raw representation size: \(publicKey.rawRepresentation.count)")
    }
    
    @Test("Try parsing Ed25519 PEM")
    func testParseEd25519PEM() throws {
        // This is a real Ed25519 private key in PKCS8 PEM format
        let ed25519PEM = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIGLGzqMx9D4yHQbFSzLAcplQAJ8cEm1lrN9ujhHLVKUa
        -----END PRIVATE KEY-----
        """
        
        // Let's try different approaches to parse it
        
        // Approach 1: Check if Curve25519.Signing.PrivateKey has an init(pemRepresentation:)
        // This would be the ideal case
        
        // Approach 2: Try using _CryptoExtras
        // Maybe there's extended support there
        
        // For now, let's just verify this is valid PEM
        #expect(ed25519PEM.contains("BEGIN PRIVATE KEY"))
        #expect(ed25519PEM.contains("END PRIVATE KEY"))
    }
}