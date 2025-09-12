import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("KeyParser Tests")
struct KeyParserTests {    
    @Test func detectKeyTypesNonRSA() throws {
        // Faster path – exclude RSA (expensive) to keep core detection coverage
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]

        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType, comment: "test")
            let publicKeyString = key.publicKeyString()

            let detectedType = KeyParser.detectKeyType(from: publicKeyString)
            #expect(detectedType == keyType)
        }
    }

    @Test func detectKeyTypesRSAOnly() throws {
        // Isolate RSA so its higher generation cost doesn't multiply with others
        let key = try SwiftKeyGen.generateKey(type: .rsa, comment: "test-rsa")
        let publicKeyString = key.publicKeyString()
        let detectedType = KeyParser.detectKeyType(from: publicKeyString)
        #expect(detectedType == .rsa)
    }
    
    @Test func parsePublicKeyWithComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "user@host") as! Ed25519Key
        let publicKeyString = key.publicKeyString()
        
        let (type, data, comment) = try KeyParser.parsePublicKey(publicKeyString)
        
        #expect(type == .ed25519)
        #expect(data == key.publicKeyData())
        #expect(comment == "user@host")
    }
    
    @Test func parsePublicKeyWithoutComment() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let publicKeyString = key.publicKeyString()
        
        let (type, _, comment) = try KeyParser.parsePublicKey(publicKeyString)
        
        #expect(type == .ed25519)
        #expect(comment == nil)
    }
    
    @Test func validateKeyDataNonRSA() throws {
        // Validate all non-RSA key types
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]

        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let keyData = key.publicKeyData()

            try KeyParser.validatePublicKeyData(keyData, type: keyType)
        }
    }

    @Test func validateKeyDataRSAOnly() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa)
        let keyData = key.publicKeyData()
        try KeyParser.validatePublicKeyData(keyData, type: .rsa)
    }
    
    @Test func invalidKeyData() throws {
        // Test invalid key data
        let invalidData = Data("invalid".utf8)
        
        do {
            try KeyParser.validatePublicKeyData(invalidData, type: .ed25519)
            Issue.record("Expected validation to fail")
        } catch SSHKeyError.invalidKeyData {
            // Expected
        }
    }
    
    @Test func mismatchedKeyType() throws {
        // Generate Ed25519 key but try to validate as RSA
        let ed25519Key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let keyData = ed25519Key.publicKeyData()
        
        do {
            try KeyParser.validatePublicKeyData(keyData, type: .rsa)
            Issue.record("Expected validation to fail")
        } catch SSHKeyError.invalidKeyData {
            // Expected
        }
    }
    
    @Test func fingerprintFromString() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let publicKeyString = key.publicKeyString()
        
        // Calculate fingerprint directly
        let directFingerprint = key.fingerprint(hash: .sha256)
        
        // Calculate fingerprint from string
        let parsedFingerprint = try KeyParser.fingerprint(from: publicKeyString)
        
        #expect(directFingerprint == parsedFingerprint)
    }
    
    @Test func multipleHashTypesNonRSA() throws {
        // Exercise all fingerprint hash types across each non-RSA algorithm (performance: exclude RSA).
        // This ensures consistent formatting logic irrespective of underlying key algorithm.
        let keyTypes: [KeyType] = [.ed25519, .ecdsa256, .ecdsa384, .ecdsa521]

        for keyType in keyTypes {
            let key = try SwiftKeyGen.generateKey(type: keyType)
            let publicKeyString = key.publicKeyString()

            let sha256 = try KeyParser.fingerprint(from: publicKeyString, hash: .sha256)
            let sha512 = try KeyParser.fingerprint(from: publicKeyString, hash: .sha512)
            let md5 = try KeyParser.fingerprint(from: publicKeyString, hash: .md5)

            #expect(sha256.hasPrefix("SHA256:"), "Expected SHA256 prefix for \(keyType)")
            #expect(sha512.hasPrefix("SHA512:"), "Expected SHA512 prefix for \(keyType)")
            #expect(md5.contains(":") && !md5.hasPrefix("SHA"), "Expected MD5 colon separated hex for \(keyType)") // MD5 prints hex groups with colons
        }
    }

    @Test func multipleHashTypesRSAOnly() throws {
        // Minimal RSA coverage (single hash) to ensure RSA path still interoperates with fingerprinting.
        let key = try SwiftKeyGen.generateKey(type: .rsa) as! RSAKey
        let publicKeyString = key.publicKeyString()
        let sha256 = try KeyParser.fingerprint(from: publicKeyString, hash: .sha256)
        #expect(sha256.hasPrefix("SHA256:"))
    }
}