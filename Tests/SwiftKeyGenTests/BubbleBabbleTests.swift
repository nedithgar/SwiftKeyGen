import Testing
import Foundation
import SwiftKeyGen
@testable import SwiftKeyGen

@Test("Bubble babble encoding matches OpenSSH implementation")
func testBubbleBabbleEncoding() throws {
    // Note: These test vectors match the OpenSSH implementation of bubble babble,
    // which differs slightly from the original Antti Huima specification.
    // We follow OpenSSH's implementation since this is for SSH key fingerprints.
    struct TestVector {
        let input: Data
        let expected: String
    }
    
    let vectors = [
        // Empty input
        TestVector(
            input: Data(),
            expected: "xexax"
        ),
        
        // Single byte
        TestVector(
            input: Data([0x01]),
            expected: "xebex"  // OpenSSH implementation
        ),
        
        // Two bytes
        TestVector(
            input: Data([0x01, 0x02]),
            expected: "xebeb-dixix"  // OpenSSH implementation
        ),
        
        // MD5 hash example (16 bytes)
        TestVector(
            input: Data([
                0xd1, 0x94, 0x17, 0x5a, 0xd8, 0x2c, 0xf7, 0xbb,
                0x8f, 0xb3, 0xc0, 0x2b, 0x0f, 0xd0, 0x87, 0xd1
            ]),
            expected: "xugen-gihih-pakid-situr-ryfer-fubod-rafut-bocat-cexux"  // OpenSSH implementation
        )
    ]
    
    for vector in vectors {
        let encoded = BubbleBabble.encode(vector.input)
        if encoded != vector.expected {
            print("Input: \(vector.input.map { String(format: "%02x", $0) }.joined())")
            print("Expected: \(vector.expected)")
            print("Got:      \(encoded)")
        }
        #expect(encoded == vector.expected)
    }
}

@Test("Bubble babble fingerprints for different key types")
func testBubbleBabbleFingerprintsForKeys() throws {
    // Generate test keys
    let ed25519Key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
    let rsaKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "test@example.com") as! RSAKey
    let ecdsaKey = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "test@example.com") as! ECDSAKey
    
    // Test MD5 bubble babble
    let ed25519BubbleMD5 = ed25519Key.fingerprint(hash: .md5, format: .bubbleBabble)
    let rsaBubbleMD5 = rsaKey.fingerprint(hash: .md5, format: .bubbleBabble)
    let ecdsaBubbleMD5 = ecdsaKey.fingerprint(hash: HashFunction.md5, format: FingerprintFormat.bubbleBabble)
    
    // Verify format (should start with x and end with x, with groups separated by -)
    #expect(ed25519BubbleMD5.hasPrefix("x"))
    #expect(ed25519BubbleMD5.hasSuffix("x"))
    #expect(ed25519BubbleMD5.contains("-"))
    
    #expect(rsaBubbleMD5.hasPrefix("x"))
    #expect(rsaBubbleMD5.hasSuffix("x"))
    #expect(rsaBubbleMD5.contains("-"))
    
    #expect(ecdsaBubbleMD5.hasPrefix("x"))
    #expect(ecdsaBubbleMD5.hasSuffix("x"))
    #expect(ecdsaBubbleMD5.contains("-"))
    
    // Test SHA256 bubble babble
    let ed25519BubbleSHA256 = ed25519Key.fingerprint(hash: .sha256, format: .bubbleBabble)
    let rsaBubbleSHA256 = rsaKey.fingerprint(hash: .sha256, format: .bubbleBabble)
    let ecdsaBubbleSHA256 = ecdsaKey.fingerprint(hash: HashFunction.sha256, format: FingerprintFormat.bubbleBabble)
    
    // SHA256 produces longer hashes, so more groups
    #expect(ed25519BubbleSHA256.components(separatedBy: "-").count > ed25519BubbleMD5.components(separatedBy: "-").count)
    #expect(rsaBubbleSHA256.components(separatedBy: "-").count > rsaBubbleMD5.components(separatedBy: "-").count)
    #expect(ecdsaBubbleSHA256.components(separatedBy: "-").count > ecdsaBubbleMD5.components(separatedBy: "-").count)
}

@Test("Bubble babble format consistency")
func testBubbleBabbleFormatConsistency() throws {
    let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
    
    // Same key should produce same bubble babble
    let bubble1 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
    let bubble2 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
    #expect(bubble1 == bubble2)
    
    // Different hash algorithms should produce different bubble babble
    let bubbleMD5 = key.fingerprint(hash: .md5, format: .bubbleBabble)
    let bubbleSHA256 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
    let bubbleSHA512 = key.fingerprint(hash: .sha512, format: .bubbleBabble)
    
    #expect(bubbleMD5 != bubbleSHA256)
    #expect(bubbleSHA256 != bubbleSHA512)
    #expect(bubbleMD5 != bubbleSHA512)
}

@Test("Compare fingerprint formats")
func testCompareFingerprintFormats() throws {
    let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
    
    // Get fingerprints in all formats
    let hexMD5 = key.fingerprint(hash: .md5, format: .hex)
    let base64SHA256 = key.fingerprint(hash: .sha256, format: .base64)
    let bubbleSHA256 = key.fingerprint(hash: .sha256, format: .bubbleBabble)
    
    // Verify format characteristics
    #expect(hexMD5.contains(":")) // MD5 hex has colons
    #expect(base64SHA256.hasPrefix("SHA256:")) // SHA256 base64 has prefix
    #expect(bubbleSHA256.hasPrefix("x") && bubbleSHA256.hasSuffix("x")) // Bubble babble format
    
    // All should be different representations
    #expect(!base64SHA256.contains(bubbleSHA256))
    #expect(!hexMD5.contains(bubbleSHA256))
}