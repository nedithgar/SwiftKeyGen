import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("KeyPair wrapper tests", .tags(.unit))
struct KeyPairUnitTests {
    // MARK: - Basic delegation (Ed25519 fast path)
    @Test("KeyPair exposes identical public/private representations as underlying key")
    func keyPairConsistencyEd25519() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "kp@example.com")
        // Algorithm propagated
        #expect(pair.privateKey.keyType == .ed25519)
        // Delegated getters match exactly
        #expect(pair.publicKeyString == pair.privateKey.publicKeyString())
        #expect(pair.publicKeyData == pair.privateKey.publicKeyData())
        #expect(pair.privateKeyData == pair.privateKey.privateKeyData())
        // Public key string should contain the comment at the end
        #expect(pair.publicKeyString.hasSuffix(" kp@example.com"))
        // Quick structural sanity: "ssh-ed25519 <base64> kp@example.com"
        let components = pair.publicKeyString.split(separator: " ")
        #expect(components.count >= 3)
    }

    // MARK: - Fingerprint delegation (Ed25519)
    @Test("KeyPair.fingerprint delegates to underlying key (SHA256 base64)")
    func keyPairFingerprintDelegationEd25519() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        let pairFP = pair.fingerprint(hash: .sha256, format: .base64)
        let directFP = pair.privateKey.fingerprint(hash: .sha256, format: .base64)
        #expect(pairFP == directFP)
        #expect(pairFP.hasPrefix("SHA256:"))
    }

    // MARK: - All hash + format variants (RSA minimal size for speed)
    @Test("KeyPair fingerprint variants parity (RSA)", .tags(.rsa))
    func keyPairFingerprintVariantsRSA() throws {
        // 1024 bits to keep the test reasonably fast
        let pair = try SwiftKeyGen.generateKeyPair(type: .rsa, bits: 1024, comment: "rsa@test")
        // SHA256 (base64 default)
        let sha256Pair = pair.fingerprint(hash: .sha256, format: .base64)
        let sha256Direct = pair.privateKey.fingerprint(hash: .sha256, format: .base64)
        #expect(sha256Pair == sha256Direct)
        #expect(sha256Pair.hasPrefix("SHA256:"))
        // SHA512
        let sha512Pair = pair.fingerprint(hash: .sha512, format: .base64)
        let sha512Direct = pair.privateKey.fingerprint(hash: .sha512, format: .base64)
        #expect(sha512Pair == sha512Direct)
        #expect(sha512Pair.hasPrefix("SHA512:"))
        // MD5 hex (colon separated)
        let md5Pair = pair.fingerprint(hash: .md5, format: .hex)
        let md5Direct = pair.privateKey.fingerprint(hash: .md5, format: .hex)
        #expect(md5Pair == md5Direct)
        #expect(md5Pair.contains(":"))
        // Bubble Babble (structure: should contain dashes and be > 10 chars)
        let bubblePair = pair.fingerprint(hash: .sha256, format: .bubbleBabble)
        let bubbleDirect = pair.privateKey.fingerprint(hash: .sha256, format: .bubbleBabble)
        #expect(bubblePair == bubbleDirect)
        #expect(bubblePair.count > 10)
        #expect(bubblePair.contains("-"))
    }

    // MARK: - No comment scenario
    @Test("KeyPair publicKeyString without comment doesn't include trailing space")
    func keyPairNoComment() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519)
        // Underlying key should have nil comment
        #expect(pair.privateKey.comment == nil)
        let parts = pair.publicKeyString.split(separator: " ")
        // Expect exactly 2 parts: algorithm + base64 when no comment present
        #expect(parts.count == 2, "Expected 2 components (algo + base64) but got \(parts.count): \(parts)")
        // Ensure computed value matches underlying directly
        #expect(pair.publicKeyString == pair.privateKey.publicKeyString())
    }
}
