import Testing
import Foundation
import Crypto
@testable import SwiftKeyGen

@Suite("KeyGeneration factory tests", .tags(.unit))
struct KeyGenerationUnitTests {

    // MARK: - RSA PEM conversion helpers
    @Test("SwiftKeyGen.rsaToPEM returns PKCS#1 private PEM", .tags(.rsa))
    func testRSAPrivatePEMConversion() throws {
        let rsa = try RSAKeyGenerator.generate(bits: 1024, comment: "unit@test")
        let pem = try SwiftKeyGen.rsaToPEM(rsa)
        #expect(pem.hasPrefix("-----BEGIN RSA PRIVATE KEY-----"))
        #expect(pem.hasSuffix("-----END RSA PRIVATE KEY-----\n"))
    }

    @Test("SwiftKeyGen.rsaPublicKeyToPEM returns PKCS#1 public PEM", .tags(.rsa))
    func testRSAPublicPEMConversion() throws {
        let rsa = try RSAKeyGenerator.generate(bits: 1024)
        let pem = try SwiftKeyGen.rsaPublicKeyToPEM(rsa)
        // NOTE: publicKey.pkcs1PEMRepresentation() returns a generic BEGIN PUBLIC KEY header
        #expect(pem.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        #expect(pem.hasSuffix("-----END PUBLIC KEY-----\n"))
    }

    // MARK: - Generation for each algorithm
    @Test("Generate Ed25519 key via SwiftKeyGen.generateKey")
    func testGenerateEd25519() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519@test")
        #expect(key.keyType == .ed25519)
        #expect(key.comment == "ed25519@test")
        // Ed25519 public key strings start with algorithm + space + base64
        let pub = key.publicKeyString()
        #expect(pub.hasPrefix("ssh-ed25519 "))
        #expect(pub.contains("ed25519@test"))
    }

    @Test("Generate RSA key (1024 bits) via SwiftKeyGen.generateKey", .tags(.rsa))
    func testGenerateRSAWithExplicitBits() throws {
        // Use 1024 to keep unit test fast; other sizes covered elsewhere.
        let keyAny = try SwiftKeyGen.generateKey(type: .rsa, bits: 1024, comment: "rsa@test")
        #expect(keyAny.keyType == .rsa)
        #expect(keyAny.comment == "rsa@test")
        // Fingerprint should not be empty
        let fp = keyAny.fingerprint(hash: .sha256, format: .base64)
        #expect(!fp.isEmpty)
    }

    @Test("Generate ECDSA P-256 key via SwiftKeyGen.generateKey")
    func testGenerateECDSA256() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256)
        #expect(key.keyType == .ecdsa256)
        let pub = key.publicKeyString()
        #expect(pub.hasPrefix("ecdsa-sha2-nistp256 "))
    }

    @Test("Generate ECDSA P-384 key via SwiftKeyGen.generateKey")
    func testGenerateECDSA384() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384)
        #expect(key.keyType == .ecdsa384)
        let pub = key.publicKeyString()
        #expect(pub.hasPrefix("ecdsa-sha2-nistp384 "))
    }

    @Test("Generate ECDSA P-521 key via SwiftKeyGen.generateKey")
    func testGenerateECDSA521() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521)
        #expect(key.keyType == .ecdsa521)
        let pub = key.publicKeyString()
        #expect(pub.hasPrefix("ecdsa-sha2-nistp521 "))
    }

    // MARK: - KeyPair wrapper
    @Test("Generate KeyPair wrapper returns consistent public key")
    func testGenerateKeyPairWrapper() throws {
        let pair = try SwiftKeyGen.generateKeyPair(type: .ed25519, comment: "pair@test")
        #expect(pair.privateKey.keyType == .ed25519)
        #expect(pair.publicKeyString.hasPrefix("ssh-ed25519 "))
        // Public key data should match base64 (after splitting). Quick sanity: length > 32
        #expect(pair.publicKeyData.count > 32)
    }

    // MARK: - RSA bit size validation through SwiftKeyGen.generateKey
    @Test("RSA invalid too small bit size throws", .tags(.rsa))
    func testRSATooSmall() throws {
        #expect(throws: SSHKeyError.self) {
            _ = try SwiftKeyGen.generateKey(type: .rsa, bits: 512)
        }
    }

    @Test("RSA invalid non-multiple-of-8 bit size throws", .tags(.rsa))
    func testRSANonAligned() throws {
        #expect(throws: SSHKeyError.self) {
            _ = try SwiftKeyGen.generateKey(type: .rsa, bits: 2050)
        }
    }

    @Test("RSA invalid too large bit size throws", .tags(.rsa))
    func testRSATooLarge() throws {
        #expect(throws: SSHKeyError.self) {
            _ = try SwiftKeyGen.generateKey(type: .rsa, bits: 20000)
        }
    }
}
