import Testing
import Foundation
import Crypto
@testable import SwiftKeyGen

@Suite("ECDSAKey Unit Tests", .tags(.unit))
struct ECDSAKeyUnitTests {

    // MARK: - Helpers
    private func assertECDSABasics(
        _ key: ECDSAKey,
        expectedType: KeyType,
        expectedCurve: String,
        expectedPointLength: Int,
        expectedPrivateLength: Int,
        comment: String
    ) throws {
        // Key metadata
        #expect(key.keyType == expectedType)
        #expect(key.comment == comment)

        // Public key string formatting
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("\(expectedType.rawValue) "))
        #expect(publicKeyString.hasSuffix(" \(comment)"))

        // Public key blob structure: [string type][string curve][data point(x963)]
        let publicKeyBlob = key.publicKeyData()
        #expect(publicKeyBlob.count > 0)

        var decoder = SSHDecoder(data: publicKeyBlob)
        let typeString = try decoder.decodeString()
        let curve = try decoder.decodeString()
        let point = try decoder.decodeData()
        #expect(typeString == expectedType.rawValue)
        #expect(curve == expectedCurve)
        #expect(point.count == expectedPointLength)

        // Private key raw representation length
        let priv = key.privateKeyData()
        #expect(priv.count == expectedPrivateLength)
    }

    // MARK: - Generation and public key structure
    @Test("Generate P-256 and validate structure")
    func testP256Basics() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "p256@example.com") as! ECDSAKey
        try assertECDSABasics(
            key,
            expectedType: .ecdsa256,
            expectedCurve: "nistp256",
            expectedPointLength: 65,  // 0x04 || X(32) || Y(32)
            expectedPrivateLength: 32,
            comment: "p256@example.com"
        )
    }

    @Test("Generate P-384 and validate structure")
    func testP384Basics() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "p384@example.com") as! ECDSAKey
        try assertECDSABasics(
            key,
            expectedType: .ecdsa384,
            expectedCurve: "nistp384",
            expectedPointLength: 97,  // 0x04 || X(48) || Y(48)
            expectedPrivateLength: 48,
            comment: "p384@example.com"
        )
    }

    @Test("Generate P-521 and validate structure")
    func testP521Basics() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "p521@example.com") as! ECDSAKey
        try assertECDSABasics(
            key,
            expectedType: .ecdsa521,
            expectedCurve: "nistp521",
            expectedPointLength: 133, // 0x04 || X(66) || Y(66)
            expectedPrivateLength: 66,
            comment: "p521@example.com"
        )
    }

    // MARK: - Fingerprints
    @Test("ECDSA fingerprints: MD5/HEX, SHA256, SHA512")
    func testFingerprints() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey

        let sha256 = key.fingerprint(hash: .sha256)
        #expect(sha256.hasPrefix("SHA256:"))

        let sha512 = key.fingerprint(hash: .sha512)
        #expect(sha512.hasPrefix("SHA512:"))

        let md5hex = key.fingerprint(hash: .md5, format: .hex)
        #expect(md5hex.contains(":"))
        #expect(md5hex.count == 47) // 16 bytes * 2 hex + 15 colons
    }

    // MARK: - Signing and verification
    @Test("Sign and verify P-256", .tags(.critical))
    func testSignVerifyP256() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let message = Data("hello world".utf8)

        let signature = try key.sign(data: message)
        #expect(signature.count > 0)

        let isValid = try key.verify(signature: signature, for: message)
        #expect(isValid)

        // Mutate signature (flip last byte in r||s blob) and expect verification to fail
        var decoder = SSHDecoder(data: signature)
        _ = try decoder.decodeString() // type
        var sigBlob = try decoder.decodeData() // r,s encoded
        #expect(sigBlob.count > 0)
        sigBlob[sigBlob.count - 1] ^= 0xFF

        var reenc = SSHEncoder()
        reenc.encodeString(key.keyType.rawValue)
        reenc.encodeData(sigBlob)
        let mutated = reenc.encode()

        let shouldBeInvalid = try key.verify(signature: mutated, for: message)
        #expect(shouldBeInvalid == false)
    }

    @Test("Sign and verify P-384")
    func testSignVerifyP384() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384) as! ECDSAKey
        let message = Data("swift-testing".utf8)

        let signature = try key.sign(data: message)
        let isValid = try key.verify(signature: signature, for: message)
        #expect(isValid)
    }

    @Test("Sign and verify P-521")
    func testSignVerifyP521() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521) as! ECDSAKey
        let message = Data("ecdsa-p521".utf8)

        let signature = try key.sign(data: message)
        let isValid = try key.verify(signature: signature, for: message)
        #expect(isValid)
    }

    // MARK: - Raw signature helpers
    @Test("Raw signature round-trip (P-256)")
    func testRawSignatureVerification() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let msg = Data("raw-sig".utf8)

        let rawSig = try key.rawSignature(for: msg) // SSH-encoded r,s
        #expect(rawSig.count > 0)

        let ok = try key.verifyRawSignature(rawSig, for: msg)
        #expect(ok)
    }

    @Test("Raw signature round-trip (P-384)")
    func testRawSignatureVerificationP384() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa384) as! ECDSAKey
        let msg = Data("raw-sig-p384".utf8)

        let rawSig = try key.rawSignature(for: msg)
        #expect(rawSig.count > 0)

        let ok = try key.verifyRawSignature(rawSig, for: msg)
        #expect(ok)
    }

    @Test("Raw signature round-trip (P-521)")
    func testRawSignatureVerificationP521() throws {
        let key = try SwiftKeyGen.generateKey(type: .ecdsa521) as! ECDSAKey
        let msg = Data("raw-sig-p521".utf8)

        let rawSig = try key.rawSignature(for: msg)
        #expect(rawSig.count > 0)

        let ok = try key.verifyRawSignature(rawSig, for: msg)
        #expect(ok)
    }

    // MARK: - Generator dispatch
    @Test("ECDSAKeyGenerator.generate dispatch and unsupported type")
    func testGeneratorDispatch() throws {
        let p256 = try ECDSAKeyGenerator.generate(curve: .ecdsa256)
        #expect(p256.keyType == .ecdsa256)

        let p384 = try ECDSAKeyGenerator.generate(curve: .ecdsa384)
        #expect(p384.keyType == .ecdsa384)

        let p521 = try ECDSAKeyGenerator.generate(curve: .ecdsa521)
        #expect(p521.keyType == .ecdsa521)

        #expect(throws: SSHKeyError.unsupportedKeyType) {
            _ = try ECDSAKeyGenerator.generate(curve: .rsa)
        }
    }
}
