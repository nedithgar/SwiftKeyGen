import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Ed25519Key Unit Tests", .tags(.unit))
struct Ed25519KeyUnitTests {

    @Test("Sign and verify SSH-formatted signature")
    func testSignVerifySSHFormatted() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "unit@test") as! Ed25519Key
        let message = Data("ed25519-ssh".utf8)

        // Sign (SSH-formatted)
        let sig = try key.sign(data: message)
        #expect(sig.count > 0)

        // Verify succeeds
        let ok = try key.verify(signature: sig, for: message)
        #expect(ok)

        // Mutate signature payload, expect failure
        var dec = SSHDecoder(data: sig)
        let sigType = try dec.decodeString()
        #expect(sigType == KeyType.ed25519.rawValue)
        var sigBlob = try dec.decodeData()
        #expect(sigBlob.count == 64)
        sigBlob[sigBlob.count - 1] ^= 0xFF

        var enc = SSHEncoder()
        enc.encodeString(KeyType.ed25519.rawValue)
        enc.encodeData(sigBlob)
        let mutated = enc.encode()

        let bad = try key.verify(signature: mutated, for: message)
        #expect(bad == false)
    }

    @Test("Verify accepts raw and SSH-formatted signatures")
    func testVerifyAcceptsRawAndSSH() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let message = Data("raw-and-ssh".utf8)

        // Raw signature via CryptoKit
        let raw = try key.privateKey.signature(for: message)
        #expect(raw.count == 64)

        // Ed25519Key.verify should accept raw
        let okRaw = try key.verify(signature: Data(raw), for: message)
        #expect(okRaw)

        // SSH-formatted signature via Ed25519Key.sign
        let ssh = try key.sign(data: message)
        let okSSH = try key.verify(signature: ssh, for: message)
        #expect(okSSH)
    }

    @Test("Public-only key verifies raw signature, rejects SSH blob")
    func testPublicOnlyKeyVerification() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let pub = key.publicOnlyKey() as! Ed25519PublicKey
        let message = Data("public-only".utf8)

        let raw = try key.privateKey.signature(for: message)
        #expect(try pub.verify(signature: Data(raw), for: message))

        let ssh = try key.sign(data: message)
        #expect(throws: SSHKeyError.invalidSignature) {
            _ = try pub.verify(signature: ssh, for: message)
        }
    }

    @Test("Mismatched SSH signature type is rejected")
    func testVerifyRejectsMismatchedSSHTag() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let message = Data("mismatch".utf8)

        // Produce a valid raw signature
        let raw = try key.privateKey.signature(for: message)

        // Wrap it with a wrong SSH signature type
        var enc = SSHEncoder()
        enc.encodeString("ssh-rsa")
        enc.encodeData(Data(raw))
        let wrongTagged = enc.encode()

        // Ed25519Key should not accept this (falls back to raw -> invalid length)
        let ok = try key.verify(signature: wrongTagged, for: message)
        #expect(ok == false)
    }

    @Test("Init from privateKeyData round-trip")
    func testInitFromRawSeed() throws {
        let original = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let seed = original.privateKeyData()
        #expect(seed.count == 32)

        let copy = try Ed25519Key(privateKeyData: seed, comment: "copy")
        #expect(copy.comment == "copy")

        // Public keys match
        #expect(original.publicKeyData() == copy.publicKeyData())

        // Cross-verify signatures
        let msg = Data("seed-roundtrip".utf8)
        let sshSig = try copy.sign(data: msg)
        #expect(try original.verify(signature: sshSig, for: msg))
    }
}

