import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("OpenSSHPrivateKey Unit Tests", .tags(.unit))
struct OpenSSHPrivateKeyUnitTests {

    // Helper: extract base64 payload from PEM string
    private func base64Payload(from pem: String) -> Data {
        let lines = pem.split(separator: "\n")
        var capturing = false
        var b64 = ""
        for line in lines {
            if line.contains("-----BEGIN OPENSSH PRIVATE KEY-----") { capturing = true; continue }
            if line.contains("-----END OPENSSH PRIVATE KEY-----") { break }
            if capturing { b64 += String(line) }
        }
        return Data(base64Encoded: b64)!
    }

    // Helper: AUTH_MAGIC used by OpenSSHPrivateKey
    private let authMagic = "openssh-key-v1\u{0}"

    @Test("serialize (none) writes header, kdf and public block correctly")
    func testSerializeUnencryptedHeaderAndFields() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "unit@test")
        let serialized = try OpenSSHPrivateKey.serialize(key: key)
        let pem = String(data: serialized, encoding: .utf8)!

        // Extract and decode payload
        let payload = base64Payload(from: pem)

        // Verify magic header
        #expect(payload.prefix(authMagic.utf8.count) == Data(authMagic.utf8))

        // Decode the rest of the structure
        var dec = SSHDecoder(data: payload.suffix(from: authMagic.utf8.count))
        let cipherName = try dec.decodeString()
        let kdfName = try dec.decodeString()
        let kdfData = try dec.decodeData()
        let numKeys = try dec.decodeUInt32()
        let pub = try dec.decodeData()
        let encLen = try dec.decodeUInt32()

        #expect(cipherName == "none")
        #expect(kdfName == "none")
        #expect(kdfData.isEmpty)
        #expect(numKeys == 1)
        #expect(pub == key.publicKeyData())
        // For unauthenticated ciphers, remaining should equal written length
        #expect(dec.remaining == Int(encLen))
    }

    @Test("serialize (bcrypt) encodes KDF salt and rounds")
    func testSerializeEncryptedKDFParameters() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "kdf@test")
        let rounds = 8
        let serialized = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: "pw",
            comment: key.comment,
            rounds: rounds
        )
        let pem = String(data: serialized, encoding: .utf8)!
        let payload = base64Payload(from: pem)

        var dec = SSHDecoder(data: payload.suffix(from: authMagic.utf8.count))
        let cipherName = try dec.decodeString()
        let kdfName = try dec.decodeString()
        let kdfData = try dec.decodeData()
        _ = try dec.decodeUInt32() // numKeys
        _ = try dec.decodeData()   // publicKeyData
        let encLen = try dec.decodeUInt32()

        #expect(cipherName == Cipher.defaultCipher)
        #expect(kdfName == "bcrypt")

        // Inspect KDF params: salt (16 bytes) + rounds (UInt32)
        var kdfDec = SSHDecoder(data: kdfData)
        let salt = try kdfDec.decodeData()
        let parsedRounds = try kdfDec.decodeUInt32()
        #expect(salt.count == 16)
        #expect(parsedRounds == UInt32(rounds))

        // CTR/GCM lengths: for CTR the encrypted length equals remaining bytes
        let info = Cipher.cipherByName(cipherName)!
        if info.authLen == 0 {
            #expect(dec.remaining == Int(encLen))
        }
    }

    @Test("AEAD ciphers write length excluding tag")
    func testAEADCipherLengthAccounting() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "aead@test")
        let cipher = "aes256-gcm@openssh.com"
        let serialized = try OpenSSHPrivateKey.serialize(
            key: key,
            passphrase: "secret",
            comment: key.comment,
            cipher: cipher,
            rounds: 6
        )
        let pem = String(data: serialized, encoding: .utf8)!
        let payload = base64Payload(from: pem)

        var dec = SSHDecoder(data: payload.suffix(from: authMagic.utf8.count))
        let cipherName = try dec.decodeString()
        _ = try dec.decodeString() // kdfName
        _ = try dec.decodeData()   // kdfData
        _ = try dec.decodeUInt32() // numKeys
        _ = try dec.decodeData()   // publicKeyData
        let encLen = try dec.decodeUInt32()

        #expect(cipherName == cipher)
        let authLen = Cipher.cipherByName(cipherName)!.authLen
        // Remaining should be ciphertext length + tag
        #expect(dec.remaining == Int(encLen) + authLen)
    }

    @Test("parse with wrong passphrase -> invalidPassphrase")
    func testParseWrongPassphrase() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "wrongpass@test")
        let serialized = try OpenSSHPrivateKey.serialize(key: key, passphrase: "correct", rounds: 6)
        #expect(throws: SSHKeyError.invalidPassphrase) {
            _ = try OpenSSHPrivateKey.parse(data: serialized, passphrase: "incorrect")
        }
    }

    @Test("parse invalid PEM -> invalidFormat")
    func testParseInvalidPEMMarkers() throws {
        let bogus = Data("not a key".utf8)
        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try OpenSSHPrivateKey.parse(data: bogus)
        }
    }

    @Test("parse invalid magic header -> invalidFormat")
    func testParseInvalidMagicHeader() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "magic@test")
        let serialized = try OpenSSHPrivateKey.serialize(key: key)
        let pem = String(data: serialized, encoding: .utf8)!
        var payload = base64Payload(from: pem)

        // Corrupt the first byte of magic header
        if !payload.isEmpty { payload[0] ^= 0xFF }

        // Re-wrap into PEM
        let b64 = payload.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        let wrapped = [
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            b64,
            "-----END OPENSSH PRIVATE KEY-----",
            ""
        ].joined(separator: "\n")

        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try OpenSSHPrivateKey.parse(data: Data(wrapped.utf8))
        }
    }

    @Test("parse unsupported cipher -> unsupportedCipher")
    func testParseUnsupportedCipher() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "unsupported@test")
        let pub = key.publicKeyData()

        // Build minimal valid envelope with unknown cipher name
        var enc = SSHEncoder()
        enc.data.append(Data(authMagic.utf8))
        enc.encodeString("unknown-cipher")
        enc.encodeString("none")
        enc.encodeData(Data()) // kdf
        enc.encodeUInt32(1)    // num keys
        enc.encodeData(pub)    // public key block
        enc.encodeUInt32(0)    // encrypted length (0)

        let b64 = enc.encode().base64EncodedData(options: [.lineLength64Characters, .endLineWithLineFeed])
        var pem = Data()
        pem.append(Data("-----BEGIN OPENSSH PRIVATE KEY-----\n".utf8))
        pem.append(b64); pem.append(Data("\n".utf8))
        pem.append(Data("-----END OPENSSH PRIVATE KEY-----\n".utf8))

        #expect(throws: SSHKeyError.unsupportedCipher("unknown-cipher")) {
            _ = try OpenSSHPrivateKey.parse(data: pem)
        }
    }

    @Test("padding mismatch yields invalidFormat")
    func testPaddingMismatch() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "pad@test")

        // Prepare private block with wrong padding byte at the end
        var pubDec = SSHDecoder(data: key.publicKeyData())
        _ = try pubDec.decodeString() // skip type
        let rawPub = try pubDec.decodeData()

        var priv = SSHEncoder()
        let check: UInt32 = 0xAABBCCDD
        priv.encodeUInt32(check)
        priv.encodeUInt32(check)
        priv.encodeString("ssh-ed25519")
        priv.encodeData(rawPub)
        var full = Data()
        full.append(key.privateKeyData())
        full.append(rawPub)
        priv.encodeData(full)
        priv.encodeString("pad@test")
        // Add a single wrong padding byte (should be 0x01)
        var privData = priv.encode()
        privData.append(0x02)

        // Build full envelope with cipher "none"
        var enc = SSHEncoder()
        enc.data.append(Data(authMagic.utf8))
        enc.encodeString("none")
        enc.encodeString("none")
        enc.encodeData(Data())
        enc.encodeUInt32(1)
        enc.encodeData(key.publicKeyData())
        enc.encodeUInt32(UInt32(privData.count))
        var payload = enc.encode()
        payload.append(privData)

        let b64 = payload.base64EncodedData(options: [.lineLength64Characters, .endLineWithLineFeed])
        var pem = Data()
        pem.append(Data("-----BEGIN OPENSSH PRIVATE KEY-----\n".utf8))
        pem.append(b64); pem.append(Data("\n".utf8))
        pem.append(Data("-----END OPENSSH PRIVATE KEY-----\n".utf8))

        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try OpenSSHPrivateKey.parse(data: pem)
        }
    }

    @Test("unsupported key type yields unsupportedKeyType")
    func testUnsupportedKeyType() throws {
        let key = try Ed25519KeyGenerator.generate(comment: "type@test")

        var priv = SSHEncoder()
        let check: UInt32 = 0x01020304
        priv.encodeUInt32(check)
        priv.encodeUInt32(check)
        priv.encodeString("ssh-unknown")
        // no further fields needed; parse should fail at type dispatch
        let privData = priv.encode()

        var enc = SSHEncoder()
        enc.data.append(Data(authMagic.utf8))
        enc.encodeString("none")
        enc.encodeString("none")
        enc.encodeData(Data())
        enc.encodeUInt32(1)
        enc.encodeData(key.publicKeyData())
        enc.encodeUInt32(UInt32(privData.count))
        var payload = enc.encode()
        payload.append(privData)

        let b64 = payload.base64EncodedData(options: [.lineLength64Characters, .endLineWithLineFeed])
        var pem = Data()
        pem.append(Data("-----BEGIN OPENSSH PRIVATE KEY-----\n".utf8))
        pem.append(b64); pem.append(Data("\n".utf8))
        pem.append(Data("-----END OPENSSH PRIVATE KEY-----\n".utf8))

        #expect(throws: SSHKeyError.unsupportedKeyType) {
            _ = try OpenSSHPrivateKey.parse(data: pem)
        }
    }
}

