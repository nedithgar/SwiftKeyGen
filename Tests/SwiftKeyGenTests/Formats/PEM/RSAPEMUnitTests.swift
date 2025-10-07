import Testing
import Foundation
import Crypto
import BigInt
@testable import SwiftKeyGen

@Suite("RSA PKCS#1 + PEM", .tags(.unit, .rsa))
struct RSAPEMUnitTests {

    @Test("Unencrypted PKCS#1 PEM round-trip", .tags(.slow))
    func testUnencryptedRSAPKCS1PEMRoundTrip() throws {
        // Generate a small RSA key to keep tests fast
        let original = try RSAKeyGenerator.generate(bits: 1024)

        // Export to PKCS#1 PEM and parse back via RSA+PEM.swift
        let pem = try original.privateKey.pkcs1PEMRepresentation()
        let parsed = try PEMParser.parseRSAPrivateKey(pem)

        // Public material and CRT components must match
        #expect(parsed.publicKeyData() == original.publicKeyData())
        #expect(parsed.privateKey.n == original.privateKey.n)
        #expect(parsed.privateKey.e == original.privateKey.e)
        #expect(parsed.privateKey.d == original.privateKey.d)
        #expect(parsed.privateKey.p == original.privateKey.p)
        #expect(parsed.privateKey.q == original.privateKey.q)
        #expect(parsed.privateKey.dP == original.privateKey.dP)
        #expect(parsed.privateKey.dQ == original.privateKey.dQ)
        #expect(parsed.privateKey.qInv == original.privateKey.qInv)

        // DER encodings should also match exactly
        let parsedDER = try parsed.privateKey.pkcs1DERRepresentation()
        let originalDER = try original.privateKey.pkcs1DERRepresentation()
        #expect(parsedDER == originalDER)
    }

    @Test("Encrypted PKCS#1 PEM (AES-256-CBC)")
    func testEncryptedRSAPKCS1PEM_AES256CBC() throws {
        let key = try RSAKeyGenerator.generate(bits: 1024)
        let der = try key.privateKey.pkcs1DERRepresentation()
        let pass = "correct horse battery staple"

        // Encrypt DER using OpenSSL-compatible PEMEncryption
        let (ciphertext, iv) = try PEMEncryption.encrypt(
            data: der,
            passphrase: pass,
            cipher: .aes256CBC
        )

        // Format as traditional OpenSSL PEM (Proc-Type/DEK-Info headers)
        let pem = PEMEncryption.formatEncryptedPEM(
            type: "RSA PRIVATE KEY",
            encryptedData: ciphertext,
            cipher: .aes256CBC,
            salt: iv
        )

        // Parse with the correct passphrase
        let parsed = try PEMParser.parseRSAPrivateKey(pem, passphrase: pass)

        // Check public portion and CRT components
        #expect(parsed.publicKeyData() == key.publicKeyData())
        #expect(parsed.privateKey.n == key.privateKey.n)
        #expect(parsed.privateKey.e == key.privateKey.e)
        #expect(parsed.privateKey.d == key.privateKey.d)
        #expect(parsed.privateKey.p == key.privateKey.p)
        #expect(parsed.privateKey.q == key.privateKey.q)
        #expect(parsed.privateKey.dP == key.privateKey.dP)
        #expect(parsed.privateKey.dQ == key.privateKey.dQ)
        #expect(parsed.privateKey.qInv == key.privateKey.qInv)
    }

    @Test("Encrypted PKCS#1 PEM (3DES) wrong passphrase rejects")
    func testEncryptedRSAPKCS1PEM_3DES_WrongPassphrase() throws {
        let key = try RSAKeyGenerator.generate(bits: 1024)
        let der = try key.privateKey.pkcs1DERRepresentation()
        let pass = "p@ssw0rd"

        let (ciphertext, iv) = try PEMEncryption.encrypt(
            data: der,
            passphrase: pass,
            cipher: .des3CBC
        )

        let pem = PEMEncryption.formatEncryptedPEM(
            type: "RSA PRIVATE KEY",
            encryptedData: ciphertext,
            cipher: .des3CBC,
            salt: iv
        )

        // Wrong passphrase should throw
        #expect(throws: Error.self) {
            _ = try PEMParser.parseRSAPrivateKey(pem, passphrase: "wrong")
        }
    }

    @Test("Encrypted PEM without passphrase requires one")
    func testEncryptedPEMRequiresPassphrase() throws {
        // Minimal encrypted-looking PEM with headers and some base64
        let pem = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF

        AQID
        -----END RSA PRIVATE KEY-----
        """

        #expect(throws: SSHKeyError.passphraseRequired) {
            _ = try PEMParser.parseRSAPrivateKey(pem)
        }
    }

    @Test("Reject unsupported DEK-Info cipher")
    func testRejectUnsupportedCipherInPEM() {
        let pem = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: BLOWFISH-CBC,0011223344556677

        AQID
        -----END RSA PRIVATE KEY-----
        """

        #expect(throws: SSHKeyError.unsupportedCipher("BLOWFISH-CBC")) {
            _ = try PEMParser.parseRSAPrivateKey(pem, passphrase: "test")
        }
    }

    @Test("Reject invalid base64/DER body for RSA PRIVATE KEY")
    func testRejectInvalidDERBody() {
        // Base64 for a single 0x00 byte – not a valid SEQUENCE
        let pem = """
        -----BEGIN RSA PRIVATE KEY-----
        AA==
        -----END RSA PRIVATE KEY-----
        """
        #expect(throws: Error.self) {
            _ = try PEMParser.parseRSAPrivateKey(pem)
        }
    }
}
