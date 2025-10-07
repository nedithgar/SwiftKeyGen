import Testing
import Foundation
import Crypto
@testable import SwiftKeyGen

@Suite("Ed25519 PKCS#8/SPKI + PEM", .tags(.unit))
struct Ed25519PEMUnitTests {

    @Test("PrivateKey PKCS#8 DER/PEM round-trip")
    func testPrivateKeyPKCS8RoundTrip() throws {
        // Generate a fresh Ed25519 key (CryptoKit)
        let original = Curve25519.Signing.PrivateKey()

        // DER round-trip
        let der = original.pkcs8DERRepresentation
        #expect(!der.isEmpty)
        #expect(der[0] == 0x30) // SEQUENCE tag

        let fromDER = try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: der)
        #expect(fromDER.rawRepresentation == original.rawRepresentation)
        #expect(fromDER.publicKey.rawRepresentation == original.publicKey.rawRepresentation)

        // PEM round-trip
        let pem = original.pemRepresentation
        #expect(pem.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        #expect(pem.hasSuffix("-----END PRIVATE KEY-----"))

        let fromPEM = try Curve25519.Signing.PrivateKey(pemRepresentation: pem)
        #expect(fromPEM.rawRepresentation == original.rawRepresentation)
        #expect(fromPEM.publicKey.rawRepresentation == original.publicKey.rawRepresentation)

        // Validate base64 lines are wrapped at 64 cols (when applicable)
        let lines = pem.split(separator: "\n")
        #expect(lines.first == "-----BEGIN PRIVATE KEY-----")
        #expect(lines.last == "-----END PRIVATE KEY-----")
        if lines.count > 2 {
            let b64Lines = lines[1..<(lines.count - 1)]
            // All non-final base64 lines are exactly 64 chars
            for (i, line) in b64Lines.enumerated() {
                if i < b64Lines.count - 1 { #expect(line.count == 64) }
                else { #expect(line.count <= 64) }
            }
        }

        // Sanity-check that the 32-byte seed is present in the inner OCTET STRING
        // AlgorithmIdentifier: 30 05 06 03 2B 65 70
        let algId: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]
        let bytes = [UInt8](der)
        if let algIndex = Self.findSubsequence(algId, in: bytes) {
            // Expect: 04 <len> 04 20 <32-byte-seed>
            let outerIdx = algIndex + algId.count
            #expect(bytes.count > outerIdx + 2)
            #expect(bytes[outerIdx] == 0x04) // outer OCTET STRING tag
            let innerIdx = outerIdx + 2 // length is single-byte for 34 (0x22)
            #expect(bytes[innerIdx] == 0x04)
            #expect(bytes[innerIdx + 1] == 0x20)
            let seed = Data(bytes[(innerIdx + 2)..<(innerIdx + 2 + 32)])
            #expect(seed == original.rawRepresentation)
        }
    }

    @Test("PublicKey SPKI DER/PEM round-trip")
    func testPublicKeySPKIRoundTrip() throws {
        let priv = Curve25519.Signing.PrivateKey()
        let original = priv.publicKey

        // DER round-trip
        let der = original.spkiDERRepresentation
        #expect(!der.isEmpty)
        #expect(der[0] == 0x30) // SEQUENCE tag

        let fromDER = try Curve25519.Signing.PublicKey(spkiDERRepresentation: der)
        #expect(fromDER.rawRepresentation == original.rawRepresentation)

        // PEM round-trip
        let pem = original.pemRepresentation
        #expect(pem.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        #expect(pem.hasSuffix("-----END PUBLIC KEY-----"))

        let fromPEM = try Curve25519.Signing.PublicKey(pemRepresentation: pem)
        #expect(fromPEM.rawRepresentation == original.rawRepresentation)

        // BIT STRING structure: 03 21 00 <32-byte key>
        let algId: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]
        let bytes = [UInt8](der)
        if let algIndex = Self.findSubsequence(algId, in: bytes) {
            let bitStringIdx = algIndex + algId.count
            #expect(bytes.count > bitStringIdx + 3)
            #expect(bytes[bitStringIdx] == 0x03) // BIT STRING tag
            #expect(bytes[bitStringIdx + 1] == 0x21)
            #expect(bytes[bitStringIdx + 2] == 0x00) // 0 unused bits
            let key = Data(bytes[(bitStringIdx + 3)..<(bitStringIdx + 3 + 32)])
            #expect(key == original.rawRepresentation)
        }
    }

    @Test("Reject too-short DER payloads")
    func testRejectShortDER() {
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: Data(repeating: 0, count: 10))
        }
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PublicKey(spkiDERRepresentation: Data(repeating: 0, count: 10))
        }
    }

    @Test("Reject wrong algorithm identifier")
    func testRejectWrongAlgorithmIdentifier() throws {
        // Start from valid encodings then corrupt the OID
        let priv = Curve25519.Signing.PrivateKey()
        var pkcs8 = priv.pkcs8DERRepresentation
        var spki = priv.publicKey.spkiDERRepresentation

        // Find and corrupt the Ed25519 AlgorithmIdentifier (last OID byte 0x70)
        let algId: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]
        if let idx = Self.findSubsequence(algId, in: [UInt8](pkcs8)) {
            pkcs8[idx + algId.count - 1] ^= 0x01 // 0x70 -> 0x71
        }
        if let idx = Self.findSubsequence(algId, in: [UInt8](spki)) {
            spki[idx + algId.count - 1] ^= 0x01
        }

        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: pkcs8)
        }
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PublicKey(spkiDERRepresentation: spki)
        }
    }

    @Test("Reject malformed inner tags")
    func testRejectMalformedInnerTags() throws {
        let priv = Curve25519.Signing.PrivateKey()
        var pkcs8 = priv.pkcs8DERRepresentation
        var spki = priv.publicKey.spkiDERRepresentation

        // Locate AlgorithmIdentifier then flip the next tag
        let algId: [UInt8] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]

        // For PKCS#8: expect OCTET STRING after AlgorithmIdentifier
        if let algIndex = Self.findSubsequence(algId, in: [UInt8](pkcs8)) {
            let outerOctetIndex = algIndex + algId.count
            if outerOctetIndex < pkcs8.count { pkcs8[outerOctetIndex] = 0x05 /* NULL */ }
        }
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: pkcs8)
        }

        // For SPKI: expect BIT STRING after AlgorithmIdentifier
        if let algIndex = Self.findSubsequence(algId, in: [UInt8](spki)) {
            let bitStringIndex = algIndex + algId.count
            if bitStringIndex < spki.count { spki[bitStringIndex] = 0x04 /* OCTET STRING */ }
        }
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PublicKey(spkiDERRepresentation: spki)
        }
    }

    @Test("PEM initializer rejects invalid base64 body")
    func testPEMRejectsInvalidBase64() {
        let badPrivatePEM = """
        -----BEGIN PRIVATE KEY-----
        !!!!! not-base64 !!!!!
        -----END PRIVATE KEY-----
        """
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PrivateKey(pemRepresentation: badPrivatePEM)
        }

        let badPublicPEM = """
        -----BEGIN PUBLIC KEY-----
        @@@@
        -----END PUBLIC KEY-----
        """
        #expect(throws: Error.self) {
            _ = try Curve25519.Signing.PublicKey(pemRepresentation: badPublicPEM)
        }
    }

    // MARK: - Helpers
    private static func findSubsequence(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        let n = haystack.count - needle.count
        var i = 0
        while i <= n {
            if haystack[i] == needle[0] {
                var j = 1
                while j < needle.count, haystack[i + j] == needle[j] { j += 1 }
                if j == needle.count { return i }
            }
            i += 1
        }
        return nil
    }
}

