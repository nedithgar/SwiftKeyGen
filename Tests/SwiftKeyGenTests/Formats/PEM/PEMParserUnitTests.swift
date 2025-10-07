import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("PEMParser utilities", .tags(.unit))
struct PEMParserUnitTests {

    @Test("Detect PEM format by BEGIN/END markers")
    func testIsPEMFormat() {
        let pem = """
        -----BEGIN FOO-----
        YWJj
        -----END FOO-----
        """
        #expect(PEMParser.isPEMFormat(pem))
        #expect(!PEMParser.isPEMFormat("not a pem"))
    }

    @Test("Extract PEM type from BEGIN line")
    func testDetectPEMType() {
        let rsa = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
        let spki = "  -----BEGIN PUBLIC KEY-----  \n...\n-----END PUBLIC KEY-----"
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n...\n-----END ENCRYPTED PRIVATE KEY-----"

        #expect(PEMParser.detectPEMType(rsa) == "RSA PRIVATE KEY")
        #expect(PEMParser.detectPEMType(spki) == "PUBLIC KEY")
        #expect(PEMParser.detectPEMType(enc) == "ENCRYPTED PRIVATE KEY")
        #expect(PEMParser.detectPEMType("no markers") == nil)
    }

    @Test("Decode base64 payload and return declared type")
    func testParsePEMDecodesPayload() throws {
        // base64: "YWJj" -> "abc"
        let pem = """
        -----BEGIN FOO-----
        YWJj
        -----END FOO-----
        """
        let (type, data) = try PEMParser.parsePEM(pem)
        #expect(type == "FOO")
        #expect(String(data: data, encoding: .utf8) == "abc")
    }

    @Test("Skip OpenSSL encryption headers (Proc-Type/DEK-Info)")
    func testParsePEMSkipsEncryptionHeaders() throws {
        // Base64 payload is 0x01,0x02,0x03 (AQID)
        let pem = """
        -----BEGIN EC PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-CBC,0011223344556677AABBCCDDEEFF0011

        AQID
        -----END EC PRIVATE KEY-----
        """
        let result = try PEMParser.parsePEM(pem)
        #expect(result.type == "EC PRIVATE KEY")
        #expect(result.data == Data([0x01, 0x02, 0x03]))
    }

    @Test("Invalid base64 body throws invalidBase64")
    func testParsePEMInvalidBase64() {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        !!!! invalid base64 !!!!
        -----END PUBLIC KEY-----
        """
        #expect(throws: SSHKeyError.invalidBase64) {
            _ = try PEMParser.parsePEM(pem)
        }
    }

    @Test("Private key detection from type")
    func testIsPrivateKeyDetection() {
        let pub = "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"
        let ec = "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----"
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----"

        #expect(!PEMParser.isPrivateKey(pub))
        #expect(PEMParser.isPrivateKey(ec))
        #expect(PEMParser.isPrivateKey(enc))
    }

    @Test("Detect key algorithm from PEM type")
    func testDetectKeyAlgorithm() {
        let rsa = "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----"
        let ec = "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----"
        let spki = "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----"
        let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----"

        #expect(PEMParser.detectKeyAlgorithm(rsa) == "RSA")
        #expect(PEMParser.detectKeyAlgorithm(ec) == "ECDSA")
        #expect(PEMParser.detectKeyAlgorithm(spki) == nil)
        #expect(PEMParser.detectKeyAlgorithm(enc) == nil)
    }

    @Test("Only the first PEM block is parsed")
    func testParseStopsAtFirstEnd() throws {
        let pem = """
        -----BEGIN FOO-----
        YWJj
        -----END FOO-----
        -----BEGIN BAR-----
        ZGVm
        -----END BAR-----
        """
        let (type, data) = try PEMParser.parsePEM(pem)
        #expect(type == "FOO")
        #expect(String(data: data, encoding: .utf8) == "abc")
    }
}

