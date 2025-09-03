import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Certificate Parser Tests", .tags(.unit))
struct CertificateParserTests {

    @Test("Parse Ed25519 certificate string round-trip")
    func testParseEd25519CertificateStringRoundTrip() throws {
        // Arrange: create a certificate with options and extensions
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let comment = "parser-roundtrip"

        let certified = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "user-id",
            principals: ["alice", "bob"],
            certificateType: .user,
            criticalOptions: [(.forceCommand, "/bin/echo")],
            extensions: [.permitPty, .permitUserRc]
        )

        // Build a .pub-like line using the same encoding the parser expects
        let publicData = try certified.publicKeyData()
        let base64 = publicData.base64EncodedString()
        let line = "\(certified.certifiedKeyType) \(base64) \(comment)"

        // Act
        let parsed = try CertificateParser.parseCertificate(from: line)

        // Assert core fields
        #expect(parsed.certificate.type == .user)
        #expect(parsed.certificate.keyId == "user-id")
        #expect(parsed.certificate.principals == ["alice", "bob"])
        #expect(parsed.certificate.validAfter == 0)
        #expect(parsed.certificate.validBefore == UInt64.max)

        // Options and extensions
        #expect(parsed.certificate.criticalOptions.count == 1)
        if parsed.certificate.criticalOptions.count == 1 {
            #expect(parsed.certificate.criticalOptions[0].0 == "force-command")
            #expect(parsed.certificate.criticalOptions[0].1 == "/bin/echo")
        }
        #expect(parsed.certificate.extensions.contains("permit-pty"))
        #expect(parsed.certificate.extensions.contains("permit-user-rc"))

        // Signature metadata
        #expect(parsed.certificate.signatureType == "ssh-ed25519")
        let parsedCA = parsed.certificate.signatureKey!
        #expect(parsedCA.publicKeyData() == caKey.publicOnlyKey().publicKeyData())

        // Underlying key and comment
        #expect(parsed.originalKey.keyType == .ed25519)
        #expect(parsed.originalKey.comment == comment)
    }

    @Test("Parse ECDSA P256 certificate")
    func testParseECDSACertificate() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey

        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "ecdsa-user",
            principals: ["user"],
            certificateType: .user
        )

        let data = try cert.publicKeyData()
        let line = "\(cert.certifiedKeyType) \(data.base64EncodedString())"
        let parsed = try CertificateParser.parseCertificate(from: line)

        #expect(parsed.originalKey.keyType == .ecdsa256)
        #expect(parsed.certificate.signatureType == "ssh-ed25519")
        #expect(parsed.certificate.signatureKey?.keyType == .ed25519)
        #expect(parsed.certificate.keyId == "ecdsa-user")
    }

    @Test("parseCertificateData detects key type mismatch")
    func testParseDataMismatchedType() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id"
        )

        let data = try cert.publicKeyData()
        #expect(throws: SSHKeyError.invalidFormat) {
            _ = try CertificateParser.parseCertificateData(
                data,
                keyType: "ssh-rsa-cert-v01@openssh.com",
                comment: nil
            )
        }
    }

    @Test("Reject non-certificate public key strings")
    func testNotACertificateString() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let pub = key.publicKeyString()
        #expect(throws: SSHKeyError.notACertificate) {
            _ = try CertificateParser.parseCertificate(from: pub)
        }
    }

    @Test("Reject invalid base64 input")
    func testInvalidBase64() throws {
        let line = "ssh-ed25519-cert-v01@openssh.com not_base64_data"
        #expect(throws: SSHKeyError.invalidBase64) {
            _ = try CertificateParser.parseCertificate(from: line)
        }
    }

    @Test("Unsupported certificate key type")
    func testUnsupportedCertificateType() throws {
        // Build minimal, syntactically valid envelope with unknown cert type
        var blob = SSHEncoder()
        blob.encodeData(Data()) // nonce
        let blobData = blob.encode()

        var top = SSHEncoder()
        let unknownType = "ssh-unknown-cert-v01@openssh.com"
        top.encodeString(unknownType)
        top.encodeData(blobData)
        let data = top.encode()

        let line = "\(unknownType) \(data.base64EncodedString())"
        #expect(throws: SSHKeyError.unsupportedKeyType) {
            _ = try CertificateParser.parseCertificate(from: line)
        }
    }

    @Test("Invalid certificate type value")
    func testInvalidCertificateTypeValue() throws {
        // Start from a valid certificate, then mutate the type field inside the blob
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let userKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let cert = try CertificateAuthority.signCertificate(
            publicKey: userKey,
            caKey: caKey,
            keyId: "id",
            principals: ["alice"]
        )

        guard let blob = cert.certificate.certBlob else {
            Issue.record("Certificate blob missing")
            return
        }

        // Decode the existing blob
        var d = SSHDecoder(data: blob)
        let nonce = try d.decodeData()
        let pub = try d.decodeData() // ed25519 public key
        let serialHigh = try d.decodeUInt32()
        let serialLow = try d.decodeUInt32()
        _ = try d.decodeUInt32() // original type
        let keyId = try d.decodeString()
        let principalsData = try d.decodeData()
        let vaHigh = try d.decodeUInt32()
        let vaLow = try d.decodeUInt32()
        let vbHigh = try d.decodeUInt32()
        let vbLow = try d.decodeUInt32()
        let crit = try d.decodeData()
        let exts = try d.decodeData()
        let reserved = try d.decodeData()
        let caKeyData = try d.decodeData()
        let sig = try d.decodeData()

        // Re-encode with invalid certificate type (e.g., 999)
        var e = SSHEncoder()
        e.encodeData(nonce)
        e.encodeData(pub)
        let serial = (UInt64(serialHigh) << 32) | UInt64(serialLow)
        e.encodeUInt64(serial)
        e.encodeUInt32(999)
        e.encodeString(keyId)
        e.encodeData(principalsData)
        let va = (UInt64(vaHigh) << 32) | UInt64(vaLow)
        let vb = (UInt64(vbHigh) << 32) | UInt64(vbLow)
        e.encodeUInt64(va)
        e.encodeUInt64(vb)
        e.encodeData(crit)
        e.encodeData(exts)
        e.encodeData(reserved)
        e.encodeData(caKeyData)
        e.encodeData(sig)
        let mutatedBlob = e.encode()

        // Wrap as public key data (type + length-prefixed blob)
        var top = SSHEncoder()
        top.encodeString(cert.certifiedKeyType)
        top.encodeData(mutatedBlob)
        let line = "\(cert.certifiedKeyType) \(top.encode().base64EncodedString())"

        #expect(throws: SSHKeyError.invalidCertificateType) {
            _ = try CertificateParser.parseCertificate(from: line)
        }
    }
}
