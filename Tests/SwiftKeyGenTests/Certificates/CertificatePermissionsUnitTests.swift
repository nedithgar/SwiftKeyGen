import Foundation
import Testing
@testable import SwiftKeyGen

@Suite("Explicit certificate permissions", .tags(.unit))
struct CertificatePermissionsUnitTests {
    static let keyTypes: [KeyType] = [.ed25519, .rsa, .ecdsa256, .ecdsa384, .ecdsa521]
    static let defaults = [
        "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding",
        "permit-pty", "permit-user-rc"
    ]

    enum Selection: CaseIterable {
        case omitted, explicitNil, empty, ptyOnly

        var extensions: [SSHCertificateExtension]? {
            switch self {
            case .omitted, .explicitNil: nil
            case .empty: []
            case .ptyOnly: [.permitPty]
            }
        }

        func expectedNames(host: Bool = false) -> [String] {
            switch self {
            case .omitted, .explicitNil: host ? [] : CertificatePermissionsUnitTests.defaults
            case .empty: []
            case .ptyOnly: ["permit-pty"]
            }
        }
    }

    @Test("Selections survive serialization and signature verification for every key pair",
          .tags(.rsa, .slow), arguments: keyTypes, keyTypes)
    func signing(subjectType: KeyType, caType: KeyType) throws {
        let subject = try SwiftKeyGen.generateKey(type: subjectType, bits: 2048)
        let ca = try SwiftKeyGen.generateKey(type: caType, bits: 2048)
        for selection in Selection.allCases {
            for certificateType in [SSHCertificateType.user, .host] {
                let signed: CertifiedKey
                if selection == .omitted {
                    signed = try CertificateAuthority.signCertificate(
                        publicKey: subject, caKey: ca, keyId: "permissions",
                        certificateType: certificateType
                    )
                } else {
                    signed = try CertificateAuthority.signCertificate(
                        publicKey: subject, caKey: ca, keyId: "permissions",
                        certificateType: certificateType, extensions: selection.extensions
                    )
                }
                let expected = selection.expectedNames(host: certificateType == .host)
                try Self.check(signed, ca: ca, expected: expected)
            }
        }
    }

    @Test("User convenience preserves each selection and restrictions", arguments: Selection.allCases)
    func userConvenience(selection: Selection) throws {
        let subject = try SwiftKeyGen.generateKey(type: .ed25519)
        let ca = try SwiftKeyGen.generateKey(type: .ed25519)
        let signed: CertifiedKey
        if selection == .omitted {
            signed = try CertificateManager.createUserCertificate(
                publicKey: subject, caKey: ca, username: "alice",
                forceCommand: "/usr/bin/git-shell", sourceAddress: "203.0.113.0/24"
            )
        } else {
            signed = try CertificateManager.createUserCertificate(
                publicKey: subject, caKey: ca, username: "alice",
                forceCommand: "/usr/bin/git-shell", sourceAddress: "203.0.113.0/24",
                extensions: selection.extensions
            )
        }
        let parsed = try Self.check(signed, ca: ca, expected: selection.expectedNames())
        #expect(parsed.certificate.criticalOptions.map(\.0) == ["force-command", "source-address"])
        #expect(parsed.certificate.criticalOptions.map(\.1) == ["/usr/bin/git-shell", "203.0.113.0/24"])
    }

    @Test("Empty extensions do not clear independently supplied critical flags")
    func independentCriticalOptions() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519)
        let signed = try CertificateAuthority.signCertificate(
            publicKey: key, caKey: key, keyId: "restricted",
            criticalOptions: [(.forceCommand, "echo restricted"), (.sourceAddress, "192.0.2.0/24"),
                              (.verifyRequired, "")], extensions: []
        )
        let parsed = try Self.check(signed, ca: key, expected: [])
        #expect(parsed.certificate.criticalOptions.map(\.0) == ["force-command", "source-address", "verify-required"])
        #expect(parsed.certificate.criticalOptions.map(\.1) == ["echo restricted", "192.0.2.0/24", ""])
    }

    @discardableResult
    static func check(_ signed: CertifiedKey, ca: any SSHKey, expected: [String]) throws -> CertifiedKey {
        let parsed = try CertificateParser.parseCertificate(from: signed.publicKeyString())
        #expect(signed.certificate.extensions.sorted() == expected.sorted())
        #expect(parsed.certificate.extensions.sorted() == expected.sorted())
        #expect(CertificateVerifier.verifyCertificate(parsed, caKey: ca) == .valid)

        // Read the actual signed wire fields, independently of the certificate model.
        var decoder = SSHDecoder(data: try #require(signed.certificate.certBlob))
        _ = try decoder.decodeData() // nonce
        let componentCount = signed.originalKey.keyType == .ed25519 ? 1 : 2
        for _ in 0..<componentCount { _ = try decoder.decodeData() }
        _ = try decoder.decodeBytes(count: 8) // serial
        _ = try decoder.decodeUInt32() // certificate type
        _ = try decoder.decodeString() // key ID
        _ = try decoder.decodeData() // principals
        _ = try decoder.decodeBytes(count: 8) // valid after
        _ = try decoder.decodeBytes(count: 8) // valid before
        _ = try decoder.decodeData() // critical options
        if expected.isEmpty {
            #expect(try decoder.decodeUInt32() == 0, "Empty extensions must have a zero-length SSH string")
        } else {
            var extensions = SSHDecoder(data: try decoder.decodeData())
            var names: [String] = []
            while extensions.remaining > 0 {
                names.append(try extensions.decodeString())
                #expect(try extensions.decodeData().isEmpty)
            }
            #expect(names.sorted() == expected.sorted())
        }
        return parsed
    }
}
