import Foundation
import Testing
@testable import SwiftKeyGen

@Suite("Certificate permission interoperability", .tags(.integration))
struct CertificatePermissionsIntegrationTests {
    @Test("OpenSSH default, clear and PTY-only fixtures preserve exact semantics",
          arguments: CertificatePermissionsUnitTests.Selection.allCases, [false, true])
    func openSSH(selection: CertificatePermissionsUnitTests.Selection, restricted: Bool) throws {
        try IntegrationTestSupporter.withTemporaryDirectory { directory in
            let ca = try SwiftKeyGen.generateKey(type: .ed25519)
            let subject = try SwiftKeyGen.generateKey(type: .ed25519)
            let caPath = directory.appendingPathComponent("ca")
            let subjectPath = directory.appendingPathComponent("subject.pub")
            try IntegrationTestSupporter.write(try OpenSSHPrivateKey.serialize(key: ca), to: caPath)
            try IntegrationTestSupporter.write(subject.publicKeyString(), to: subjectPath)

            var arguments = ["-q", "-s", caPath.path, "-I", "permissions", "-n", "alice"]
            switch selection {
            case .omitted, .explicitNil: break
            case .empty: arguments += ["-O", "clear"]
            case .ptyOnly: arguments += ["-O", "clear", "-O", "permit-pty"]
            }
            let restrictions: [(SSHCertificateOption, String)] = restricted
                ? [(.forceCommand, "/usr/bin/git-shell"), (.sourceAddress, "203.0.113.0/24")] : []
            for (option, value) in restrictions {
                arguments += ["-O", "\(option.rawValue)=\(value)"]
            }
            arguments.append(subjectPath.path)
            let result = try IntegrationTestSupporter.runSSHKeygen(arguments)
            try #require(result.succeeded, "ssh-keygen signing failed: \(result.stderr)")
            let fixture = try CertificateManager.readCertificate(
                from: directory.appendingPathComponent("subject-cert.pub").path
            )
            let signed: CertifiedKey
            if selection == .omitted {
                signed = try CertificateAuthority.signCertificate(
                    publicKey: subject, caKey: ca, keyId: "permissions", principals: ["alice"],
                    criticalOptions: restrictions
                )
            } else {
                signed = try CertificateAuthority.signCertificate(
                    publicKey: subject, caKey: ca, keyId: "permissions", principals: ["alice"],
                    criticalOptions: restrictions, extensions: selection.extensions
                )
            }
            let parsed = try CertificatePermissionsUnitTests.check(
                signed, ca: ca, expected: selection.expectedNames()
            )
            #expect(fixture.certificate.extensions.sorted() == selection.expectedNames().sorted())
            #expect(fixture.certificate.extensions.sorted() == parsed.certificate.extensions.sorted())
            #expect(fixture.certificate.criticalOptions.map(\.0) == restrictions.map { $0.0.rawValue })
            #expect(fixture.certificate.criticalOptions.map(\.1) == restrictions.map(\.1))
            #expect(parsed.certificate.criticalOptions.map(\.0) == fixture.certificate.criticalOptions.map(\.0))
            #expect(parsed.certificate.criticalOptions.map(\.1) == fixture.certificate.criticalOptions.map(\.1))
            #expect(CertificateVerifier.verifyCertificate(fixture, caKey: ca) == .valid)

            let generatedPath = directory.appendingPathComponent("generated-cert.pub")
            try IntegrationTestSupporter.write(signed.publicKeyString(), to: generatedPath)
            let listing = try IntegrationTestSupporter.runSSHKeygen(["-L", "-f", generatedPath.path])
            #expect(listing.succeeded, "OpenSSH must read the generated certificate: \(listing.stderr)")
        }
    }

    @Test("Host generation convenience retains its default empty extension set")
    func hostConvenience() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { directory in
            let ca = try SwiftKeyGen.generateKey(type: .ed25519)
            let caPath = directory.appendingPathComponent("ca")
            try IntegrationTestSupporter.write(try OpenSSHPrivateKey.serialize(key: ca), to: caPath)
            let generated = try CertificateManager.generateCertificatesForHosts(
                hosts: ["host.example.com"], caKeyPath: caPath.path, outputDirectory: directory.path
            )
            let result = try #require(generated.first)
            let certificate = try CertificateManager.readCertificate(from: result.certificatePath)
            #expect(certificate.certificate.type == .host)
            #expect(certificate.certificate.extensions == [])
            #expect(certificate.certificate.criticalOptions.isEmpty)
            #expect(CertificateVerifier.verifyCertificate(certificate, caKey: ca) == .valid)
        }
    }

    @Test("Temporary directories are removed after success and thrown failures")
    func temporaryDirectoryCleanup() throws {
        let success = try IntegrationTestSupporter.withTemporaryDirectory { directory in
            try IntegrationTestSupporter.write("test", to: directory.appendingPathComponent("key"))
        }
        #expect(!FileManager.default.fileExists(atPath: success.path))
        enum ExpectedFailure: Error { case test }
        var failureDirectory: URL?
        #expect(throws: ExpectedFailure.test) {
            try IntegrationTestSupporter.withTemporaryDirectory { directory in
                failureDirectory = directory
                try IntegrationTestSupporter.write("test", to: directory.appendingPathComponent("key"))
                throw ExpectedFailure.test
            }
        }
        let failure = try #require(failureDirectory)
        #expect(!FileManager.default.fileExists(atPath: failure.path))
    }
}
