import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("SSH Certificate Unit Tests", .tags(.unit))
struct SSHCertificateUnitTests {

    @Test("Validity formatting scenarios")
    func testValidityFormattingScenarios() throws {
        // forever case (defaults)
    let foreverCert = SSHCertificate(type: .user)
    #expect(foreverCert.formatValidity() == "forever")

        // from <date> to forever
        var fromCert = SSHCertificate(type: .user)
        let fromDate = Date(timeIntervalSince1970: 1_700_000_000) // Fixed timestamp for deterministic output
        fromCert.validAfter = UInt64(fromDate.timeIntervalSince1970)
        let expectedFrom: String = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            f.timeZone = TimeZone(secondsFromGMT: 0)
            return "from \(f.string(from: fromDate)) to forever"
        }()
        #expect(fromCert.formatValidity() == expectedFrom)

        // from always to <date>
        var toCert = SSHCertificate(type: .user)
        let toDate = Date(timeIntervalSince1970: 1_800_000_000)
        toCert.validBefore = UInt64(toDate.timeIntervalSince1970)
        let expectedTo: String = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            f.timeZone = TimeZone(secondsFromGMT: 0)
            return "from always to \(f.string(from: toDate))"
        }()
        #expect(toCert.formatValidity() == expectedTo)

        // from <date1> to <date2>
        var rangeCert = SSHCertificate(type: .user)
        let start = Date(timeIntervalSince1970: 1_750_000_000)
        let end = Date(timeIntervalSince1970: 1_750_360_000)
        rangeCert.validAfter = UInt64(start.timeIntervalSince1970)
        rangeCert.validBefore = UInt64(end.timeIntervalSince1970)
        let expectedRange: String = {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            f.timeZone = TimeZone(secondsFromGMT: 0)
            return "from \(f.string(from: start)) to \(f.string(from: end))"
        }()
        #expect(rangeCert.formatValidity() == expectedRange)
    }

    @Test("isValid boundary conditions")
    func testIsValidBoundaries() throws {
        // Only validFrom set
        var fromCert = SSHCertificate(type: .user)
        let now = Date()
        fromCert.validAfter = UInt64(now.timeIntervalSince1970)
        #expect(!fromCert.isValid(at: now.addingTimeInterval(-1)))
        #expect(fromCert.isValid(at: now))
        #expect(fromCert.isValid(at: now.addingTimeInterval(10)))

        // Only validBefore set
        var toCert = SSHCertificate(type: .user)
        let future = now.addingTimeInterval(60)
        toCert.validBefore = UInt64(future.timeIntervalSince1970)
        #expect(toCert.isValid(at: now))
        #expect(toCert.isValid(at: future)) // inclusive
        #expect(!toCert.isValid(at: future.addingTimeInterval(1)))

        // Both set
        var rangeCert = SSHCertificate(type: .user)
        let start = now.addingTimeInterval(-30)
        let end = now.addingTimeInterval(30)
        rangeCert.validAfter = UInt64(start.timeIntervalSince1970)
        rangeCert.validBefore = UInt64(end.timeIntervalSince1970)
        #expect(!rangeCert.isValid(at: start.addingTimeInterval(-1)))
        #expect(rangeCert.isValid(at: start))
        #expect(rangeCert.isValid(at: end))
        #expect(!rangeCert.isValid(at: end.addingTimeInterval(1)))
    }

    @Test("Critical options wire encoding")
    func testCriticalOptionsEncoding() throws {
        var cert = SSHCertificate(type: .user)
        cert.addCriticalOption(.forceCommand, value: "/bin/true")
        cert.addCriticalOption(.sourceAddress, value: "10.0.0.0/8")

        let data = cert.encodeCriticalOptions()
        var d = SSHDecoder(data: data)
        var decoded: [(String, String)] = []
        while d.hasMoreData {
            let name = try d.decodeString()
            let valueBlob = try d.decodeData()
            var inner = SSHDecoder(data: valueBlob)
            let value = try inner.decodeString()
            decoded.append((name, value))
        }
        #expect(decoded.count == 2)
        #expect(decoded[0].0 == "force-command")
        #expect(decoded[0].1 == "/bin/true")
        #expect(decoded[1].0 == "source-address")
        #expect(decoded[1].1 == "10.0.0.0/8")
    }

    @Test("Extensions wire encoding")
    func testExtensionsEncoding() throws {
        var cert = SSHCertificate(type: .user)
        cert.addExtension(.permitPty)
        cert.addExtension(.permitUserRc)
        cert.addExtension(.noTouchRequired)

        let data = cert.encodeExtensions()
        var d = SSHDecoder(data: data)
        var names: [String] = []
        while d.hasMoreData {
            let name = try d.decodeString()
            let valueBlob = try d.decodeData()
            #expect(valueBlob.count == 0) // Boolean style (empty)
            names.append(name)
        }
        #expect(names == ["permit-pty", "permit-user-rc", "no-touch-required"])
    }

    @Test("Certified key type mappings", .tags(.rsa))
    func testCertifiedKeyTypeMappings() throws {
        let ed = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let rsa = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        let ecdsa256 = try SwiftKeyGen.generateKey(type: .ecdsa256) as! ECDSAKey
        let ecdsa384 = try SwiftKeyGen.generateKey(type: .ecdsa384) as! ECDSAKey
        let ecdsa521 = try SwiftKeyGen.generateKey(type: .ecdsa521) as! ECDSAKey

        #expect(ed.toCertified().certifiedKeyType == "ssh-ed25519-cert-v01@openssh.com")
        #expect(rsa.toCertified().certifiedKeyType == "ssh-rsa-cert-v01@openssh.com")
        #expect(ecdsa256.toCertified().certifiedKeyType == "ecdsa-sha2-nistp256-cert-v01@openssh.com")
        #expect(ecdsa384.toCertified().certifiedKeyType == "ecdsa-sha2-nistp384-cert-v01@openssh.com")
        #expect(ecdsa521.toCertified().certifiedKeyType == "ecdsa-sha2-nistp521-cert-v01@openssh.com")
    }

    @Test("publicKeyData throws when unsigned")
    func testPublicKeyDataUnsigned() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let certified = key.toCertified()
        #expect(throws: SSHKeyError.certificateNotSigned) {
            _ = try certified.publicKeyData()
        }
    }

    @Test("publicKeyString empty when unsigned")
    func testPublicKeyStringUnsigned() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let certified = key.toCertified()
        #expect(certified.publicKeyString().isEmpty)
    }

    @Test("certificateInfo with no principals/options/extensions shows (none)")
    func testCertificateInfoEmptySections() throws {
        let caKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let hostKey = try SwiftKeyGen.generateKey(type: .ed25519) as! Ed25519Key
        let cert = try CertificateAuthority.signCertificate(
            publicKey: hostKey,
            caKey: caKey,
            keyId: "empty-sections",
            principals: [],
            certificateType: .host,
            criticalOptions: [],
            extensions: [] // host default => none
        )
        // Ensure we truly have no extensions (user cert would auto-populate)
        #expect(cert.certificate.extensions.isEmpty)
        let info = cert.certificateInfo()
        #expect(info.contains("Principals:\n    (none)"))
        #expect(info.contains("Critical Options:\n    (none)"))
        #expect(info.contains("Extensions:\n    (none)"))
    }
}
