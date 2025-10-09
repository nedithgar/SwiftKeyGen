import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto
import BigInt

@Suite("RSA DER Encoding", .tags(.unit, .rsa))
struct RSADEREncodingUnitTests {

    // Minimal ASN.1 DER helpers (test-local) ---------------------------------
    private func readLength(_ data: Data, _ index: inout Int) -> Int? {
        guard index < data.count else { return nil }
        let first = data[index]; index += 1
        if first & 0x80 == 0 { return Int(first) }
        let count = Int(first & 0x7F)
        guard count > 0 && count <= 4 && index + count <= data.count else { return nil }
        var value = 0
        for _ in 0..<count { value = (value << 8) | Int(data[index]); index += 1 }
        return value
    }

    private func readInteger(_ data: Data, _ index: inout Int) -> BigUInt? {
        guard index < data.count, data[index] == 0x02 else { return nil }
        index += 1
        guard let len = readLength(data, &index), index + len <= data.count else { return nil }
        let bytes = data[index..<(index+len)]
        index += len
        // Strip optional leading 0x00 used for sign bit padding
        let cleaned: Data
        if bytes.count > 1 && bytes.first == 0x00 {
            cleaned = Data(bytes.drop(while: { $0 == 0x00 && bytes.dropFirst().first! & 0x80 == 0 }))
        } else { cleaned = Data(bytes) }
        return BigUInt(cleaned)
    }

    private func expectOID(_ data: Data, oid: [UInt8]) -> Bool {
        var idx = 0
        guard idx < data.count, data[idx] == 0x06 else { return false }
        idx += 1
        guard let len = readLength(data, &idx), idx + len == data.count else { return false }
        let body = data[idx..<(idx+len)]
        return Array(body) == oid
    }

    // Tests ------------------------------------------------------------------

    @Test("PKCS#1 Private Key DER Structure")
    func testPrivateKeyPKCS1DERStructure() throws {
        let (priv, _) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        let der = try priv.pkcs1DERRepresentation()

        #expect(der.first == 0x30) // SEQUENCE
        var idx = 1
        guard let seqLen = readLength(der, &idx) else { Issue.record("Could not read sequence length"); return }
        #expect(idx + seqLen == der.count)

        // Expect 9 INTEGERs: version + 8 components
        var integers: [BigUInt] = []
        while idx < der.count {
            guard let intVal = readInteger(der, &idx) else { Issue.record("Failed to read INTEGER at index \(idx)"); return }
            integers.append(intVal)
        }
        #expect(integers.count == 9)
        // version must be 0
        #expect(integers.first == 0)

        // Compare core components we can access
        #expect(integers[1] == priv.n) // modulus
        #expect(integers[2] == priv.e) // public exponent
        // The rest (d, p, q, dP, dQ, qInv) encode sensitive data; spot‑check one relation.
        // dP = d mod (p-1)
        if integers.count == 9 {
            let d = integers[3]; let p = integers[4]; let dP = integers[6]
            if p > 1 { #expect(d % (p - 1) == dP) }
        }
    }

    @Test("PKCS#1 Public Key DER Structure")
    func testPublicKeyPKCS1DERStructure() throws {
        let (_, pub) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        let der = try pub.pkcs1DERRepresentation()
        #expect(der.first == 0x30)
        var idx = 1
    guard let _ = readLength(der, &idx) else { Issue.record("Length parse fail"); return }
        var components: [BigUInt] = []
        while idx < der.count { guard let v = readInteger(der, &idx) else { Issue.record("Missing integer"); return }; components.append(v) }
        #expect(components.count == 2)
        #expect(components[0] == pub.n)
        #expect(components[1] == pub.e)
    }

    @Test("SubjectPublicKeyInfo DER Structure")
    func testSubjectPublicKeyInfoDERStructure() throws {
        let (_, pub) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        let spki = try pub.subjectPublicKeyInfoDERRepresentation()
        let innerPKCS1 = try pub.pkcs1DERRepresentation()
        #expect(spki.first == 0x30)
        var idx = 1
        guard let seqLen = readLength(spki, &idx) else { Issue.record("SPKI seq len parse fail"); return }
        #expect(idx + seqLen == spki.count)

        // Parse algorithm identifier sequence
        guard idx < spki.count, spki[idx] == 0x30 else { Issue.record("Missing AlgorithmIdentifier sequence"); return }
        idx += 1
        guard let algLen = readLength(spki, &idx) else { Issue.record("Alg len fail"); return }
        let algEnd = idx + algLen
        #expect(algEnd <= spki.count)
        // Expect OID + NULL
        // rsaEncryption OID encodes to: 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
        // We'll parse minimally.
        if idx < algEnd, spki[idx] == 0x06 { // OBJECT IDENTIFIER
            // Capture exact OID TLV
            idx += 1
            guard let oidLen = readLength(spki, &idx) else { Issue.record("OID length parse fail"); return }
            guard idx + oidLen <= algEnd else { Issue.record("OID length exceeds algorithm sequence"); return }
            let oidBody = spki[idx..<(idx + oidLen)]
            idx += oidLen
            // Reset idx back to end-of-OID for later NULL parsing.
            // Expected rsaEncryption OID body: 2A 86 48 86 F7 0D 01 01 01
            let expectedBody: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
            #expect(Array(oidBody) == expectedBody)
            // Expect following NULL
            if idx < algEnd {
                #expect(spki[idx] == 0x05) // NULL tag
                idx += 1
                guard let nullLen = readLength(spki, &idx) else { Issue.record("NULL length parse fail"); return }
                #expect(nullLen == 0)
            } else { Issue.record("Missing NULL after OID") }
            // Ensure we consumed exactly the algorithm sequence
            #expect(idx == algEnd)
        }
        // Move to end of alg sequence
        idx = algEnd

        // BIT STRING
        guard idx < spki.count, spki[idx] == 0x03 else { Issue.record("Missing BIT STRING"); return }
        idx += 1
        guard let bitLen = readLength(spki, &idx), idx + bitLen <= spki.count else { Issue.record("Bit string len fail"); return }
        #expect(bitLen >= innerPKCS1.count + 1)
        // Unused bits byte must be 0
        #expect(spki[idx] == 0x00)
        idx += 1
        let bitStringPayload = spki[idx..<(idx + bitLen - 1)]
        #expect(Data(bitStringPayload) == innerPKCS1)
    }

    @Test("Public Key PEM Round Trip")
    func testPublicKeyPEMRoundTrip() throws {
        let (_, pub) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        let pem = try pub.pkcs1PEMRepresentation()
        #expect(pem.contains("-----BEGIN PUBLIC KEY-----"))
        #expect(pem.contains("-----END PUBLIC KEY-----"))
        // Extract base64
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") }
    let b64 = lines.joined()
    guard let der = Data(base64Encoded: b64) else { Issue.record("Base64 decode fail"); return }
    let expected = try pub.subjectPublicKeyInfoDERRepresentation()
    #expect(der == expected)
    }

    @Test("Private Key PEM Round Trip")
    func testPrivateKeyPEMRoundTrip() throws {
        let (priv, _) = try Insecure.RSA.generateKeyPair(bitSize: 512)
        let pem = try priv.pkcs1PEMRepresentation()
        #expect(pem.contains("-----BEGIN RSA PRIVATE KEY-----"))
        #expect(pem.contains("-----END RSA PRIVATE KEY-----"))
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") && !$0.isEmpty }
        let b64 = lines.joined()
        guard let der = Data(base64Encoded: b64) else { Issue.record("Base64 decode fail"); return }
        // Very lightweight structural check (already thoroughly tested elsewhere)
        #expect(der.first == 0x30)
    }
}
