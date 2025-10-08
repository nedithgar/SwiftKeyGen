import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("RSA Key Unit Tests", .tags(.unit, .rsa))
struct RSAKeyUnitTests {
    
    @Test("Generate 2048-bit RSA key and verify components")
    func generateRSAKey() throws {
        // Generate a 2048-bit RSA key
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa@example.com") as! RSAKey
        
        // Verify key type
        #expect(key.keyType == .rsa)
        #expect(key.comment == "rsa@example.com")
        
        // Verify public key format
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-rsa "))
        #expect(publicKeyString.hasSuffix(" rsa@example.com"))
        
        // Verify public key data
        let publicKeyData = key.publicKeyData()
        #expect(publicKeyData.count > 0)
        
        // Decode and verify the public key structure
        var decoder = SSHDecoder(data: publicKeyData)
        let keyType = try decoder.decodeString()
        #expect(keyType == "ssh-rsa")
        
        let exponent = try decoder.decodeData()
        let modulus = try decoder.decodeData()
        
        // RSA exponent is typically 65537 (0x010001)
        #expect(exponent.count > 0)
        
        // Modulus should be approximately 256 bytes for 2048-bit key
        #expect(modulus.count >= 255 && modulus.count <= 257)
    }

    @Test("RSA key fingerprint generation")
    func rsaFingerprint() throws {
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048) as! RSAKey
        
        // Test fingerprints
        let sha256Fingerprint = key.fingerprint(hash: .sha256)
        #expect(sha256Fingerprint.hasPrefix("SHA256:"))
        
        let md5Fingerprint = key.fingerprint(hash: .md5, format: .hex)
        #expect(md5Fingerprint.contains(":"))
    }
    
    @Test("Invalid RSA key size")
    func invalidKeySize() throws {
        // Test invalid key sizes according to OpenSSH standards
        let invalidSizes = [
            512,    // Too small (< 1024)
            768,    // Too small (< 1024)
            1023,   // Not a multiple of 8
            1025,   // Not a multiple of 8
            16385,  // Too large (> 16384)
            32768   // Too large (> 16384)
        ]
        
        for size in invalidSizes {
            do {
                _ = try SwiftKeyGen.generateKey(type: .rsa, bits: size) as! RSAKey
                Issue.record("Expected error for invalid key size \(size)")
            } catch SSHKeyError.invalidKeySize(_, _) {
                // Expected error
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
        }
    }

    @Test("Generate RSA key with arbitrary size (e.g., 3584 bits)")
    func arbitraryKeySize() throws {
        let size = 3584
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: size, comment: "test-\(size)") as! RSAKey
        
        // Verify key was generated
        #expect(key.comment == "test-\(size)")
        
        // Verify public key can be exported
        let publicKeyString = key.publicKeyString()
        #expect(publicKeyString.hasPrefix("ssh-rsa"))
        #expect(publicKeyString.contains("test-\(size)"))
        
        // Verify key size by checking the public key data
        let publicData = key.publicKeyData()
        #expect(publicData.count > 0)
        
        // Verify the modulus size matches the requested key size
        var decoder = SSHDecoder(data: publicData)
        _ = try decoder.decodeString() // skip key type
        _ = try decoder.decodeData()   // skip exponent
        let modulus = try decoder.decodeData()
        
        // Modulus size should match key size (in bytes)
        let expectedSize = size / 8  // 3584 / 8 = 448 bytes
        #expect(modulus.count >= expectedSize - 1 && modulus.count <= expectedSize + 1)
        
        // Basic fingerprint test
        let fingerprint = key.fingerprint(hash: .sha256)
        #expect(fingerprint.hasPrefix("SHA256:"))
    }

    @Test("RSA privateKeyData DER round-trip via PEM")
    func rsaPrivateKeyDataDERRoundTrip() throws {
        // Generate a 1024-bit RSA key to keep runtime bounded
        let original = try SwiftKeyGen.generateKey(type: .rsa, bits: 1024, comment: "der-roundtrip") as! RSAKey

        // Obtain PKCS#1 DER from the key under test
        let der = original.privateKeyData()
        #expect(der.count > 0)
        #expect(der[0] == 0x30) // SEQUENCE tag sanity

        // Cross-check with direct helper to ensure consistency
        if let directDER = try? original.privateKey.pkcs1DERRepresentation() {
            #expect(der == directDER)
        }

        // Wrap DER as PKCS#1 PEM
    // Produce a deterministic 64‑column wrapped base64 body without indentation
    let base64Wrapped = der.base64EncodedString().wrapped(every: 64) + "\n"
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n" + base64Wrapped + "-----END RSA PRIVATE KEY-----\n"

        // Sanity: PEM detection and body extraction should succeed and round-trip
        #expect(PEMParser.isPEMFormat(pem))
        #expect(PEMParser.detectPEMType(pem) == "RSA PRIVATE KEY")
        let body = pem.pemBody(type: "RSA PRIVATE KEY")
        #expect(body != nil)
        if let body = body, let decoded = Data(base64Encoded: body) {
            // Length should match exactly; if not we surface the diff for debugging
            #expect(decoded.count == der.count, "(decoded → \(decoded.count) bytes) == (der → \(der.count) bytes)")
            #expect(decoded == der)
        }

        // Extra sanity: the DER should contain the expected number of INTEGERs
        var sanity = ASN1Parser(data: der)
        #expect(try sanity.parseSequence() != nil) // outer sequence present
        sanity = ASN1Parser(data: der)
        #expect(der[0] == 0x30)
        sanity.offset = 1
        _ = try sanity.parseLength()
        #expect(try sanity.parseInteger() != nil) // version
        #expect(try sanity.parseInteger() != nil) // n
        #expect(try sanity.parseInteger() != nil) // e
        #expect(try sanity.parseInteger() != nil) // d
        #expect(try sanity.parseInteger() != nil) // p
        #expect(try sanity.parseInteger() != nil) // q
        #expect(try sanity.parseInteger() != nil) // dP
        #expect(try sanity.parseInteger() != nil) // dQ
        #expect(try sanity.parseInteger() != nil) // qInv

        // Parse back via existing PEM parser
        let parsed = try PEMParser.parseRSAPrivateKey(pem)

        // Public portions must match exactly
        #expect(parsed.publicKeyData() == original.publicKeyData())

        // Verify private material by signing and cross-verifying
        let msg = Data("rsa-der-roundtrip".utf8)
        let sig = try parsed.sign(data: msg)
        #expect(try original.verify(signature: sig, for: msg))
    }
}
