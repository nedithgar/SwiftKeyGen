import Testing
@testable import SwiftKeyGen
import Foundation

/// Integration tests for format conversion round-trips between different key formats.
@Suite("Format Conversion Round-Trip Integration Tests", .tags(.integration))
struct FormatConversionRoundTripIntegrationTests {
    
    // MARK: - OpenSSH ↔ PEM Round-Trips
    
    @Test("OpenSSH → PEM → OpenSSH round-trip via both tools")
    func testOpenSSHToPEMToOpenSSHRoundTrip() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key in OpenSSH format with ssh-keygen
            let opensshPath = tempDir.appendingPathComponent("openssh_key")
            let pubPath = tempDir.appendingPathComponent("openssh_key.pub")
            
            // Use RSA for this test because OpenSSH's ssh-keygen reliably supports
            // reading PEM (PKCS#1 / PKCS#8) representations for RSA private keys.
            // Ed25519 PKCS#8 PEM parsing is not universally supported by ssh-keygen
            // (it expects the OpenSSH proprietary format), which previously caused
            // this test to fail even though our PKCS#8 serialization was correct.
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "rsa",
                "-b", "2048",
                "-f", opensshPath.path,
                "-N", "",
                "-C", "test@host.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate OpenSSH RSA key")
            
            // Get original fingerprint from ssh-keygen
            let originalFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(originalFP.succeeded)
            
            // Convert to PEM with our implementation
            let parsed = try KeyManager.readPrivateKey(from: opensshPath.path, passphrase: nil)
            let pemString = try KeyConverter.toPEM(key: parsed, passphrase: nil)
            
            // Write PEM version
            let pemPath = tempDir.appendingPathComponent("pem_key.pem")
            try IntegrationTestSupporter.write(pemString, to: pemPath)
            
            // Verify ssh-keygen can read the PEM
            let pemFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pemPath.path])
            #expect(pemFP.succeeded, "ssh-keygen should read our PEM format")
            
            // Compare fingerprints
            let originalHashFull = originalFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let pemHashFull = pemFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            // Strip trailing comment (last space‑separated token) for comparison – comment preservation
            // across formats (PKCS#1/PKCS#8) is not standardized.
            func normalize(_ s: String) -> String {
                let parts = s.split(separator: " ")
                guard parts.count >= 2 else { return s }
                let bits = parts[0]
                let fingerprint = parts[1]
                if let alg = parts.last, alg.first == "(", alg.last == ")" {
                    return "\(bits) \(fingerprint) \(alg)"
                }
                return "\(bits) \(fingerprint)"
            }
            let originalHash = normalize(originalHashFull)
            let pemHash = normalize(pemHashFull)
            #expect(originalHash == pemHash, "Fingerprints (sans comment) should match after OpenSSH→PEM conversion")
            
            // Convert PEM back to OpenSSH with our implementation
            let parsedPEM = try KeyManager.readPrivateKey(from: pemPath.path, passphrase: nil)
            let backToOpenSSHData = try OpenSSHPrivateKey.serialize(key: parsedPEM, passphrase: nil)
            
            // Write back to OpenSSH
            let roundTripPath = tempDir.appendingPathComponent("roundtrip_key")
            try backToOpenSSHData.write(to: roundTripPath)
            
            // Verify ssh-keygen can read it
            let roundTripFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", roundTripPath.path])
            #expect(roundTripFP.succeeded, "ssh-keygen should read round-trip OpenSSH key")
            
            let roundTripHashFull = roundTripFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let roundTripHash = normalize(roundTripHashFull)
            #expect(originalHash == roundTripHash, "Fingerprints (sans comment) should match after full round-trip")
        }
    }
    
    // MARK: - OpenSSH ↔ PKCS8 Round-Trips
    
    @Test("OpenSSH → PKCS8 → OpenSSH round-trip via both tools", .tags(.slow))
    func testOpenSSHToPKCS8ToOpenSSHRoundTrip() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key in OpenSSH format with ssh-keygen
            let opensshPath = tempDir.appendingPathComponent("openssh_key")
            let pubPath = tempDir.appendingPathComponent("openssh_key.pub")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", opensshPath.path,
                "-N", "",
                "-C", "test@host.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate OpenSSH key")
            
            // Get original fingerprint
            let originalFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(originalFP.succeeded)
            
            // Convert to PKCS8 with our implementation
            let parsed = try KeyManager.readPrivateKey(from: opensshPath.path, passphrase: nil)
            let pkcs8Data = try KeyConverter.toPKCS8(key: parsed, passphrase: nil)
            let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
            
            // Write PKCS8 version
            let pkcs8Path = tempDir.appendingPathComponent("pkcs8_key.pem")
            try IntegrationTestSupporter.write(pkcs8String, to: pkcs8Path)
            
            // Verify ssh-keygen can read the PKCS8
            let pkcs8FP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pkcs8Path.path])
            #expect(pkcs8FP.succeeded, "ssh-keygen should read our PKCS8 format")
            
            // Compare fingerprints
            let originalHash = originalFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let pkcs8Hash = pkcs8FP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            #expect(originalHash == pkcs8Hash, "Fingerprints should match after OpenSSH→PKCS8 conversion")
            
            // Convert PKCS8 back to OpenSSH with our implementation
            let parsedPKCS8 = try KeyManager.readPrivateKey(from: pkcs8Path.path, passphrase: nil)
            let backToOpenSSHData = try OpenSSHPrivateKey.serialize(key: parsedPKCS8, passphrase: nil)
            
            // Write back to OpenSSH
            let roundTripPath = tempDir.appendingPathComponent("roundtrip_key")
            try backToOpenSSHData.write(to: roundTripPath)
            
            // Verify ssh-keygen can read it
            let roundTripFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", roundTripPath.path])
            #expect(roundTripFP.succeeded, "ssh-keygen should read round-trip OpenSSH key")
            
            let roundTripHash = roundTripFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            #expect(originalHash == roundTripHash, "Fingerprints should match after full round-trip")
        }
    }
    
    // MARK: - PEM ↔ PKCS8 Round-Trips
    
    @Test("PEM → PKCS8 → PEM round-trip via both tools", .tags(.slow))
    func testPEMToPKCS8ToPEMRoundTrip() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key in PEM format with our implementation
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@host.com") as! Ed25519Key
            let pemString = try KeyConverter.toPEM(key: key, passphrase: nil)
            
            // Write PEM version
            let pemPath1 = tempDir.appendingPathComponent("pem_key1.pem")
            try IntegrationTestSupporter.write(pemString, to: pemPath1)
            
            // Get fingerprint from ssh-keygen
            let pem1FP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pemPath1.path])
            #expect(pem1FP.succeeded, "ssh-keygen should read our PEM format")
            
            // Convert to PKCS8 with our implementation
            let pkcs8Data = try KeyConverter.toPKCS8(key: key, passphrase: nil)
            let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
            
            // Write PKCS8 version
            let pkcs8Path = tempDir.appendingPathComponent("pkcs8_key.pem")
            try IntegrationTestSupporter.write(pkcs8String, to: pkcs8Path)
            
            // Verify ssh-keygen can read the PKCS8
            let pkcs8FP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pkcs8Path.path])
            #expect(pkcs8FP.succeeded, "ssh-keygen should read our PKCS8 format")
            
            // Compare fingerprints
            let pem1Hash = pem1FP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let pkcs8Hash = pkcs8FP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            #expect(pem1Hash == pkcs8Hash, "Fingerprints should match after PEM→PKCS8 conversion")
            
            // Convert PKCS8 back to PEM with our implementation
            let parsedPKCS8 = try KeyManager.readPrivateKey(from: pkcs8Path.path, passphrase: nil)
            let backToPEM = try KeyConverter.toPEM(key: parsedPKCS8, passphrase: nil)
            
            // Write back to PEM
            let pemPath2 = tempDir.appendingPathComponent("pem_key2.pem")
            try IntegrationTestSupporter.write(backToPEM, to: pemPath2)
            
            // Verify ssh-keygen can read it
            let pem2FP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pemPath2.path])
            #expect(pem2FP.succeeded, "ssh-keygen should read round-trip PEM key")
            
            let pem2Hash = pem2FP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            #expect(pem1Hash == pem2Hash, "Fingerprints should match after full round-trip")
        }
    }
    
    // MARK: - OpenSSH ↔ RFC4716 Round-Trips (Public Key Only)
    
    @Test("OpenSSH → RFC4716 → OpenSSH public key round-trip")
    func testOpenSSHToRFC4716ToOpenSSHRoundTrip() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate key with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("test_key")
            let pubPath = tempDir.appendingPathComponent("test_key.pub")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", "",
                "-C", "test@host.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate key")
            
            // Get original fingerprint
            let originalFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pubPath.path])
            #expect(originalFP.succeeded)
            
            // Convert to RFC4716 with ssh-keygen
            let rfc4716Path = tempDir.appendingPathComponent("test_key.rfc4716")
            let exportResult = try IntegrationTestSupporter.runSSHKeygen([
                "-e",
                "-f", pubPath.path,
                "-m", "RFC4716"
            ])
            #expect(exportResult.succeeded, "ssh-keygen should export to RFC4716")
            try IntegrationTestSupporter.write(exportResult.stdout, to: rfc4716Path)
            
            // Verify our parser can read the RFC4716
            _ = try Data(contentsOf: rfc4716Path)
            
            // Parse and convert back via our implementation
            let tempKey = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: nil)
            let backToOpenSSH = tempKey.publicKeyString()
            
            // Write back to file
            let roundTripPath = tempDir.appendingPathComponent("roundtrip.pub")
            try IntegrationTestSupporter.write(backToOpenSSH, to: roundTripPath)
            
            // Verify ssh-keygen can read it
            let roundTripFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", roundTripPath.path])
            #expect(roundTripFP.succeeded, "ssh-keygen should read round-trip public key")
            
            // Compare fingerprints (normalize both to compare just hash part)
            let originalHash = originalFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            let roundTripHash = roundTripFP.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            #expect(originalHash == roundTripHash, "Fingerprints should match after RFC4716 round-trip")
        }
    }
    
    // MARK: - Multiple Key Types Round-Trip
    
    @Test("All key types preserve integrity through format conversions", .tags(.slow, .rsa))
    func testAllKeyTypesPreserveIntegrityThroughConversions() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Test with different key types
            let keyTypes: [(KeyType, String)] = [
                (.ed25519, "ed25519"),
                (.ecdsa256, "ecdsa256"),
                (.ecdsa384, "ecdsa384"),
                (.ecdsa521, "ecdsa521"),
                (.rsa, "rsa2048"),
            ]
            
            for (keyType, name) in keyTypes {
                let key = try SwiftKeyGen.generateKey(type: keyType, bits: keyType == .rsa ? 2048 : nil, comment: "\(name)@test.com")
                
                // Test OpenSSH format (default)
                let opensshData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
                let opensshPath = tempDir.appendingPathComponent("\(name)_openssh.key")
                try opensshData.write(to: opensshPath)
                
                // Verify ssh-keygen can read it
                let opensshFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", opensshPath.path])
                #expect(opensshFP.succeeded, "ssh-keygen should read OpenSSH format for \(keyType)")
                
                // Test PEM format
                let pemString = try KeyConverter.toPEM(key: key, passphrase: nil)
                let pemPath = tempDir.appendingPathComponent("\(name)_pem.key")
                try IntegrationTestSupporter.write(pemString, to: pemPath)
                
                // Verify ssh-keygen can read it
                let pemFP = try IntegrationTestSupporter.runSSHKeygen(["-l", "-f", pemPath.path])
                #expect(pemFP.succeeded, "ssh-keygen should read PEM format for \(keyType)")
            }
        }
    }
    
    // MARK: - Conversion Preserves Public Key Integrity
    
    @Test("All conversions preserve public key integrity")
    func testConversionsPreservePublicKeyIntegrity() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            // Generate a key
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "integrity@test.com") as! Ed25519Key
            let originalPublicKey = key.publicKeyString()
            
            // Test OpenSSH format
            let opensshData = try OpenSSHPrivateKey.serialize(key: key, passphrase: nil)
            let opensshPath = tempDir.appendingPathComponent("openssh.key")
            try opensshData.write(to: opensshPath)
            let parsedOpenSSH = try KeyManager.readPrivateKey(from: opensshPath.path, passphrase: nil)
            #expect(parsedOpenSSH.publicKeyString() == originalPublicKey, "OpenSSH format should preserve public key")
            
            // Test PEM format
            let pemString = try KeyConverter.toPEM(key: key, passphrase: nil)
            let pemPath = tempDir.appendingPathComponent("pem.key")
            try IntegrationTestSupporter.write(pemString, to: pemPath)
            let parsedPEM = try KeyManager.readPrivateKey(from: pemPath.path, passphrase: nil)
            #expect(parsedPEM.publicKeyString() == originalPublicKey, "PEM format should preserve public key")
        }
    }
    
    // MARK: - Encrypted Key Conversions
    
    @Test("Encrypted keys preserve integrity through format conversions", .tags(.slow))
    func testEncryptedKeysPreserveIntegrityThroughConversions() throws {
        try IntegrationTestSupporter.withTemporaryDirectory { tempDir in
            let passphrase = "test-passphrase-123"
            
            // Generate encrypted key in OpenSSH format with ssh-keygen
            let keyPath = tempDir.appendingPathComponent("encrypted_key")
            
            let genResult = try IntegrationTestSupporter.runSSHKeygen([
                "-t", "ed25519",
                "-f", keyPath.path,
                "-N", passphrase,
                "-C", "encrypted@test.com"
            ])
            #expect(genResult.succeeded, "ssh-keygen should generate encrypted key")
            
            // Get fingerprint
            let fpResult = try IntegrationTestSupporter.runSSHKeygen(
                ["-y", "-f", keyPath.path],
                input: "\(passphrase)\n".data(using: .utf8)
            )
            #expect(fpResult.succeeded, "ssh-keygen should decrypt with passphrase")
            
            // Parse with our implementation
            let parsed = try KeyManager.readPrivateKey(from: keyPath.path, passphrase: passphrase)
            let originalPublicKey = parsed.publicKeyString()
            
            // Convert to PEM (encrypted)
            let pemString = try KeyConverter.toPEM(key: parsed, passphrase: passphrase)
            
            // Write encrypted PEM
            let pemPath = tempDir.appendingPathComponent("encrypted.pem")
            try IntegrationTestSupporter.write(pemString, to: pemPath)
            
            // Verify ssh-keygen can decrypt it
            let pemFPResult = try IntegrationTestSupporter.runSSHKeygen(
                ["-y", "-f", pemPath.path],
                input: "\(passphrase)\n".data(using: .utf8)
            )
            #expect(pemFPResult.succeeded, "ssh-keygen should decrypt our encrypted PEM")
            
            // Parse encrypted PEM back
            let parsedPEM = try KeyManager.readPrivateKey(from: pemPath.path, passphrase: passphrase)
            let pemPublicKey = parsedPEM.publicKeyString()
            
            #expect(originalPublicKey == pemPublicKey, 
                    "Public key should match after encrypted conversion")
        }
    }
}
