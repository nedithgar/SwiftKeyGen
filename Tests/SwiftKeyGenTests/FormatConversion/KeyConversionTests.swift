import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Key Conversion Tests")
struct KeyConversionTests {
    
    @Test("RFC4716 export")
    func testRFC4716Export() throws {
        // Generate a test key
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test@example.com") as! Ed25519Key
        
        // Export to RFC4716
        let rfc4716 = try KeyConverter.toRFC4716(key: key)
        
        // Verify format
        #expect(rfc4716.contains("---- BEGIN SSH2 PUBLIC KEY ----"))
        #expect(rfc4716.contains("---- END SSH2 PUBLIC KEY ----"))
        #expect(rfc4716.contains("Comment: \"test@example.com\""))
        
        // Verify it can be parsed back
        let parsed = try PublicKeyParser.parseRFC4716(rfc4716)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "test@example.com")
        #expect(parsed.data == key.publicKeyData())
    }
    
    @Test("RFC4716 import")
    func testRFC4716Import() throws {
        let rfc4716String = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        Comment: "user@host"
        AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
        ---- END SSH2 PUBLIC KEY ----
        """
        
        let parsed = try PublicKeyParser.parseRFC4716(rfc4716String)
        #expect(parsed.type == .ed25519)
        #expect(parsed.comment == "user@host")
        
        // Verify the key data is valid
        try PublicKeyParser.validatePublicKeyData(parsed.data, type: parsed.type)
    }
    
    @Test("RFC4716 with long lines")
    func testRFC4716LongLines() throws {
        // Generate RSA key which produces longer base64
        let key = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-test") as! RSAKey
        
        // Export to RFC4716
        let rfc4716 = try KeyConverter.toRFC4716(key: key)
        
        // Verify lines are properly wrapped at 70 characters
        let lines = rfc4716.split(separator: "\n")
        for (index, line) in lines.enumerated() {
            // Skip header, footer, and comment lines
            if index == 0 || index == lines.count - 1 || line.hasPrefix("Comment:") {
                continue
            }
            #expect(line.count <= 70)
        }
        
        // Parse it back
        let parsed = try PublicKeyParser.parseRFC4716(rfc4716)
        #expect(parsed.type == .rsa)
        #expect(parsed.data == key.publicKeyData())
    }
    
    @Test("Format detection")
    func testFormatDetection() throws {
        // OpenSSH public key
        let opensshPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"
        #expect(try KeyConversionManager.detectFormat(from: opensshPub) == .openssh)
        
        // RFC4716
        let rfc4716 = """
        ---- BEGIN SSH2 PUBLIC KEY ----
        AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
        ---- END SSH2 PUBLIC KEY ----
        """
        #expect(try KeyConversionManager.detectFormat(from: rfc4716) == .rfc4716)
        
        // OpenSSH private key
        let opensshPrivate = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        -----END OPENSSH PRIVATE KEY-----
        """
        #expect(try KeyConversionManager.detectFormat(from: opensshPrivate) == .openssh)
    }
    
    @Test("Parse any format")
    func testParseAnyFormat() throws {
        let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-key") as! Ed25519Key
        
        // Test OpenSSH format
        let opensshFormat = key.publicKeyString()
        let parsedOpenSSH = try PublicKeyParser.parseAnyFormat(opensshFormat)
        #expect(parsedOpenSSH.data == key.publicKeyData())
        
        // Test RFC4716 format
        let rfc4716Format = try KeyConverter.toRFC4716(key: key)
        let parsedRFC4716 = try PublicKeyParser.parseAnyFormat(rfc4716Format)
        #expect(parsedRFC4716.data == key.publicKeyData())
    }
    
    @Test("Stdin/stdout simulation")
    func testStdinStdoutSupport() throws {
        // Test that special filename is recognized
        #expect(KeyFileManager.STDIN_STDOUT_FILENAME == "-")
        
        // Test readKeyData with regular file
        let testData = Data("test data".utf8)
        let tempFile = FileManager.default.temporaryDirectory.appendingPathComponent("test.txt")
        try testData.write(to: tempFile)
        defer { try? FileManager.default.removeItem(at: tempFile) }
        
        let readData = try KeyFileManager.readKeyData(from: tempFile.path)
        #expect(readData == testData)
    }
    
    @Test("Batch conversion")
    func testBatchConversion() throws {
        // Create test files
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        
        var testFiles: [String] = []
        
        // Create test keys
        for i in 1...3 {
            let key = try SwiftKeyGen.generateKey(type: .ed25519, comment: "test-\(i) as! Ed25519Key")
            let filePath = tempDir.appendingPathComponent("key\(i).pub").path
            try key.publicKeyString().write(toFile: filePath, atomically: true, encoding: .utf8)
            testFiles.append(filePath)
        }
        
        // Batch convert to RFC4716
        let options = KeyConversionManager.ConversionOptions(
            toFormat: .rfc4716,
            fromFormat: .openssh,
            output: tempDir.path  // Will generate individual output files
        )
        
        let results = try KeyConversionManager.batchConvert(files: testFiles, options: options)
        
        // Verify all conversions succeeded
        #expect(results.count == 3)
        for result in results {
            #expect(result.success == true)
            #expect(result.error == nil)
            
            // Verify output file exists and is valid RFC4716
            let outputContent = try String(contentsOfFile: result.output, encoding: .utf8)
            #expect(PublicKeyParser.isRFC4716Format(outputContent))
        }
    }
    
    @Test("All key types RFC4716 conversion")
    func testAllKeyTypesRFC4716() throws {
        // Test Ed25519
        let ed25519 = try SwiftKeyGen.generateKey(type: .ed25519, comment: "ed25519-test") as! Ed25519Key
        let ed25519RFC = try KeyConverter.toRFC4716(key: ed25519)
        let ed25519Parsed = try PublicKeyParser.parseRFC4716(ed25519RFC)
        #expect(ed25519Parsed.type == .ed25519)
        
        // Test RSA
        let rsa = try SwiftKeyGen.generateKey(type: .rsa, bits: 2048, comment: "rsa-test") as! RSAKey
        let rsaRFC = try KeyConverter.toRFC4716(key: rsa)
        let rsaParsed = try PublicKeyParser.parseRFC4716(rsaRFC)
        #expect(rsaParsed.type == .rsa)
        
        // Test ECDSA P-256
        let ecdsa256 = try SwiftKeyGen.generateKey(type: .ecdsa256, comment: "ecdsa256-test") as! ECDSAKey
        let ecdsa256RFC = try KeyConverter.toRFC4716(key: ecdsa256)
        let ecdsa256Parsed = try PublicKeyParser.parseRFC4716(ecdsa256RFC)
        #expect(ecdsa256Parsed.type == .ecdsa256)
        
        // Test ECDSA P-384
        let ecdsa384 = try SwiftKeyGen.generateKey(type: .ecdsa384, comment: "ecdsa384-test") as! ECDSAKey
        let ecdsa384RFC = try KeyConverter.toRFC4716(key: ecdsa384)
        let ecdsa384Parsed = try PublicKeyParser.parseRFC4716(ecdsa384RFC)
        #expect(ecdsa384Parsed.type == .ecdsa384)
        
        // Test ECDSA P-521
        let ecdsa521 = try SwiftKeyGen.generateKey(type: .ecdsa521, comment: "ecdsa521-test") as! ECDSAKey
        let ecdsa521RFC = try KeyConverter.toRFC4716(key: ecdsa521)
        let ecdsa521Parsed = try PublicKeyParser.parseRFC4716(ecdsa521RFC)
        #expect(ecdsa521Parsed.type == .ecdsa521)
    }
}
