import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Test("EVP_BytesToKey implementation")
func testEVPBytesToKey() throws {
    // Test vector from OpenSSL
    let password = "test"
    let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    
    // Test AES-128-CBC (16 byte key, 16 byte IV)
    let (key128, iv128) = PEMEncryption.evpBytesToKey(
        password: password,
        salt: salt,
        keyLen: 16,
        ivLen: 16
    )
    
    #expect(key128.count == 16)
    #expect(iv128.count == 16)
    
    // Test AES-256-CBC (32 byte key, 16 byte IV)
    let (key256, iv256) = PEMEncryption.evpBytesToKey(
        password: password,
        salt: salt,
        keyLen: 32,
        ivLen: 16
    )
    
    #expect(key256.count == 32)
    #expect(iv256.count == 16)
    
    // Keys should start the same but 256 is longer
    #expect(key256.prefix(16) == key128)
}

@Test("PKCS#7 padding")
func testPKCS7Padding() throws {
    // Test various data sizes
    let testCases: [(data: Data, blockSize: Int, expectedPaddingLength: Int)] = [
        (Data([0x01, 0x02, 0x03]), 8, 5),
        (Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]), 8, 8), // Full block
        (Data([0x01]), 16, 15),
        (Data(repeating: 0x00, count: 16), 16, 16), // Full block
    ]
    
    for testCase in testCases {
        let padded = PEMEncryption.pkcs7Pad(data: testCase.data, blockSize: testCase.blockSize)
        #expect(padded.count % testCase.blockSize == 0)
        #expect(padded.count == testCase.data.count + testCase.expectedPaddingLength)
        
        // Verify padding bytes
        let paddingByte = padded[padded.count - 1]
        #expect(Int(paddingByte) == testCase.expectedPaddingLength)
        
        // Test unpadding
        let unpadded = try PEMEncryption.pkcs7Unpad(data: padded, blockSize: testCase.blockSize)
        #expect(unpadded == testCase.data)
    }
}

@Test("Encrypted SEC1 PEM export")
func testEncryptedSEC1Export() throws {
    // Generate test key
    let key = try ECDSAKeyGenerator.generateP256(comment: "test-encrypted")
    let passphrase = "test123"
    
    // Export with encryption
    let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase)
    
    // Verify PEM structure
    #expect(encryptedPEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(encryptedPEM.contains("-----END EC PRIVATE KEY-----"))
    #expect(encryptedPEM.contains("Proc-Type: 4,ENCRYPTED"))
    #expect(encryptedPEM.contains("DEK-Info: AES-128-CBC,"))
    
    // Extract salt from DEK-Info
    let lines = encryptedPEM.components(separatedBy: .newlines)
    let dekInfoLine = lines.first { $0.hasPrefix("DEK-Info:") }!
    let dekParts = dekInfoLine.split(separator: " ")[1].split(separator: ",")
    #expect(dekParts[0] == "AES-128-CBC")
    #expect(dekParts[1].count == 16) // 8 bytes hex = 16 chars
}

@Test("Encrypted PKCS#8 PEM export")
func testEncryptedPKCS8Export() throws {
    // Generate test key
    let key = try ECDSAKeyGenerator.generateP384(comment: "test-pkcs8")
    let passphrase = "mysecret"
    
    // Export with encryption
    let encryptedPEM = try key.pkcs8PEMRepresentation(passphrase: passphrase)
    
    // Verify PEM structure
    #expect(encryptedPEM.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----"))
    #expect(encryptedPEM.contains("-----END ENCRYPTED PRIVATE KEY-----"))
    #expect(!encryptedPEM.contains("Proc-Type")) // PKCS#8 doesn't use these headers
    #expect(!encryptedPEM.contains("DEK-Info"))
}

@Test("KeyConverter with encryption")
func testKeyConverterEncryption() throws {
    let key = try ECDSAKeyGenerator.generateP521(comment: "converter-test")
    let passphrase = "secretpass"
    
    // Test PEM format with encryption
    let pemString = try KeyConverter.toPEM(key: key, passphrase: passphrase)
    #expect(pemString.contains("Proc-Type: 4,ENCRYPTED"))
    #expect(pemString.contains("DEK-Info:"))
    
    // Test PKCS#8 format with encryption
    let pkcs8Data = try KeyConverter.toPKCS8(key: key, passphrase: passphrase)
    let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
    #expect(pkcs8String.contains("BEGIN ENCRYPTED PRIVATE KEY"))
}

@Test("Different cipher support")
func testDifferentCiphers() throws {
    let key = try ECDSAKeyGenerator.generateP256()
    let passphrase = "ciphertest"
    
    // Test all supported ciphers
    for cipher in PEMEncryption.PEMCipher.allCases {
        let encryptedPEM = try key.sec1PEMRepresentation(passphrase: passphrase, cipher: cipher)
        #expect(encryptedPEM.contains("DEK-Info: \(cipher.rawValue),"))
    }
}

@Test("PBKDF2 key derivation")
func testPBKDF2() throws {
    // Test vector
    let password = "password"
    let salt = Data("salt".utf8)
    let iterations = 1
    let keyLen = 20
    
    let derivedKey = try PKCS8Encryption.pbkdf2(
        password: password,
        salt: salt,
        iterations: iterations,
        keyLen: keyLen
    )
    
    #expect(derivedKey.count == keyLen)
    
    // With more iterations
    let derivedKey2048 = try PKCS8Encryption.pbkdf2(
        password: password,
        salt: salt,
        iterations: 2048,
        keyLen: keyLen
    )
    
    #expect(derivedKey2048.count == keyLen)
    #expect(derivedKey != derivedKey2048) // Different iterations = different key
}

@Test("Export key files with encryption")
func testExportKeyFilesWithEncryption() throws {
    let key = try ECDSAKeyGenerator.generateP256()
    let passphrase = "filetest"
    let tempDir = FileManager.default.temporaryDirectory
    let basePath = tempDir.appendingPathComponent("test_encrypted_\(UUID().uuidString)").path
    
    // Export with passphrase
    let results = try KeyConverter.exportKey(
        key,
        formats: [.pem, .pkcs8],
        basePath: basePath,
        passphrase: passphrase
    )
    
    // Read and verify PEM file
    if let pemPath = results[.pem] {
        let pemContent = try String(contentsOfFile: pemPath)
        #expect(pemContent.contains("Proc-Type: 4,ENCRYPTED"))
        #expect(pemContent.contains("DEK-Info:"))
        #expect(pemContent.contains("BEGIN EC PRIVATE KEY"))
    }
    
    // Read and verify PKCS8 file
    if let pkcs8Path = results[.pkcs8] {
        let pkcs8Content = try String(contentsOfFile: pkcs8Path)
        #expect(pkcs8Content.contains("BEGIN ENCRYPTED PRIVATE KEY"))
    }
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: basePath + ".pem")
    try? FileManager.default.removeItem(atPath: basePath + ".p8")
}