import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Test("ECDSA SEC1/RFC5915 Export (PEM format)")
func testECDSASEC1Export() throws {
    // Generate ECDSA keys for each curve
    let p256Key = try ECDSAKeyGenerator.generateP256(comment: "test-p256")
    let p384Key = try ECDSAKeyGenerator.generateP384(comment: "test-p384")
    let p521Key = try ECDSAKeyGenerator.generateP521(comment: "test-p521")
    
    // Test P256 SEC1 export
    let p256PEM = p256Key.sec1PEMRepresentation
    #expect(p256PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(p256PEM.contains("-----END EC PRIVATE KEY-----"))
    #expect(!p256PEM.contains("-----BEGIN PRIVATE KEY-----"))
    
    // Test P384 SEC1 export
    let p384PEM = p384Key.sec1PEMRepresentation
    #expect(p384PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(p384PEM.contains("-----END EC PRIVATE KEY-----"))
    #expect(!p384PEM.contains("-----BEGIN PRIVATE KEY-----"))
    
    // Test P521 SEC1 export
    let p521PEM = p521Key.sec1PEMRepresentation
    #expect(p521PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(p521PEM.contains("-----END EC PRIVATE KEY-----"))
    #expect(!p521PEM.contains("-----BEGIN PRIVATE KEY-----"))
}

@Test("ECDSA Format Compatibility - PEM vs PKCS8")
func testECDSAFormatCompatibility() throws {
    let key = try ECDSAKeyGenerator.generateP256(comment: "format-test")
    
    // Get both formats
    let sec1PEM = key.sec1PEMRepresentation
    let pkcs8PEM = key.pkcs8PEMRepresentation
    
    // Verify they are different formats
    #expect(sec1PEM.contains("BEGIN EC PRIVATE KEY"))
    #expect(pkcs8PEM.contains("BEGIN PRIVATE KEY"))
    #expect(sec1PEM != pkcs8PEM)
}

@Test("ECDSA KeyConverter Format Selection")
func testECDSAKeyConverterFormats() throws {
    let key = try ECDSAKeyGenerator.generateP384()
    
    // Test toPEM returns SEC1 format
    let pemString = try KeyConverter.toPEM(key: key)
    #expect(pemString.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(pemString.contains("-----END EC PRIVATE KEY-----"))
    
    // Test toPKCS8 returns PKCS#8 format
    let pkcs8Data = try KeyConverter.toPKCS8(key: key)
    let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
    #expect(pkcs8String.contains("-----BEGIN PRIVATE KEY-----"))
    #expect(pkcs8String.contains("-----END PRIVATE KEY-----"))
}

@Test("ECDSA Export Formats Match ssh-keygen")
func testECDSAExportFormatsMatchSSHKeygen() throws {
    let key = try ECDSAKeyGenerator.generateP521()
    
    // Export with different formats
    let formats: Set<KeyFormat> = [.pem, .pkcs8]
    let tempDir = FileManager.default.temporaryDirectory
    let basePath = tempDir.appendingPathComponent("test_ecdsa_\(UUID().uuidString)").path
    
    let results = try KeyConverter.exportKey(key, formats: formats, basePath: basePath)
    
    // Read PEM format file
    if let pemPath = results[.pem] {
        let pemContent = try String(contentsOfFile: pemPath)
        #expect(pemContent.contains("BEGIN EC PRIVATE KEY"))
    } else {
        Issue.record("PEM format not exported")
    }
    
    // Read PKCS8 format file
    if let pkcs8Path = results[.pkcs8] {
        let pkcs8Content = try String(contentsOfFile: pkcs8Path)
        #expect(pkcs8Content.contains("BEGIN PRIVATE KEY"))
    } else {
        Issue.record("PKCS8 format not exported")
    }
    
    // Cleanup
    try? FileManager.default.removeItem(atPath: basePath + ".pem")
    try? FileManager.default.removeItem(atPath: basePath + ".p8")
}