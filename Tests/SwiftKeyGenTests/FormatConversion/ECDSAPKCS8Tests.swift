import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Test("ECDSA PKCS#8 Export")
func testECDSAPKCS8Export() throws {
    // Generate ECDSA keys for each curve
    let p256Key = try ECDSAKeyGenerator.generateP256(comment: "test-p256")
    let p384Key = try ECDSAKeyGenerator.generateP384(comment: "test-p384")
    let p521Key = try ECDSAKeyGenerator.generateP521(comment: "test-p521")
    
    // Test P256 PKCS#8 export
    let p256PEM = p256Key.pemRepresentation
    #expect(p256PEM.contains("-----BEGIN PRIVATE KEY-----"))
    #expect(p256PEM.contains("-----END PRIVATE KEY-----"))
    #expect(!p256PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    
    // Test P384 PKCS#8 export
    let p384PEM = p384Key.pemRepresentation
    #expect(p384PEM.contains("-----BEGIN PRIVATE KEY-----"))
    #expect(p384PEM.contains("-----END PRIVATE KEY-----"))
    #expect(!p384PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
    
    // Test P521 PKCS#8 export
    let p521PEM = p521Key.pemRepresentation
    #expect(p521PEM.contains("-----BEGIN PRIVATE KEY-----"))
    #expect(p521PEM.contains("-----END PRIVATE KEY-----"))
    #expect(!p521PEM.contains("-----BEGIN EC PRIVATE KEY-----"))
}

@Test("ECDSA PKCS#8 Export via KeyConverter")
func testECDSAPKCS8ExportViaConverter() throws {
    // Generate test key
    let key = try ECDSAKeyGenerator.generateP256(comment: "test-converter")
    
    // Test toPEM (returns SEC1 format for ECDSA)
    let pem = try KeyConverter.toPEM(key: key)
    #expect(pem.contains("-----BEGIN EC PRIVATE KEY-----"))
    #expect(pem.contains("-----END EC PRIVATE KEY-----"))
    
    // Test toPKCS8
    let pkcs8Data = try KeyConverter.toPKCS8(key: key)
    let pkcs8String = String(data: pkcs8Data, encoding: .utf8)!
    #expect(pkcs8String.contains("-----BEGIN PRIVATE KEY-----"))
    #expect(pkcs8String.contains("-----END PRIVATE KEY-----"))
}

@Test("ECDSA PKCS#8 Round-trip")
func testECDSAPKCS8RoundTrip() throws {
    // Generate a test key
    let originalKey = try ECDSAKeyGenerator.generateP256(comment: "round-trip-test")
    
    // Export to PKCS#8
    let pkcs8PEM = originalKey.pemRepresentation
    
    // Try to parse it back - this verifies it's valid PKCS#8
    #expect(throws: Never.self) {
        // We should be able to parse it as a P256 private key
        _ = try P256.Signing.PrivateKey(pemRepresentation: pkcs8PEM)
    }
    
    // Also verify we can parse it using PEMParser
    let parsedKey = try PEMParser.parseECDSAPrivateKey(pkcs8PEM)
    
    // Verify the public key data matches (not strings, since comment is lost)
    let originalPublicData = originalKey.publicKeyData()
    let parsedPublicData = parsedKey.publicKeyData()
    #expect(originalPublicData == parsedPublicData)
}

@Test("ECDSA Format Detection")
func testECDSAFormatDetection() throws {
    let key = try ECDSAKeyGenerator.generateP384()
    let pkcs8PEM = key.pemRepresentation
    
    // Verify format detection recognizes PKCS#8
    let detectedFormat = try KeyConversionManager.detectFormat(from: pkcs8PEM)
    #expect(detectedFormat == .pkcs8)
}