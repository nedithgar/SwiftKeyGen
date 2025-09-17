import Testing
import Foundation
import _CryptoExtras
@testable import SwiftKeyGen

@Suite("ASN1 Parser Integration", .tags(.integration, .rsa))
struct ASN1ParserTests {
    
    @Test func parseRSAPublicKey() throws {
        // Generate a test RSA key
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let publicKey = privateKey.publicKey
        let derData = publicKey.derRepresentation
        
        print("DER data length: \(derData.count)")
        print("First few bytes: \(derData.prefix(20).map { String(format: "%02x", $0) }.joined(separator: " "))")
        
        // Try to parse it
        var parser = ASN1Parser(data: derData)
        do {
            let (modulus, exponent) = try parser.parseRSAPublicKey()
            print("Modulus length: \(modulus.count)")
            print("Exponent length: \(exponent.count)")
            print("Exponent: \(exponent.map { String(format: "%02x", $0) }.joined(separator: " "))")
            
            // RSA-2048 should have ~256 byte modulus
            #expect(modulus.count >= 255 && modulus.count <= 257)
            // Common exponent is 65537 (0x010001)
            #expect(exponent == Data([0x01, 0x00, 0x01]))
        } catch {
            print("Parse error: \(error)")
            throw error
        }
    }
}
