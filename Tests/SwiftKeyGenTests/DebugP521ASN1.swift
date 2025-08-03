import Testing
@testable import SwiftKeyGen
import Foundation
import Crypto

@Test("Debug P521 ASN.1 encoding")
func debugP521ASN1() throws {
    let key = try P521.Signing.PrivateKey()
    
    print("=== P521 Key Details ===")
    print("Private key size: \(key.rawRepresentation.count) bytes")
    print("Public key x963 size: \(key.publicKey.x963Representation.count) bytes")
    
    // Test bit string encoding
    let publicKeyData = key.publicKey.x963Representation
    print("\nPublic key x963 hex: \(publicKeyData.hexEncodedString())")
    
    // Manual ASN.1 bit string encoding
    var bitString = Data([0x03]) // BIT STRING tag
    let dataWithPadding = Data([0x00]) + publicKeyData // No padding bits
    
    // For P521, public key is 133 bytes (0x04 + 66 + 66), plus 1 for padding = 134
    print("Bit string content length: \(dataWithPadding.count)")
    
    if dataWithPadding.count < 128 {
        bitString.append(UInt8(dataWithPadding.count))
    } else {
        // Long form: first byte has high bit set and indicates number of length bytes
        bitString.append(0x81) // High bit + 1 byte for length
        bitString.append(UInt8(dataWithPadding.count))
    }
    bitString.append(dataWithPadding)
    
    print("Bit string total length: \(bitString.count)")
    print("Bit string hex: \(bitString.prefix(10).hexEncodedString())...")
    
    // Now test the context tag
    print("\nContext tag [1] encoding:")
    print("Should encode length: \(bitString.count)")
    
    if bitString.count < 128 {
        print("Using short form: 0xA1 \(String(format: "%02X", bitString.count))")
    } else {
        print("Using long form: 0xA1 0x81 \(String(format: "%02X", bitString.count))")
    }
}