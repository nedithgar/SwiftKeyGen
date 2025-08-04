import Testing
import Foundation
import BigInt
@testable import SwiftKeyGen

@Suite("RSA Bit Size Test")
struct RSABitSizeTest {
    
    @Test("Check RSA key bit size calculation")
    func testRSABitSize() throws {
        // Generate multiple RSA keys and check their sizes
        for _ in 0..<5 {
            let rsaKey = try SwiftKeyGen.generateKey(type: .rsa, bits: 1024, comment: "test") as! RSAKey
            
            // Get public key components
            let publicKeyData = rsaKey.publicKeyData()
            var decoder = SSHDecoder(data: publicKeyData)
            _ = try decoder.decodeString() // Skip type
            let e = try decoder.decodeData()
            let n = try decoder.decodeData()
            
            // Create BigUInt from modulus
            let modulus = BigUInt(n)
            let bitWidth = modulus.bitWidth
            let byteSize = (bitWidth + 7) / 8
            
            print("Key modulus info:")
            print("  Modulus data length: \(n.count) bytes")
            print("  First byte: 0x\(String(format: "%02x", n[0]))")
            print("  BigUInt bitWidth: \(bitWidth)")
            print("  Calculated byte size: \(byteSize)")
            print("  Expected: 128 bytes (1024 bits)")
            
            // The issue: if the modulus has high bit set, SSH adds a leading zero
            // This makes the data 129 bytes, but the key is still 1024 bits
            if n[0] == 0x00 && n.count == 129 {
                print("  -> SSH added leading zero byte for positive representation")
                let actualModulus = n.dropFirst()
                let actualBigUInt = BigUInt(actualModulus)
                print("  -> Actual bitWidth: \(actualBigUInt.bitWidth)")
                print("  -> Actual byte size: \((actualBigUInt.bitWidth + 7) / 8)")
            }
            print("")
        }
    }
}