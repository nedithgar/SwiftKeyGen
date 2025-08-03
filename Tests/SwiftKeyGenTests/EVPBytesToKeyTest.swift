import Testing
@testable import SwiftKeyGen
import Foundation
import CommonCrypto

@Test("EVP_BytesToKey validation")
func evpBytesToKeyValidation() throws {
    // Test with known values from OpenSSL
    // openssl enc -aes-128-cbc -pass pass:test123 -S 0102030405060708 -P
    let password = "test123"
    let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    
    let (key, iv) = PEMEncryption.evpBytesToKey(
        password: password,
        salt: salt,
        keyLen: 16,
        ivLen: 16
    )
    
    print("Password: \(password)")
    print("Salt: \(salt.hexEncodedString())")
    print("Derived Key: \(key.hexEncodedString())")
    print("Derived IV: \(iv.hexEncodedString())")
    
    // Expected from OpenSSL:
    // key=647D9C53AFA2B09BCD154FACE8289A98
    // iv =C7AC5BE4BCD574E1E54F4AF9E5748441
    
    print("\nExpected from OpenSSL:")
    print("Key: 647D9C53AFA2B09BCD154FACE8289A98")
    print("IV:  C7AC5BE4BCD574E1E54F4AF9E5748441")
    
    // Let's trace through the algorithm step by step
    print("\n=== Algorithm trace ===")
    
    let passwordData = password.data(using: .utf8)!
    var derived = Data()
    var block = Data()
    
    // First round: MD5(password + salt)
    let round1Input = passwordData + salt
    print("Round 1 input: \(round1Input.hexEncodedString())")
    
    var digest1 = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    round1Input.withUnsafeBytes { bytes in
        _ = CC_MD5(bytes.baseAddress, CC_LONG(round1Input.count), &digest1)
    }
    block = Data(digest1)
    derived.append(block)
    print("Round 1 MD5: \(block.hexEncodedString())")
    
    // Second round: MD5(previous_block + password + salt)
    let round2Input = block + passwordData + salt
    print("\nRound 2 input: \(round2Input.hexEncodedString())")
    
    var digest2 = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    round2Input.withUnsafeBytes { bytes in
        _ = CC_MD5(bytes.baseAddress, CC_LONG(round2Input.count), &digest2)
    }
    block = Data(digest2)
    derived.append(block)
    print("Round 2 MD5: \(block.hexEncodedString())")
    
    print("\nDerived data: \(derived.hexEncodedString())")
    print("Key (first 16): \(derived.prefix(16).hexEncodedString())")
    print("IV (next 16): \(derived.dropFirst(16).prefix(16).hexEncodedString())")
}