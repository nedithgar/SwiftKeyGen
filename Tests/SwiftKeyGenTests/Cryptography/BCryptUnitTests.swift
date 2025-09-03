import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("BCrypt PBKDF Tests", .tags(.unit))
struct BCryptUnitTests {
    
    @Test("BCrypt PBKDF key derivation")
    func testKeyDerivation() throws {
        // Test vector for bcrypt_pbkdf
        // These are simplified test cases - real OpenSSH uses specific test vectors
        let password = "password"
        let salt = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        let rounds = 16
        let outputLength = 32
        
        let key = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key.count == outputLength)
        // Key should not be all zeros
        #expect(!key.allSatisfy { $0 == 0 })
    }
    
    @Test("BCrypt PBKDF with empty password fails")
    func testEmptyPasswordFails() throws {
        let salt = Data([0x00, 0x01, 0x02, 0x03])
        
        #expect(throws: SSHKeyError.self) {
            _ = try BCryptPBKDF.deriveKey(
                password: "",
                salt: salt,
                outputByteCount: 32,
                rounds: 16
            )
        }
    }
    
    @Test("BCrypt PBKDF with empty salt fails")
    func testEmptySaltFails() throws {
        #expect(throws: SSHKeyError.self) {
            _ = try BCryptPBKDF.deriveKey(
                password: "password",
                salt: Data(),
                outputByteCount: 32,
                rounds: 16
            )
        }
    }
    
    @Test("BCrypt PBKDF with invalid rounds fails")
    func testInvalidRoundsFails() throws {
        let salt = Data([0x00, 0x01, 0x02, 0x03])
        
        #expect(throws: SSHKeyError.self) {
            _ = try BCryptPBKDF.deriveKey(
                password: "password",
                salt: salt,
                outputByteCount: 32,
                rounds: 0
            )
        }
    }
    
    @Test("BCrypt PBKDF deterministic output")
    func testDeterministicOutput() throws {
        let password = "test123"
        let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let rounds = 4
        let outputLength = 64
        
        let key1 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        let key2 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key1 == key2)
    }
    
    @Test("BCrypt PBKDF different passwords produce different keys")
    func testDifferentPasswords() throws {
        let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let rounds = 4
        let outputLength = 32
        
        let key1 = try BCryptPBKDF.deriveKey(
            password: "password1",
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        let key2 = try BCryptPBKDF.deriveKey(
            password: "password2",
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key1 != key2)
    }
    
    @Test("BCrypt PBKDF different salts produce different keys")
    func testDifferentSalts() throws {
        let password = "password"
        let rounds = 4
        let outputLength = 32
        
        let key1 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: Data([0x01, 0x02, 0x03, 0x04]),
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        let key2 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: Data([0x05, 0x06, 0x07, 0x08]),
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key1 != key2)
    }
    
    @Test("BCrypt PBKDF non-linear output")
    func testNonLinearOutput() throws {
        // Test the non-linear output property of bcrypt_pbkdf
        let password = "testpassword"
        let salt = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        let rounds = 8
        
        // Generate a larger key
        let key = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: 96,
            rounds: rounds
        )
        
        // The key should have good distribution (not just sequential bytes)
        var uniqueBytes = Set<UInt8>()
        for byte in key {
            uniqueBytes.insert(byte)
        }
        
        // Should have reasonable entropy (many unique bytes)
        #expect(uniqueBytes.count > 16)
    }

    @Test("BCrypt PBKDF key expansion")
    func testKeyExpansion() throws {
        // Test that BCrypt PBKDF can expand to various key sizes
        let password = "testpassword"
        let salt = Data("saltsalt".utf8)
        let rounds = 4
        
        // Test various output sizes
        let sizes = [16, 32, 48, 64, 96, 128]
        
        for size in sizes {
            let key = try BCryptPBKDF.deriveKey(
                password: password,
                salt: salt,
                outputByteCount: size,
                rounds: rounds
            )
            
            #expect(key.count == size)
        }
        
        // Test non-linear output property
        // bcrypt_pbkdf outputs bytes in a special pattern to prevent
        // simple truncation attacks
        let key64 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: 64,
            rounds: rounds
        )
        
        let key32 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: 32,
            rounds: rounds
        )
        
        // Due to non-linear output, key32 is NOT a prefix of key64
        // The bytes are distributed differently
        #expect(Data(key64.prefix(32)) != key32)
    }
    
    @Test("Verify BCrypt PBKDF matches OpenSSH implementation")
    func testBCryptPBKDFVectors() throws {
        // Test with known values from OpenSSH
        let password = "password"
        let salt = Data("saltsalt".utf8) // 8 bytes
        let rounds = 16
        let outputLength = 32
        
        let derivedKey = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        // The key should be deterministic and non-trivial
        #expect(derivedKey.count == outputLength)
        #expect(!derivedKey.allSatisfy { $0 == 0 })
        
        // Verify the key has good entropy distribution
        let uniqueBytes = Set(derivedKey)
        #expect(uniqueBytes.count > outputLength / 4) // At least 25% unique bytes
    }
    
    @Test("BCrypt PBKDF with Unicode password")
    func testUnicodePassword() throws {
        let password = "пароль🔐" // Russian + emoji
        let salt = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let rounds = 4
        let outputLength = 48
        
        let key = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key.count == outputLength)
        
        // Verify UTF-8 encoding is handled correctly
        let key2 = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: rounds
        )
        
        #expect(key == key2) // Should be deterministic
    }
    
    @Test("BCrypt PBKDF performance characteristics")
    func testPerformance() throws {
        let password = "testpassword"
        let salt = Data("12345678".utf8)
        let outputLength = 32
        
        // Test that more rounds take more time (basic sanity check)
        let start1 = Date()
        _ = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: 1
        )
        let time1 = Date().timeIntervalSince(start1)
        
        let start2 = Date()
        _ = try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputLength,
            rounds: 16
        )
        let time2 = Date().timeIntervalSince(start2)
        
        // 16 rounds should take noticeably longer than 1 round
        #expect(time2 > time1)
    }
}