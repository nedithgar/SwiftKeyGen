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
}