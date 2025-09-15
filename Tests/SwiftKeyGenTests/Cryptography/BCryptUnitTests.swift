import Testing
@testable import SwiftKeyGen
import Foundation

@Suite("BCrypt PBKDF Unit Tests", .tags(.unit))
struct BCryptUnitTests {
    // MARK: Shared Fixtures
    private enum Fixture {
        static let defaultPassword = "password"
        static let altPassword1 = "password1"
        static let altPassword2 = "password2"
        static let unicodePassword = "пароль🔐" // Russian + emoji
        static let eightByteSalt = Data("saltsalt".utf8) // 8 bytes as used commonly in vectors
        static let smallSaltA = Data([0x01, 0x02, 0x03, 0x04])
        static let smallSaltB = Data([0x05, 0x06, 0x07, 0x08])
        static let fullSaltSeq = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        static let distributionSalt = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
    }

    // MARK: Helper
    @discardableResult
    private static func derive(
        password: String,
        salt: Data,
        length: Int,
        rounds: Int
    ) throws -> Data {
        try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: length,
            rounds: rounds
        )
    }

    // MARK: - Valid Derivation Scenarios
    @Suite("Valid Derivations")
    struct ValidDerivationTests {
        @Test("Derives key with standard parameters")
        func derivesKeyWithStandardInputs() throws {
            let length = 32
            let key = try derive(
                password: Fixture.defaultPassword,
                salt: Fixture.fullSaltSeq,
                length: length,
                rounds: 16
            )
            #expect(key.count == length)
            #expect(!key.allSatisfy { $0 == 0 })
        }

        @Test("Deterministic derivation for identical inputs")
        func deterministicOutput() throws {
            let length = 64
            let rounds = 4
            let key1 = try derive(password: "test123", salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            let key2 = try derive(password: "test123", salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            #expect(key1 == key2)
        }

        @Test("Different passwords yield different keys")
        func differentPasswords() throws {
            let length = 32
            let rounds = 4
            let key1 = try derive(password: Fixture.altPassword1, salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            let key2 = try derive(password: Fixture.altPassword2, salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            #expect(key1 != key2)
        }

        @Test("Different salts yield different keys")
        func differentSalts() throws {
            let length = 32
            let rounds = 4
            let key1 = try derive(password: Fixture.defaultPassword, salt: Fixture.smallSaltA, length: length, rounds: rounds)
            let key2 = try derive(password: Fixture.defaultPassword, salt: Fixture.smallSaltB, length: length, rounds: rounds)
            #expect(key1 != key2)
        }

        @Test("Unicode password supported & deterministic")
        func unicodePasswordDeterministic() throws {
            let length = 48
            let rounds = 4
            let key1 = try derive(password: Fixture.unicodePassword, salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            let key2 = try derive(password: Fixture.unicodePassword, salt: Fixture.fullSaltSeq, length: length, rounds: rounds)
            #expect(key1.count == length)
            #expect(key1 == key2)
        }

        @Test("Expands to multiple output sizes & non-linear distribution")
        func keyExpansionAndNonLinearDistribution() throws {
            let password = "testpassword"
            let salt = Fixture.eightByteSalt
            let rounds = 4
            let sizes = [16, 32, 48, 64, 96, 128]
            for size in sizes {
                let key = try derive(password: password, salt: salt, length: size, rounds: rounds)
                #expect(key.count == size)
            }
            // Non-linear: shorter output is not a simple prefix of longer output
            let key64 = try derive(password: password, salt: salt, length: 64, rounds: rounds)
            let key32 = try derive(password: password, salt: salt, length: 32, rounds: rounds)
            #expect(Data(key64.prefix(32)) != key32)
        }
    }

    // MARK: - Parameter Validation
    @Suite("Parameter Validation")
    struct ParameterValidationTests {
        @Test("Empty password rejected")
        func emptyPasswordFails() throws {
            #expect(throws: SSHKeyError.self) {
                _ = try derive(password: "", salt: Data([0x00, 0x01, 0x02, 0x03]), length: 32, rounds: 16)
            }
        }

        @Test("Empty salt rejected")
        func emptySaltFails() throws {
            #expect(throws: SSHKeyError.self) {
                _ = try derive(password: Fixture.defaultPassword, salt: Data(), length: 32, rounds: 16)
            }
        }

        @Test("Rounds must be positive")
        func invalidRoundsFails() throws {
            #expect(throws: SSHKeyError.self) {
                _ = try derive(password: Fixture.defaultPassword, salt: Fixture.smallSaltA, length: 32, rounds: 0)
            }
        }
    }

    // MARK: - Output Characteristics
    @Suite("Output Characteristics")
    struct OutputCharacteristicsTests {
        @Test("Non-linear output distribution has entropy")
        func nonLinearOutputEntropy() throws {
            let key = try derive(
                password: "testpassword",
                salt: Fixture.distributionSalt,
                length: 96,
                rounds: 8
            )
            let uniqueCount = Set(key).count
            #expect(uniqueCount > 16)
        }

        @Test("Deterministic & non-trivial output (OpenSSH style vector sanity)")
        func vectorSanity() throws {
            // NOTE: This is a sanity check rather than a strict vector comparison.
            // For true vector validation, inject canonical reference outputs.
            let length = 32
            let derived = try derive(
                password: Fixture.defaultPassword,
                salt: Fixture.eightByteSalt,
                length: length,
                rounds: 16
            )
            #expect(derived.count == length)
            #expect(!derived.allSatisfy { $0 == 0 })
            #expect(Set(derived).count > length / 4) // >25% uniqueness
        }
    }

    // MARK: - Performance
    @Test("Rounds scaling impacts derivation time", .tags(.performance))
    func performanceScaling() throws {
        // Heuristic: higher rounds should cost more time. Not a micro-benchmark.
        let basePassword = "testpassword"
        let salt = Data("12345678".utf8)
        let length = 32

        let t1Start = Date()
        _ = try Self.derive(password: basePassword, salt: salt, length: length, rounds: 1)
        let t1 = Date().timeIntervalSince(t1Start)

        let t2Start = Date()
        _ = try Self.derive(password: basePassword, salt: salt, length: length, rounds: 16)
        let t2 = Date().timeIntervalSince(t2Start)

        // Allow occasional equal time due to timer granularity but expect strictly greater normally.
        #expect(t2 >= t1)
    }
}
