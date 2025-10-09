import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("KeyType enum contract tests", .tags(.unit))
struct KeyTypeUnitTests {
    // MARK: - Raw value stability
    @Test("Raw values match OpenSSH algorithm identifiers")
    func testRawValues() {
        #expect(KeyType.rsa.rawValue == "ssh-rsa")
        #expect(KeyType.ed25519.rawValue == "ssh-ed25519")
        #expect(KeyType.ecdsa256.rawValue == "ecdsa-sha2-nistp256")
        #expect(KeyType.ecdsa384.rawValue == "ecdsa-sha2-nistp384")
        #expect(KeyType.ecdsa521.rawValue == "ecdsa-sha2-nistp521")
    }

    // MARK: - Default bit sizing policy
    @Test("Default bit sizes reflect security policy")
    func testDefaultBits() {
        #expect(KeyType.rsa.defaultBits == 3072) // policy: strong default over 2048
        #expect(KeyType.ed25519.defaultBits == 256) // curve size label
        #expect(KeyType.ecdsa256.defaultBits == 256)
        #expect(KeyType.ecdsa384.defaultBits == 384)
        #expect(KeyType.ecdsa521.defaultBits == 521)
    }

    // MARK: - Algorithm grouping / human readable names
    @Test("Algorithm names group ECDSA variants together")
    func testAlgorithmNames() {
        #expect(KeyType.rsa.algorithmName == "RSA")
        #expect(KeyType.ed25519.algorithmName == "ED25519")
        #expect(KeyType.ecdsa256.algorithmName == "ECDSA")
        #expect(KeyType.ecdsa384.algorithmName == "ECDSA")
        #expect(KeyType.ecdsa521.algorithmName == "ECDSA")
    }

    // MARK: - CaseIterable integrity
    @Test("AllCases contains each case exactly once")
    func testAllCasesCompleteness() {
        let all = KeyType.allCases
        // Expected stable count (update if new algorithms added intentionally)
        #expect(all.count == 5)
        // Uniqueness check (defensive; enum cases should be unique)
        #expect(Set(all).count == all.count)
        // Optional explicit membership ordering (acts like a light snapshot)
        #expect(all == [.rsa, .ed25519, .ecdsa256, .ecdsa384, .ecdsa521])
    }
}
