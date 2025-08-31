import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("3DES-CBC Unit Tests", .tags(.unit))
struct TripleDESCBCUnitTests {
    @Test("3DES-CBC encryption and decryption")
    func test3DESCBC() throws {
        let testData = Data(repeating: 0x41, count: 24) // 24 bytes
        let key = Data(repeating: 0x42, count: 24) // 24 bytes for 3DES
        let iv = Data(repeating: 0x43, count: 8) // 8 bytes IV for DES
        
        let encrypted = try TripleDESCBC.encrypt(data: testData, key: key, iv: iv)
        let decrypted = try TripleDESCBC.decrypt(data: encrypted, key: key, iv: iv)
        
        #expect(testData == decrypted)
    }

    @Test("3DES-CBC multi-block round trip (5 blocks)")
    func testMultiBlockRoundTrip() throws {
        let blocks = 5
        let plaintext = Data((0..<(blocks * 8)).map { UInt8($0 & 0xFF) })
        let key = Data((0..<24).map { UInt8(($0 * 3 + 7) & 0xFF) }) // pseudo-random pattern
        let iv = Data((0..<8).map { UInt8(0xA0 &+ UInt8($0)) })
        let ciphertext = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: iv)
        #expect(ciphertext.count == plaintext.count)
        // Ciphertext should not trivially equal plaintext
        #expect(ciphertext != plaintext)
        let decrypted = try TripleDESCBC.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test("3DES-CBC empty plaintext returns empty ciphertext")
    func testEmptyPlaintext() throws {
        let key = Data(repeating: 0x11, count: 24)
        let iv = Data(repeating: 0x22, count: 8)
        let ciphertext = try TripleDESCBC.encrypt(data: Data(), key: key, iv: iv)
        #expect(ciphertext.isEmpty)
        let decrypted = try TripleDESCBC.decrypt(data: ciphertext, key: key, iv: iv)
        #expect(decrypted.isEmpty)
    }

    @Test("3DES-CBC deterministic with same key+IV")
    func testDeterministic() throws {
        let key = Data(repeating: 0x7B, count: 24)
        let iv = Data(repeating: 0x55, count: 8)
        let plaintext = Data(repeating: 0xEE, count: 16) // 2 blocks
        let c1 = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: iv)
        let c2 = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: iv)
        #expect(c1 == c2)
        let p1 = try TripleDESCBC.decrypt(data: c1, key: key, iv: iv)
        #expect(p1 == plaintext)
    }

    @Test("3DES-CBC different IV produces different first block")
    func testDifferentIVAltersCiphertext() throws {
        let key = Data(repeating: 0x33, count: 24)
        let iv1 = Data(repeating: 0x10, count: 8)
        var iv2 = iv1
        // Change just one byte of IV
        var mutable = Data(iv2)
        mutable[7] = 0x11
        iv2 = mutable
        let plaintext = Data(repeating: 0x00, count: 16)
        let c1 = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: iv1)
        let c2 = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: iv2)
        #expect(c1.count == c2.count)
        #expect(c1.prefix(8) != c2.prefix(8)) // first block must differ due to different IV
    }

    @Test("3DES-CBC invalid key sizes rejected")
    func testInvalidKeySizes() throws {
        let iv = Data(repeating: 0x01, count: 8)
        let plaintext = Data(repeating: 0x02, count: 8)
        // Valid key size is exactly 24 bytes
        let invalidSizes = [0, 1, 7, 8, 16, 23, 25, 32]
        for size in invalidSizes {
            let badKey = Data(repeating: 0xFF, count: size)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.encrypt(data: plaintext, key: badKey, iv: iv)
            }
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.decrypt(data: plaintext, key: badKey, iv: iv)
            }
        }
    }

    @Test("3DES-CBC invalid IV sizes rejected")
    func testInvalidIVSizes() throws {
        let key = Data(repeating: 0xAB, count: 24)
        let plaintext = Data(repeating: 0xCD, count: 8)
        let invalidIVLengths = [0, 1, 7, 9, 15, 16]
        for len in invalidIVLengths {
            let badIV = Data(repeating: 0x00, count: len)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.encrypt(data: plaintext, key: key, iv: badIV)
            }
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.decrypt(data: plaintext, key: key, iv: badIV)
            }
        }
    }

    @Test("3DES-CBC rejects non-multiple-of-block-size plaintext")
    func testInvalidPlaintextLengths() throws {
        let key = Data(repeating: 0x5A, count: 24)
        let iv = Data(repeating: 0xC3, count: 8)
        let invalidLengths = [1, 2, 3, 4, 5, 6, 7, 9, 10, 15]
        for len in invalidLengths {
            let data = Data(repeating: 0x00, count: len)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.encrypt(data: data, key: key, iv: iv)
            }
        }
    }

    @Test("3DES-CBC rejects non-multiple-of-block-size ciphertext on decrypt")
    func testInvalidCiphertextLengths() throws {
        let key = Data(repeating: 0x9E, count: 24)
        let iv = Data(repeating: 0x17, count: 8)
        let invalidLengths = [1, 2, 3, 4, 5, 6, 7, 9, 10, 15]
        for len in invalidLengths {
            let data = Data(repeating: 0x00, count: len)
            #expect(throws: SSHKeyError.invalidKeyData) {
                _ = try TripleDESCBC.decrypt(data: data, key: key, iv: iv)
            }
        }
    }
}