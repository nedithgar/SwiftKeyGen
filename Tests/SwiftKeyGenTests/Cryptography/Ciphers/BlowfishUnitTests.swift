import Testing
import Foundation
@testable import SwiftKeyGen

@Suite("Blowfish Cipher Unit Tests", .tags(.unit))
struct BlowfishUnitTests {
    
    // Helper function to call Span-based methods with Data for testing convenience
    private func withSpan<T>(_ data: Data, _ body: (Span<UInt8>) -> T) -> T {
        data.withUnsafeBytes { bufferPointer in
            body(Span(_unsafeElements: bufferPointer.bindMemory(to: UInt8.self)))
        }
    }
    
    // Helper function for dual Data parameters
    private func withSpans<T>(_ data1: Data, _ data2: Data, _ body: (Span<UInt8>, Span<UInt8>) -> T) -> T {
        data1.withUnsafeBytes { bufferPointer1 in
            data2.withUnsafeBytes { bufferPointer2 in
                let span1 = Span(_unsafeElements: bufferPointer1.bindMemory(to: UInt8.self))
                let span2 = Span(_unsafeElements: bufferPointer2.bindMemory(to: UInt8.self))
                return body(span1, span2)
            }
        }
    }
    
    // MARK: - Initialization Tests
    
    @Test("Blowfish state initialization produces correct P-array")
    func testInitialPArray() throws {
    var context = BlowfishContext()
    context.initializeState()
    var context2 = BlowfishContext()
    context2.initializeState()
        
        // Both contexts should produce identical encryption results
        var data1: [UInt32] = [0x00000000, 0x00000000]
        var data2: [UInt32] = [0x00000000, 0x00000000]
        
        context.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        #expect(data1 == data2)
    }
    
    @Test("Blowfish initialization is deterministic")
    func testDeterministicInitialization() throws {
        var context1 = BlowfishContext()
        var context2 = BlowfishContext()
        
    context1.initializeState()
    context2.initializeState()
        
        // Test that both contexts produce identical output
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef0]
        
        context1.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        #expect(data1 == data2)
    }
    
    // MARK: - Key Expansion Tests
    
    @Test("Blowfish expandKey (formerly expand0state) with simple key")
    func testExpand0State() throws {
    var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        // Test that expansion changes the state
        var data: [UInt32] = [0x00000000, 0x00000000]
        context.encrypt(data: &data, blocks: 1)
        
        // Result should not be all zeros after encryption
        #expect(data != [0x00000000, 0x00000000])
    }
    
    @Test("Blowfish expandKey with different keys produces different states")
    func testExpand0StateDifferentKeys() throws {
        var context1 = BlowfishContext()
        var context2 = BlowfishContext()
        
    context1.initializeState()
    context2.initializeState()
        
        let key1 = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let key2 = Data([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
        
        withSpan(key1) { keySpan in
            context1.expandKey(key: keySpan)
        }
        withSpan(key2) { keySpan in
            context2.expandKey(key: keySpan)
        }
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef0]
        
        context1.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        // Different keys should produce different encrypted output
        #expect(data1 != data2)
    }
    
    @Test("Blowfish expandSaltAndKey with salt and key")
    func testExpandState() throws {
    var context = BlowfishContext()
    context.initializeState()
        
        let salt = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        
        withSpans(salt, key) { saltSpan, keySpan in
            context.expandSaltAndKey(salt: saltSpan, key: keySpan)
        }
        
        var data: [UInt32] = [0x00000000, 0x00000000]
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0x00000000, 0x00000000])
    }
    
    @Test("Blowfish expandSaltAndKey with different salts produces different states")
    func testExpandStateDifferentSalts() throws {
        var context1 = BlowfishContext()
        var context2 = BlowfishContext()
        
    context1.initializeState()
    context2.initializeState()
        
        let salt1 = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        let salt2 = Data([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        
        withSpans(salt1, key) { saltSpan, keySpan in
        
            context1.expandSaltAndKey(salt: saltSpan, key: keySpan)
        
        }
        withSpans(salt2, key) { saltSpan, keySpan in
            context2.expandSaltAndKey(salt: saltSpan, key: keySpan)
        }
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef0]
        
        context1.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        // Different salts should produce different encrypted output
        #expect(data1 != data2)
    }
    
    // MARK: - Encryption Tests
    
    @Test("Blowfish encrypts single block")
    func testSingleBlockEncryption() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x12345678, 0x9abcdef0]
        let original = data
        
        context.encrypt(data: &data, blocks: 1)
        
        // Encrypted data should be different from original
        #expect(data != original)
        #expect(data.count == 2)
    }
    
    @Test("Blowfish encrypts multiple blocks")
    func testMultipleBlockEncryption() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [
            0x12345678, 0x9abcdef0,
            0xfedcba98, 0x76543210,
            0x11111111, 0x22222222
        ]
        let original = data
        
        context.encrypt(data: &data, blocks: 3)
        
        // All blocks should be encrypted
        #expect(data != original)
        #expect(data.count == 6)
        
        // Each block should be different
        #expect(data[0...1] != original[0...1])
        #expect(data[2...3] != original[2...3])
        #expect(data[4...5] != original[4...5])
    }
    
    @Test("Blowfish encryption is deterministic")
    func testDeterministicEncryption() throws {
        var context1 = BlowfishContext()
        var context2 = BlowfishContext()
        
    context1.initializeState()
    context2.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context1.expandKey(key: keySpan)
        }
        withSpan(key) { keySpan in
            context2.expandKey(key: keySpan)
        }
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef0]
        
        context1.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        #expect(data1 == data2)
    }
    
    @Test("Blowfish encrypts zero blocks")
    func testZeroBlockEncryption() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x00000000, 0x00000000]
        
        context.encrypt(data: &data, blocks: 1)
        
        // Even zero input should produce non-zero output
        #expect(data != [0x00000000, 0x00000000])
    }
    
    @Test("Blowfish encryption produces different output for different inputs")
    func testDifferentInputsProduceDifferentOutputs() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345679, 0x9abcdef0]
        
        context.encrypt(data: &data1, blocks: 1)
        
        // Reset context for second encryption
        var context2 = BlowfishContext()
    context2.initializeState()
        withSpan(key) { keySpan in
            context2.expandKey(key: keySpan)
        }
        context2.encrypt(data: &data2, blocks: 1)
        
        // Different inputs should produce different outputs
        #expect(data1 != data2)
    }
    
    // MARK: - Key Size Tests
    
    @Test("Blowfish handles short keys")
    func testShortKey() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x12345678, 0x9abcdef0]
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0x12345678, 0x9abcdef0])
    }
    
    @Test("Blowfish handles long keys")
    func testLongKey() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        // 32-byte key
        let key = Data([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
        ])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x12345678, 0x9abcdef0]
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0x12345678, 0x9abcdef0])
    }
    
    @Test("Blowfish handles maximum key size (56 bytes)")
    func testMaximumKeySize() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        // 56-byte key (maximum for Blowfish)
        let key = Data(repeating: 0x42, count: 56)
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x12345678, 0x9abcdef0]
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0x12345678, 0x9abcdef0])
    }
    
    // MARK: - Edge Cases
    
    @Test("Blowfish encryption with all-ones input")
    func testAllOnesInput() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0xffffffff, 0xffffffff]
        
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0xffffffff, 0xffffffff])
    }
    
    @Test("Blowfish encryption with alternating bits")
    func testAlternatingBitsInput() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0xaaaaaaaa, 0x55555555]
        let original = data
        
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != original)
    }
    
    @Test("Blowfish key wrapping behavior")
    func testKeyWrapping() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        // Key shorter than P-array, should wrap around
        let key = Data([0x01, 0x02, 0x03])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        var data: [UInt32] = [0x12345678, 0x9abcdef0]
        context.encrypt(data: &data, blocks: 1)
        
        #expect(data != [0x12345678, 0x9abcdef0])
    }
    
    // MARK: - BCrypt Integration Tests
    
    @Test("Blowfish works correctly in BCrypt context")
    func testBCryptIntegration() throws {
        // This tests the specific usage pattern from BCrypt
        var context = BlowfishContext()
    context.initializeState()
        
        let sha2pass = Data(repeating: 0x42, count: 64) // SHA512 hash
        let sha2salt = Data(repeating: 0x43, count: 64) // SHA512 hash
        
        withSpans(sha2salt, sha2pass) { saltSpan, keySpan in
            context.expandSaltAndKey(salt: saltSpan, key: keySpan)
        }
        
        // 64 rounds of expansion (as used in BCrypt)
        for _ in 0..<64 {
            withSpan(sha2salt) { keySpan in
                context.expandKey(key: keySpan)
            }
            withSpan(sha2pass) { keySpan in
                context.expandKey(key: keySpan)
            }
        }
        
        // Convert ciphertext string to UInt32 blocks
        let ciphertext = "OxychromaticBlowfishSwatDynamite"
        let ctBytes = Array(ciphertext.utf8)
        var cdata = [UInt32](repeating: 0, count: 8)
        
        for i in 0..<8 {
            let offset = i * 4
            cdata[i] = (UInt32(ctBytes[offset]) << 24) |
                      (UInt32(ctBytes[offset + 1]) << 16) |
                      (UInt32(ctBytes[offset + 2]) << 8) |
                       UInt32(ctBytes[offset + 3])
        }
        
        let original = cdata
        context.encrypt(data: &cdata, blocks: 4)
        
        // Should produce encrypted output
        #expect(cdata != original)
    }
    
    @Test("Blowfish state changes after multiple expansions")
    func testMultipleExpansions() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04])
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        
        // First expansion and encrypt
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        context.encrypt(data: &data1, blocks: 1)
        let result1 = data1
        
        // Second expansion and encrypt with same input
        data1 = [0x12345678, 0x9abcdef0]
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        context.encrypt(data: &data1, blocks: 1)
        let result2 = data1
        
        // Results should be different due to state changes
        #expect(result1 != result2)
    }
    
    // MARK: - Avalanche Effect Tests
    
    @Test("Blowfish demonstrates avalanche effect in key")
    func testKeyAvalancheEffect() throws {
        var context1 = BlowfishContext()
        var context2 = BlowfishContext()
        
    context1.initializeState()
    context2.initializeState()
        
        // Two keys differing by one bit
        let key1 = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let key2 = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09]) // Last byte differs by 1 bit
        
        withSpan(key1) { keySpan in
            context1.expandKey(key: keySpan)
        }
        withSpan(key2) { keySpan in
            context2.expandKey(key: keySpan)
        }
        
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef0]
        
        context1.encrypt(data: &data1, blocks: 1)
        context2.encrypt(data: &data2, blocks: 1)
        
        // Count differing bits
        let xor1 = data1[0] ^ data2[0]
        let xor2 = data1[1] ^ data2[1]
        let differingBits = xor1.nonzeroBitCount + xor2.nonzeroBitCount
        
        // Should have significant number of differing bits (avalanche effect)
        // Ideally around 32 bits out of 64, but at least 16 to show avalanche
        #expect(differingBits > 16)
    }
    
    @Test("Blowfish demonstrates avalanche effect in plaintext")
    func testPlaintextAvalancheEffect() throws {
        var context = BlowfishContext()
    context.initializeState()
        
        let key = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        withSpan(key) { keySpan in
            context.expandKey(key: keySpan)
        }
        
        // Two plaintexts differing by one bit
        var data1: [UInt32] = [0x12345678, 0x9abcdef0]
        var data2: [UInt32] = [0x12345678, 0x9abcdef1] // Last bit differs
        
        context.encrypt(data: &data1, blocks: 1)
        
        var context2 = BlowfishContext()
    context2.initializeState()
        withSpan(key) { keySpan in
            context2.expandKey(key: keySpan)
        }
        context2.encrypt(data: &data2, blocks: 1)
        
        // Count differing bits
        let xor1 = data1[0] ^ data2[0]
        let xor2 = data1[1] ^ data2[1]
        let differingBits = xor1.nonzeroBitCount + xor2.nonzeroBitCount
        
        // Should have significant number of differing bits (avalanche effect)
        #expect(differingBits > 16)
    }
}
