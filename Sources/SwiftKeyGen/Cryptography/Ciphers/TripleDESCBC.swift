import Foundation

// MARK: - Triple DES (3DES) CBC mode (InlineArray optimized)
// Migrated to Swift 6.2 InlineArray for fixed-size (8-byte) block operations to
// eliminate per-block Data / Array heap allocations in the hot loop.
// Remaining internal bit/perm logic still uses temporary Data for clarity;
// can be further optimized later if DES performance becomes critical.

private typealias DESBlock = InlineArray<8, UInt8>
private typealias RoundKey = InlineArray<6, UInt8> // 48-bit subkey per round
private typealias DESHalf = InlineArray<4, UInt8>

struct TripleDESCBC {
    /// Encrypt data using 3DES-CBC mode (EDE)
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // 3DES uses 24-byte key (3 x 8 bytes)
        guard key.count == 24 else { throw SSHKeyError.invalidKeyData }
        guard iv.count == 8 else { throw SSHKeyError.invalidKeyData }
        guard data.count % 8 == 0 else { throw SSHKeyError.invalidKeyData }

        // Split key into three DES keys (copy bytes once)
        let k1 = key[0..<8]
        let k2 = key[8..<16]
        let k3 = key[16..<24]
        let des1 = try DES(keyBytes: k1)
        let des2 = try DES(keyBytes: k2)
        let des3 = try DES(keyBytes: k3)

        if data.isEmpty { return Data() }
        var result = Data(count: data.count)
        var outSpan = result.mutableSpan
        let inSpan = data.span
        let ivSpan = iv.span
        var previous = DESBlock(repeating: 0)
        do {
            var span = previous.mutableSpan
            for i in 0..<8 { span[i] = ivSpan[i] }
        }
        var plain = DESBlock(repeating: 0)
        var xored = DESBlock(repeating: 0)
        for offset in stride(from: 0, to: data.count, by: 8) {
            // Load plaintext
            do {
                var p = plain.mutableSpan
                for i in 0..<8 { p[i] = inSpan[offset + i] }
            }
            // XOR with previous
            do {
                let p = plain.span
                let prev = previous.span
                var xs = xored.mutableSpan
                for i in 0..<8 { xs[i] = p[i] ^ prev[i] }
            }
            let t1 = des1.encryptBlock(xored)
            let t2 = des2.decryptBlock(t1)
            let cipher = des3.encryptBlock(t2)
            let cSpan = cipher.span
            for i in 0..<8 { outSpan[offset + i] = cSpan[i] }
            previous = cipher
        }
        return result
    }

    /// Decrypt data using 3DES-CBC mode (DED)
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 24 else { throw SSHKeyError.invalidKeyData }
        guard iv.count == 8 else { throw SSHKeyError.invalidKeyData }
        guard data.count % 8 == 0 else { throw SSHKeyError.invalidKeyData }

        let k1 = key[0..<8]
        let k2 = key[8..<16]
        let k3 = key[16..<24]
        let des1 = try DES(keyBytes: k1)
        let des2 = try DES(keyBytes: k2)
        let des3 = try DES(keyBytes: k3)

        if data.isEmpty { return Data() }
        var result = Data(count: data.count)
        var outSpan = result.mutableSpan
        let inSpan = data.span
        let ivSpan = iv.span
        var previous = DESBlock(repeating: 0)
        do {
            var span = previous.mutableSpan
            for i in 0..<8 { span[i] = ivSpan[i] }
        }
        var cipherBlock = DESBlock(repeating: 0)
        for offset in stride(from: 0, to: data.count, by: 8) {
            // Load cipher block
            do {
                var cs = cipherBlock.mutableSpan
                for i in 0..<8 { cs[i] = inSpan[offset + i] }
            }
            let t1 = des3.decryptBlock(cipherBlock)
            let t2 = des2.encryptBlock(t1)
            let dec = des1.decryptBlock(t2)
            // Produce plaintext by XOR dec and previous inside a limited borrow scope
            do {
                let decSpan = dec.span
                let prevSpan = previous.span
                for i in 0..<8 { outSpan[offset + i] = decSpan[i] ^ prevSpan[i] }
            }
            // Now safe to update previous
            previous = cipherBlock
        }
        return result
    }
}

/// DES block cipher implementation
private struct DES {
    private let subkeys: [RoundKey] // 16 round keys

    init(keyBytes: Data.SubSequence) throws {
        guard keyBytes.count == 8 else { throw SSHKeyError.invalidKeyData }
        let k = Data(keyBytes)
        self.subkeys = DES.generateSubkeys(key: k)
    }

    /// Encrypt a single 8-byte block (InlineArray)
    @inline(__always) func encryptBlock(_ block: DESBlock) -> DESBlock {
        DES.processBlock(block, subkeys: subkeys, decrypt: false)
    }

    /// Decrypt a single 8-byte block (InlineArray)
    @inline(__always) func decryptBlock(_ block: DESBlock) -> DESBlock {
        DES.processBlock(block, subkeys: subkeys, decrypt: true)
    }
    
    // MARK: - DES Core Implementation
    
    /// Initial permutation table
    private static let IP: [Int] = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]
    
    /// Final permutation table
    private static let FP: [Int] = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]
    
    /// Expansion table
    private static let E: [Int] = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    
    /// S-boxes
    private static let S: [[[UInt8]]] = [
        // S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        // S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        // S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        // S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        // S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        // S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        // S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        // S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    
    /// Permutation table
    private static let P: [Int] = [
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
    ]
    
    /// Process a block through DES
    private static func processBlock(_ block: DESBlock, subkeys: [RoundKey], decrypt: Bool) -> DESBlock {
        // Convert to Data for permutation reuse
        let blockData = block.toData()
    let permuted = applyPermutation(blockData, table: IP, inputBits: 64, outputBits: 64)

    var left = DESHalf(repeating: 0)
    var right = DESHalf(repeating: 0)
    for i in 0..<4 { left[i] = permuted[i]; right[i] = permuted[4 + i] }

        for round in 0..<16 {
            let idx = decrypt ? (15 - round) : round
            let f = feistel(right, subkey: subkeys[idx])
            let newRight = xor(left, f)
            left = right
            right = newRight
        }

    var combined = Data(capacity: 8)
    for i in 0..<4 { combined.append(right[i]) }
    for i in 0..<4 { combined.append(left[i]) }
    let finalPerm = applyPermutation(combined, table: FP, inputBits: 64, outputBits: 64)

        var out = DESBlock(repeating: 0)
        for i in 0..<8 { out[i] = finalPerm[i] }
        return out
    }
    
    /// Feistel function
    private static func feistel(_ right: DESHalf, subkey: RoundKey) -> DESHalf {
        // Expand right half from 32 to 48 bits
    let expanded = applyPermutation(right.toData(), table: E, inputBits: 32, outputBits: 48)
        
        // XOR with subkey (InlineArray RoundKey)
        var xored = RoundKey(repeating: 0)
        for i in 0..<6 { xored[i] = expanded[i] ^ subkey[i] }
        
        // Apply S-boxes
        var sboxOutput = DESHalf(repeating: 0)
        for i in 0..<8 {
            let sixBits = getSixBits(xored, index: i)
            let row = Int((sixBits & 0x20) >> 4 | (sixBits & 0x01))
            let col = Int((sixBits & 0x1E) >> 1)
            let sboxValue = S[i][row][col]
            
            if i % 2 == 0 {
                sboxOutput[i / 2] = sboxValue << 4
            } else {
                sboxOutput[i / 2] |= sboxValue
            }
        }
        
        // Apply permutation P
    let perm = applyPermutation(sboxOutput.toData(), table: P, inputBits: 32, outputBits: 32)
        var out = DESHalf(repeating: 0)
        for i in 0..<4 { out[i] = perm[i] }
        return out
    }
    
    /// Generate subkeys
    private static func generateSubkeys(key: Data) -> [RoundKey] {
        // PC1 permutation
        let PC1: [Int] = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]
        
        // PC2 permutation
        let PC2: [Int] = [
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ]
        
        // Left shift schedule
        let shifts: [Int] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        
        // Apply PC1
    let permutedKey = applyPermutation(key, table: PC1, inputBits: 64, outputBits: 56)
        
        // Convert to bits for C and D
        var permutedBits = [Bool]()
        for byte in permutedKey {
            for i in (0..<8).reversed() {
                permutedBits.append((byte & (1 << i)) != 0)
            }
        }
        
        // Split into C and D
        var C = Array(permutedBits.prefix(28))
        var D = Array(permutedBits.suffix(28))
        
    var subkeys: [RoundKey] = []
        
        for round in 0..<16 {
            // Left shift
            C = leftShift28(C, by: shifts[round])
            D = leftShift28(D, by: shifts[round])
            
            // Combine C and D (28 + 28 = 56 bits)
            let combinedBits = C + D
            let combined = bitsToBytes(combinedBits)
            
            // Apply PC2
            let subkeyData = applyPermutation(combined, table: PC2, inputBits: 56, outputBits: 48)
            var rk = RoundKey(repeating: 0)
            for i in 0..<6 { rk[i] = subkeyData[i] }
            subkeys.append(rk)
        }
        
        return subkeys
    }
    
    // MARK: - Helper Functions
    
    private static func applyPermutation(_ input: Data, table: [Int], inputBits: Int, outputBits: Int) -> Data {
        // Convert input data to bit array first
        var inputBitArray = [Bool]()
        for byte in input {
            for i in (0..<8).reversed() {
                inputBitArray.append((byte & (1 << i)) != 0)
            }
        }
        
        // Create output bit array
        var outputBitArray = [Bool](repeating: false, count: outputBits)
        for i in 0..<outputBits {
            let sourcePos = table[i] - 1
            if sourcePos >= 0 && sourcePos < inputBitArray.count {
                outputBitArray[i] = inputBitArray[sourcePos]
            }
        }
        
        return bitsToBytes(outputBitArray)
    }
    
    private static func bitsToBytes(_ bits: [Bool]) -> Data {
        var bytes = Data()
        for i in stride(from: 0, to: bits.count, by: 8) {
            var byte: UInt8 = 0
            for j in 0..<8 {
                if i + j < bits.count && bits[i + j] {
                    byte |= (1 << (7 - j))
                }
            }
            bytes.append(byte)
        }
        return bytes
    }
    
    private static func leftShift28(_ bits: [Bool], by count: Int) -> [Bool] {
        guard bits.count == 28 else { return bits }
        var shifted = [Bool](repeating: false, count: 28)
        for i in 0..<28 {
            shifted[i] = bits[(i + count) % 28]
        }
        return shifted
    }
    
    private static func xor(_ a: DESHalf, _ b: DESHalf) -> DESHalf {
        var out = DESHalf(repeating: 0)
        for i in 0..<4 { out[i] = a[i] ^ b[i] }
        return out
    }
    
    private static func getSixBits(_ bytes: RoundKey, index: Int) -> UInt8 {
        let bitOffset = index * 6
        let byteOffset = bitOffset / 8
        let bitPosition = bitOffset % 8

        if bitPosition <= 2 {
            return (bytes[byteOffset] >> (2 - bitPosition)) & 0x3F
        } else {
            let highBits = (bytes[byteOffset] << (bitPosition - 2)) & 0x3F
            let lowBits = bytes[byteOffset + 1] >> (10 - bitPosition)
            return highBits | lowBits
        }
    }
}