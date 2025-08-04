import Foundation

/// Triple DES (3DES) CBC mode implementation for OpenSSH compatibility
struct TripleDESCBC {
    
    /// Encrypt data using 3DES-CBC mode
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // 3DES uses 24-byte key (3 x 8 bytes)
        guard key.count == 24 else {
            throw SSHKeyError.invalidKeyData
        }
        
        guard iv.count == 8 else { // DES block size is 8 bytes
            throw SSHKeyError.invalidKeyData
        }
        
        // Ensure data is padded to block size
        guard data.count % 8 == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Split key into three DES keys
        let key1 = Data(key.prefix(8))
        let key2 = Data(key[8..<16])
        let key3 = Data(key.suffix(8))
        
        // Create DES instances
        let des1 = try DES(key: key1)
        let des2 = try DES(key: key2)
        let des3 = try DES(key: key3)
        
        var result = Data()
        var previousBlock = Array(iv)  // Convert to array for easier access
        
        // Process each block with 3DES-EDE (Encrypt-Decrypt-Encrypt)
        for offset in stride(from: 0, to: data.count, by: 8) {
            // Get plaintext block as array
            let endOffset = min(offset + 8, data.count)
            let plaintextBlock = Array(data[offset..<endOffset])
            
            // Ensure we have exactly 8 bytes
            guard plaintextBlock.count == 8 else {
                throw SSHKeyError.invalidKeyData
            }
            
            // XOR with previous ciphertext (CBC mode)
            var xorBlock = Data(count: 8)
            for i in 0..<8 {
                xorBlock[i] = plaintextBlock[i] ^ previousBlock[i]
            }
            
            // 3DES-EDE: Encrypt with key1, decrypt with key2, encrypt with key3
            let temp1 = try des1.encryptBlock(xorBlock)
            let temp2 = try des2.decryptBlock(temp1)
            let ciphertextBlock = try des3.encryptBlock(temp2)
            
            result.append(ciphertextBlock)
            previousBlock = Array(ciphertextBlock)
        }
        
        return result
    }
    
    /// Decrypt data using 3DES-CBC mode
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // 3DES uses 24-byte key
        guard key.count == 24 else {
            throw SSHKeyError.invalidKeyData
        }
        
        guard iv.count == 8 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Ensure data is padded to block size
        guard data.count % 8 == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Split key into three DES keys
        let key1 = Data(key.prefix(8))
        let key2 = Data(key[8..<16])
        let key3 = Data(key.suffix(8))
        
        // Create DES instances
        let des1 = try DES(key: key1)
        let des2 = try DES(key: key2)
        let des3 = try DES(key: key3)
        
        var result = Data()
        var previousBlock = Array(iv)  // Convert to array for easier access
        
        // Process each block with 3DES-DED (Decrypt-Encrypt-Decrypt)
        for offset in stride(from: 0, to: data.count, by: 8) {
            // Get ciphertext block as array
            let endOffset = min(offset + 8, data.count)
            let ciphertextBlock = Array(data[offset..<endOffset])
            
            // Ensure we have exactly 8 bytes
            guard ciphertextBlock.count == 8 else {
                throw SSHKeyError.invalidKeyData
            }
            
            // 3DES-DED: Decrypt with key3, encrypt with key2, decrypt with key1
            let temp1 = try des3.decryptBlock(Data(ciphertextBlock))
            let temp2 = try des2.encryptBlock(temp1)
            let decryptedBlock = try des1.decryptBlock(temp2)
            let decryptedArray = Array(decryptedBlock)
            
            // XOR with previous ciphertext (CBC mode)
            var plaintextBlock = Data(count: 8)
            for i in 0..<8 {
                plaintextBlock[i] = decryptedArray[i] ^ previousBlock[i]
            }
            
            result.append(plaintextBlock)
            previousBlock = ciphertextBlock
        }
        
        return result
    }
}

/// DES block cipher implementation
private struct DES {
    private let subkeys: [[UInt8]]
    
    init(key: Data) throws {
        guard key.count == 8 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Generate 16 round subkeys
        self.subkeys = DES.generateSubkeys(key: key)
    }
    
    /// Encrypt a single 8-byte block
    func encryptBlock(_ block: Data) throws -> Data {
        guard block.count == 8 else {
            throw SSHKeyError.invalidKeyData
        }
        
        return DES.processBlock(block, subkeys: subkeys, decrypt: false)
    }
    
    /// Decrypt a single 8-byte block
    func decryptBlock(_ block: Data) throws -> Data {
        guard block.count == 8 else {
            throw SSHKeyError.invalidKeyData
        }
        
        return DES.processBlock(block, subkeys: subkeys, decrypt: true)
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
    private static func processBlock(_ block: Data, subkeys: [[UInt8]], decrypt: Bool) -> Data {
        // Initial permutation
        let permuted = applyPermutation(block, table: IP, inputBits: 64, outputBits: 64)
        
        // Split into left and right halves
        var left = Array(permuted.prefix(4))
        var right = Array(permuted.suffix(4))
        
        // 16 rounds
        for round in 0..<16 {
            let subkeyIndex = decrypt ? (15 - round) : round
            let newRight = xor(left, feistel(right, subkey: subkeys[subkeyIndex]))
            left = right
            right = newRight
        }
        
        // Combine halves (swap for final)
        var combined = Data()
        combined.append(contentsOf: right)
        combined.append(contentsOf: left)
        
        // Final permutation
        return applyPermutation(combined, table: FP, inputBits: 64, outputBits: 64)
    }
    
    /// Feistel function
    private static func feistel(_ right: [UInt8], subkey: [UInt8]) -> [UInt8] {
        // Expand right half from 32 to 48 bits
        let expanded = applyPermutation(Data(right), table: E, inputBits: 32, outputBits: 48)
        
        // XOR with subkey
        var xored = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            xored[i] = expanded[i] ^ subkey[i]
        }
        
        // Apply S-boxes
        var sboxOutput = [UInt8](repeating: 0, count: 4)
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
        return Array(applyPermutation(Data(sboxOutput), table: P, inputBits: 32, outputBits: 32))
    }
    
    /// Generate subkeys
    private static func generateSubkeys(key: Data) -> [[UInt8]] {
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
        
        var subkeys: [[UInt8]] = []
        
        for round in 0..<16 {
            // Left shift
            C = leftShift28(C, by: shifts[round])
            D = leftShift28(D, by: shifts[round])
            
            // Combine C and D (28 + 28 = 56 bits)
            let combinedBits = C + D
            let combined = bitsToBytes(combinedBits)
            
            // Apply PC2
            let subkey = applyPermutation(combined, table: PC2, inputBits: 56, outputBits: 48)
            subkeys.append(Array(subkey))
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
            let sourcePos = table[i] - 1  // Convert 1-based to 0-based
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
    
    private static func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        return zip(a, b).map { $0 ^ $1 }
    }
    
    private static func getSixBits(_ bytes: [UInt8], index: Int) -> UInt8 {
        let bitOffset = index * 6
        let byteOffset = bitOffset / 8
        let bitPosition = bitOffset % 8
        
        if bitPosition <= 2 {
            // All 6 bits in one byte
            return (bytes[byteOffset] >> (2 - bitPosition)) & 0x3F
        } else {
            // Bits span two bytes
            let highBits = (bytes[byteOffset] << (bitPosition - 2)) & 0x3F
            let lowBits = bytes[byteOffset + 1] >> (10 - bitPosition)
            return highBits | lowBits
        }
    }
}