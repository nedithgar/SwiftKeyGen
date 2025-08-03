import Foundation

/// AES-CTR mode implementation for OpenSSH compatibility
/// This is a complete implementation of AES (Rijndael) in CTR mode
struct AESCTR {
    
    // MARK: - AES Core Implementation
    
    /// AES S-box for SubBytes transformation
    private static let sbox: [UInt8] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    /// Round constants for key expansion
    private static let rcon: [UInt32] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    ]
    
    /// Number of columns (32-bit words) comprising the state
    private static let nb = 4
    
    /// Number of rounds based on key size
    private static func numberOfRounds(keySize: Int) -> Int {
        switch keySize {
        case 16: return 10  // AES-128
        case 24: return 12  // AES-192
        case 32: return 14  // AES-256
        default: return 0
        }
    }
    
    /// Number of 32-bit words comprising the key
    private static func numberOfKeyWords(keySize: Int) -> Int {
        return keySize / 4
    }
    
    // MARK: - Key Expansion
    
    /// Expands the cipher key into the key schedule
    private static func keyExpansion(key: Data) -> [UInt32] {
        let nk = numberOfKeyWords(keySize: key.count)
        let nr = numberOfRounds(keySize: key.count)
        var w = [UInt32](repeating: 0, count: nb * (nr + 1))
        
        // Copy key into first part of expanded key
        for i in 0..<nk {
            let offset = i * 4
            w[i] = UInt32(key[offset]) << 24 |
                   UInt32(key[offset + 1]) << 16 |
                   UInt32(key[offset + 2]) << 8 |
                   UInt32(key[offset + 3])
        }
        
        // Expand the key
        for i in nk..<(nb * (nr + 1)) {
            var temp = w[i - 1]
            
            if i % nk == 0 {
                // RotWord and SubWord
                temp = subWord(rotWord(temp)) ^ rcon[(i / nk) - 1]
            } else if nk > 6 && i % nk == 4 {
                // SubWord for AES-256
                temp = subWord(temp)
            }
            
            w[i] = w[i - nk] ^ temp
        }
        
        return w
    }
    
    /// Rotate word (used in key expansion)
    private static func rotWord(_ word: UInt32) -> UInt32 {
        return (word << 8) | (word >> 24)
    }
    
    /// Substitute word (used in key expansion)
    private static func subWord(_ word: UInt32) -> UInt32 {
        var result: UInt32 = 0
        result |= UInt32(sbox[Int((word >> 24) & 0xff)]) << 24
        result |= UInt32(sbox[Int((word >> 16) & 0xff)]) << 16
        result |= UInt32(sbox[Int((word >> 8) & 0xff)]) << 8
        result |= UInt32(sbox[Int(word & 0xff)])
        return result
    }
    
    // MARK: - AES Round Functions
    
    /// SubBytes transformation
    private static func subBytes(_ state: inout [[UInt8]]) {
        for i in 0..<4 {
            for j in 0..<4 {
                state[i][j] = sbox[Int(state[i][j])]
            }
        }
    }
    
    /// ShiftRows transformation
    private static func shiftRows(_ state: inout [[UInt8]]) {
        // Row 0 - no shift
        
        // Row 1 - shift left by 1
        let temp1 = state[1][0]
        state[1][0] = state[1][1]
        state[1][1] = state[1][2]
        state[1][2] = state[1][3]
        state[1][3] = temp1
        
        // Row 2 - shift left by 2
        let temp20 = state[2][0]
        let temp21 = state[2][1]
        state[2][0] = state[2][2]
        state[2][1] = state[2][3]
        state[2][2] = temp20
        state[2][3] = temp21
        
        // Row 3 - shift left by 3 (or right by 1)
        let temp3 = state[3][3]
        state[3][3] = state[3][2]
        state[3][2] = state[3][1]
        state[3][1] = state[3][0]
        state[3][0] = temp3
    }
    
    /// Galois field multiplication
    private static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var p: UInt8 = 0
        var hi: UInt8 = 0
        var a = a
        var b = b
        
        for _ in 0..<8 {
            if b & 1 != 0 {
                p ^= a
            }
            hi = a & 0x80
            a <<= 1
            if hi != 0 {
                a ^= 0x1b  // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1
        }
        
        return p
    }
    
    /// MixColumns transformation
    private static func mixColumns(_ state: inout [[UInt8]]) {
        for c in 0..<4 {
            let a0 = state[0][c]
            let a1 = state[1][c]
            let a2 = state[2][c]
            let a3 = state[3][c]
            
            state[0][c] = gfMul(0x02, a0) ^ gfMul(0x03, a1) ^ a2 ^ a3
            state[1][c] = a0 ^ gfMul(0x02, a1) ^ gfMul(0x03, a2) ^ a3
            state[2][c] = a0 ^ a1 ^ gfMul(0x02, a2) ^ gfMul(0x03, a3)
            state[3][c] = gfMul(0x03, a0) ^ a1 ^ a2 ^ gfMul(0x02, a3)
        }
    }
    
    /// AddRoundKey transformation
    private static func addRoundKey(_ state: inout [[UInt8]], roundKey: [UInt32], round: Int) {
        for c in 0..<4 {
            let keyWord = roundKey[round * 4 + c]
            state[0][c] ^= UInt8((keyWord >> 24) & 0xff)
            state[1][c] ^= UInt8((keyWord >> 16) & 0xff)
            state[2][c] ^= UInt8((keyWord >> 8) & 0xff)
            state[3][c] ^= UInt8(keyWord & 0xff)
        }
    }
    
    // MARK: - AES Block Encryption
    
    /// Encrypts a single 16-byte block
    private static func encryptBlock(_ input: Data, expandedKey: [UInt32], rounds: Int) -> Data {
        // Initialize state from input
        var state = [[UInt8]](repeating: [UInt8](repeating: 0, count: 4), count: 4)
        for i in 0..<4 {
            for j in 0..<4 {
                state[j][i] = input[i * 4 + j]
            }
        }
        
        // Initial round key addition
        addRoundKey(&state, roundKey: expandedKey, round: 0)
        
        // Main rounds
        for round in 1..<rounds {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, roundKey: expandedKey, round: round)
        }
        
        // Final round (no MixColumns)
        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, roundKey: expandedKey, round: rounds)
        
        // Convert state to output
        var output = Data(count: 16)
        for i in 0..<4 {
            for j in 0..<4 {
                output[i * 4 + j] = state[j][i]
            }
        }
        
        return output
    }
    
    // MARK: - CTR Mode Implementation
    
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Validate inputs
        guard [16, 24, 32].contains(key.count) else {
            throw SSHKeyError.invalidKeyData
        }
        
        guard iv.count == 16 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Expand the key
        let expandedKey = keyExpansion(key: key)
        let rounds = numberOfRounds(keySize: key.count)
        
        var result = Data()
        var counter = Data(iv)
        let blockSize = 16
        
        // Process each block
        for offset in stride(from: 0, to: data.count, by: blockSize) {
            // Encrypt the counter to get keystream block
            let keystream = encryptBlock(counter, expandedKey: expandedKey, rounds: rounds)
            
            // XOR data with keystream
            let endIndex = min(offset + blockSize, data.count)
            for i in offset..<endIndex {
                let keystreamIndex = i - offset
                result.append(data[i] ^ keystream[keystreamIndex])
            }
            
            // Increment counter (big-endian, matching OpenSSH)
            incrementCounter(&counter)
        }
        
        return result
    }
    
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // CTR mode is symmetric - encryption and decryption are the same
        return try encrypt(data: data, key: key, iv: iv)
    }
    
    private static func incrementCounter(_ counter: inout Data) {
        // Increment counter as big-endian integer (matching OpenSSH aesctr_inc)
        for i in (0..<counter.count).reversed() {
            if counter[i] == 255 {
                counter[i] = 0
            } else {
                counter[i] += 1
                break
            }
        }
    }
}