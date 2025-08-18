import Foundation
// MARK: Disabled
// TODO: Fix this
/// Simple AES wrapper for GCM mode
private struct AES {
    private let expandedKey: [UInt32]
    private let rounds: Int
    
    init(key: [UInt8]) throws {
        guard [16, 24, 32].contains(key.count) else {
            throw SSHKeyError.invalidKeyData
        }
        
        let keyData = Data(key)
        self.expandedKey = AES.keyExpansion(key: keyData)
        self.rounds = AES.numberOfRounds(keySize: key.count)
    }
    
    func encryptBlock(_ input: [UInt8]) throws -> [UInt8] {
        guard input.count == 16 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let encrypted = AES.encryptBlock(Data(input), expandedKey: expandedKey, rounds: rounds)
        return Array(encrypted)
    }
    
    // Reuse AES implementation from AESCTR
    
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
    
    private static let rcon: [UInt32] = [
        0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x1b000000, 0x36000000
    ]
    
    private static let nb = 4
    
    private static func numberOfRounds(keySize: Int) -> Int {
        switch keySize {
        case 16: return 10
        case 24: return 12
        case 32: return 14
        default: return 0
        }
    }
    
    private static func numberOfKeyWords(keySize: Int) -> Int {
        return keySize / 4
    }
    
    private static func keyExpansion(key: Data) -> [UInt32] {
        let nk = numberOfKeyWords(keySize: key.count)
        let nr = numberOfRounds(keySize: key.count)
        var w = [UInt32](repeating: 0, count: nb * (nr + 1))
        
        for i in 0..<nk {
            let offset = i * 4
            w[i] = UInt32(key[offset]) << 24 |
                   UInt32(key[offset + 1]) << 16 |
                   UInt32(key[offset + 2]) << 8 |
                   UInt32(key[offset + 3])
        }
        
        for i in nk..<(nb * (nr + 1)) {
            var temp = w[i - 1]
            
            if i % nk == 0 {
                temp = subWord(rotWord(temp)) ^ rcon[(i / nk) - 1]
            } else if nk > 6 && i % nk == 4 {
                temp = subWord(temp)
            }
            
            w[i] = w[i - nk] ^ temp
        }
        
        return w
    }
    
    private static func rotWord(_ word: UInt32) -> UInt32 {
        return (word << 8) | (word >> 24)
    }
    
    private static func subWord(_ word: UInt32) -> UInt32 {
        var result: UInt32 = 0
        result |= UInt32(sbox[Int((word >> 24) & 0xff)]) << 24
        result |= UInt32(sbox[Int((word >> 16) & 0xff)]) << 16
        result |= UInt32(sbox[Int((word >> 8) & 0xff)]) << 8
        result |= UInt32(sbox[Int(word & 0xff)])
        return result
    }
    
    private static func subBytes(_ state: inout [[UInt8]]) {
        for i in 0..<4 {
            for j in 0..<4 {
                state[i][j] = sbox[Int(state[i][j])]
            }
        }
    }
    
    private static func shiftRows(_ state: inout [[UInt8]]) {
        let temp1 = state[1][0]
        state[1][0] = state[1][1]
        state[1][1] = state[1][2]
        state[1][2] = state[1][3]
        state[1][3] = temp1
        
        let temp20 = state[2][0]
        let temp21 = state[2][1]
        state[2][0] = state[2][2]
        state[2][1] = state[2][3]
        state[2][2] = temp20
        state[2][3] = temp21
        
        let temp3 = state[3][3]
        state[3][3] = state[3][2]
        state[3][2] = state[3][1]
        state[3][1] = state[3][0]
        state[3][0] = temp3
    }
    
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
                a ^= 0x1b
            }
            b >>= 1
        }
        
        return p
    }
    
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
    
    private static func addRoundKey(_ state: inout [[UInt8]], roundKey: [UInt32], round: Int) {
        for c in 0..<4 {
            let keyWord = roundKey[round * 4 + c]
            state[0][c] ^= UInt8((keyWord >> 24) & 0xff)
            state[1][c] ^= UInt8((keyWord >> 16) & 0xff)
            state[2][c] ^= UInt8((keyWord >> 8) & 0xff)
            state[3][c] ^= UInt8(keyWord & 0xff)
        }
    }
    
    private static func encryptBlock(_ input: Data, expandedKey: [UInt32], rounds: Int) -> Data {
        var state = [[UInt8]](repeating: [UInt8](repeating: 0, count: 4), count: 4)
        for i in 0..<4 {
            for j in 0..<4 {
                state[j][i] = input[i * 4 + j]
            }
        }
        
        addRoundKey(&state, roundKey: expandedKey, round: 0)
        
        for round in 1..<rounds {
            subBytes(&state)
            shiftRows(&state)
            mixColumns(&state)
            addRoundKey(&state, roundKey: expandedKey, round: round)
        }
        
        subBytes(&state)
        shiftRows(&state)
        addRoundKey(&state, roundKey: expandedKey, round: rounds)
        
        var output = Data(count: 16)
        for i in 0..<4 {
            for j in 0..<4 {
                output[i * 4 + j] = state[j][i]
            }
        }
        
        return output
    }
}

/// AES-GCM implementation for OpenSSH compatibility
struct AESGCM {
    /// AES-GCM authentication tag length
    static let tagLength = 16
    
    /// Encrypt data using AES-GCM
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Temporarily disabled due to implementation issues
        throw SSHKeyError.unsupportedCipher("AES-GCM encryption is temporarily unavailable")
        
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // OpenSSH uses 12-byte IV for GCM but may pass different sizes
        // We need at least 12 bytes
        guard iv.count >= 12 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Use only first 12 bytes of IV for GCM
        let gcmIV = iv.prefix(12)
        
        // Initialize AES
        let aes = try AES(key: Array(key))
        
        // GCM uses CTR mode internally with a specific counter construction
        var counter = Data(count: 16)
        counter.replaceSubrange(0..<12, with: gcmIV)
        // Counter starts at 2 for encryption (1 is used for auth key generation)
        counter[15] = 2
        
        // Generate authentication key by encrypting zeros with counter=1
        var authKeyCounter = Data(count: 16)
        authKeyCounter.replaceSubrange(0..<12, with: gcmIV)
        authKeyCounter[15] = 1
        let authKey = try aes.encryptBlock(Array(authKeyCounter))
        
        // Encrypt data using CTR mode
        var encrypted = Data()
        var offset = 0
        
        while offset < data.count {
            let keystream = try aes.encryptBlock(Array(counter))
            let blockSize = min(16, data.count - offset)
            
            for i in 0..<blockSize {
                encrypted.append(data[offset + i] ^ keystream[i])
            }
            
            offset += blockSize
            incrementCounter(&counter)
        }
        
        // Calculate authentication tag using GHASH
        let tag = try ghash(
            authKey: Data(authKey),
            aad: Data(), // No AAD for private key encryption
            ciphertext: encrypted
        )
        
        // Return ciphertext || tag
        return encrypted + tag
    }
    
    /// Decrypt data using AES-GCM
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Temporarily disabled due to implementation issues
        throw SSHKeyError.unsupportedCipher("AES-GCM decryption is temporarily unavailable")
        
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Check minimum size for tag
        guard data.count >= tagLength else {
            throw SSHKeyError.invalidKeyData
        }
        
        // OpenSSH uses 12-byte IV for GCM but may pass different sizes
        // We need at least 12 bytes
        guard iv.count >= 12 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Use only first 12 bytes of IV for GCM
        let gcmIV = iv.prefix(12)
        
        // Split ciphertext and tag
        let ciphertext = data.prefix(data.count - tagLength)
        let tag = data.suffix(tagLength)
        
        // Initialize AES
        let aes = try AES(key: Array(key))
        
        // Generate authentication key
        var authKeyCounter = Data(count: 16)
        authKeyCounter.replaceSubrange(0..<12, with: gcmIV)
        authKeyCounter[15] = 1
        let authKey = try aes.encryptBlock(Array(authKeyCounter))
        
        // Verify authentication tag
        let expectedTag = try ghash(
            authKey: Data(authKey),
            aad: Data(),
            ciphertext: ciphertext
        )
        
        guard tag == expectedTag else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decrypt using CTR mode
        var counter = Data(count: 16)
        counter.replaceSubrange(0..<12, with: gcmIV)
        counter[15] = 2
        
        var decrypted = Data()
        var offset = 0
        
        while offset < ciphertext.count {
            let keystream = try aes.encryptBlock(Array(counter))
            let blockSize = min(16, ciphertext.count - offset)
            
            for i in 0..<blockSize {
                decrypted.append(ciphertext[offset + i] ^ keystream[i])
            }
            
            offset += blockSize
            incrementCounter(&counter)
        }
        
        return decrypted
    }
    
    /// Increment GCM counter (32-bit increment of last 4 bytes)
    private static func incrementCounter(_ counter: inout Data) {
        // Increment as 32-bit big-endian integer
        var carry = true
        for i in (12..<16).reversed() {
            if carry {
                if counter[i] == 255 {
                    counter[i] = 0
                } else {
                    counter[i] += 1
                    carry = false
                }
            }
        }
    }
    
    /// GHASH function for GCM authentication
    private static func ghash(authKey: Data, aad: Data, ciphertext: Data) throws -> Data {
        // Convert auth key to GF(2^128) element
        var h = GF128Element(data: authKey)
        
        // Initialize result
        var y = GF128Element()
        
        // Process AAD (empty for private keys)
        // Skip AAD processing since it's empty
        
        // Process ciphertext
        var offset = 0
        while offset < ciphertext.count {
            let blockSize = min(16, ciphertext.count - offset)
            var block = Data(count: 16)
            block.replaceSubrange(0..<blockSize, with: ciphertext[offset..<offset+blockSize])
            
            // Y = (Y XOR block) * H
            y.xor(GF128Element(data: block))
            y = y.multiply(h)
            
            offset += blockSize
        }
        
        // Create length block (AAD length || ciphertext length in bits)
        var lengthBlock = Data(count: 16)
        // AAD length = 0 (8 bytes, big-endian)
        // Ciphertext length in bits (8 bytes, big-endian)
        let ciphertextBits = UInt64(ciphertext.count * 8)
        for i in 0..<8 {
            lengthBlock[8 + i] = UInt8((ciphertextBits >> (56 - i * 8)) & 0xff)
        }
        
        // Final multiplication
        y.xor(GF128Element(data: lengthBlock))
        y = y.multiply(h)
        
        return y.toData()
    }
}

/// GF(2^128) element for GHASH
private struct GF128Element {
    var high: UInt64 = 0
    var low: UInt64 = 0
    
    init() {}
    
    init(data: Data) {
        guard data.count >= 16 else { return }
        
        // Big-endian to native
        for i in 0..<8 {
            high = (high << 8) | UInt64(data[i])
        }
        for i in 8..<16 {
            low = (low << 8) | UInt64(data[i])
        }
    }
    
    func toData() -> Data {
        var result = Data(count: 16)
        
        // Native to big-endian
        for i in 0..<8 {
            result[i] = UInt8((high >> (56 - i * 8)) & 0xff)
        }
        for i in 0..<8 {
            result[8 + i] = UInt8((low >> (56 - i * 8)) & 0xff)
        }
        
        return result
    }
    
    mutating func xor(_ other: GF128Element) {
        high ^= other.high
        low ^= other.low
    }
    
    func multiply(_ other: GF128Element) -> GF128Element {
        var result = GF128Element()
        var v = self
        var z = other
        
        // Multiplication in GF(2^128)
        for _ in 0..<128 {
            if z.low & 1 == 1 {
                result.high ^= v.high
                result.low ^= v.low
            }
            
            // Right shift z
            z.low = (z.low >> 1) | ((z.high & 1) << 63)
            z.high = z.high >> 1
            
            // Left shift v with reduction
            let carry = (v.high & (1 << 63)) != 0
            v.high = (v.high << 1) | ((v.low >> 63) & 1)
            v.low = v.low << 1
            
            // Reduce by primitive polynomial if carry
            if carry {
                v.low ^= 0x87  // x^7 + x^2 + x + 1
            }
        }
        
        return result
    }
}