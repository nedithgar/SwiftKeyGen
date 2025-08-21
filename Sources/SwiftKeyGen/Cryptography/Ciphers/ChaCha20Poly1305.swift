import Foundation

/// ChaCha20-Poly1305 implementation for OpenSSH compatibility
/// Note: OpenSSH uses a custom construction that differs from standard ChaCha20-Poly1305
struct ChaCha20Poly1305OpenSSH {
    
    /// Encrypt data using ChaCha20-Poly1305 (OpenSSH variant)
    /// OpenSSH uses 64-byte keys: 32 bytes for main cipher, 32 bytes for header
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 64 else { // 2 x 256-bit keys
            throw SSHKeyError.invalidKeyData
        }
        // Layout per OpenSSH: first 32 bytes = K2 (payload + MAC), second 32 bytes = K1 (header) – header unused here
        let mainKey = Array(key.prefix(32))
        // Sequence (nonce) comes from iv (8 bytes) or zero if absent
        var seq = Data(repeating: 0, count: 8)
        if iv.count >= 8 { seq.replaceSubrange(0..<8, with: iv.prefix(8)) }
        // Build 16-byte IV buffer: 8 bytes counter || 8 bytes sequence (both little-endian interpretation)
        var ivCounter0 = Data(count: 16)
        // counter already zero
        ivCounter0.replaceSubrange(8..<16, with: seq)
        var ctx = ChaCha20Context(key: mainKey)
        // Generate Poly1305 one-time key using counter=0
        ctx.ivSetup(iv: ivCounter0)
        var polyKey = Data(repeating: 0, count: 32)
        let zeroBlock = Data(repeating: 0, count: 32)
        ctx.encrypt(src: zeroBlock, dst: &polyKey) // first 256 bits of keystream
        // Encrypt payload with counter=1
        var ivCounter1 = ivCounter0
        ivCounter1[0] = 1 // little-endian 64-bit value = 1 (low 32 bits in first 4 bytes, rest zero fine)
        ctx.ivSetup(iv: ivCounter1)
        var encrypted = Data(count: data.count)
        ctx.encrypt(src: data, dst: &encrypted)
        // MAC over ciphertext only (no AAD in this simplified usage)
        let tag = Poly1305.auth(message: encrypted, key: polyKey)
        return encrypted + tag
    }
    
    /// Decrypt data using ChaCha20-Poly1305 (OpenSSH variant)
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 64 else { throw SSHKeyError.invalidKeyData }
        guard data.count >= 16 else { throw SSHKeyError.invalidKeyData }
        let ciphertextSlice = data.prefix(data.count - 16)
        // Ensure contiguous Data storage (avoid potential slice indexing traps in constant-time ops)
        let ciphertext = Data(ciphertextSlice)
        let tag = data.suffix(16)
        // Sequence (nonce)
        var seq = Data(repeating: 0, count: 8)
        if iv.count >= 8 { seq.replaceSubrange(0..<8, with: iv.prefix(8)) }
        var ivCounter0 = Data(count: 16)
        ivCounter0.replaceSubrange(8..<16, with: seq)
        let mainKey = Array(key.prefix(32))
        var ctx = ChaCha20Context(key: mainKey)
        // Re-create Poly1305 key
        ctx.ivSetup(iv: ivCounter0)
        var polyKey = Data(repeating: 0, count: 32)
        let zeroBlock = Data(repeating: 0, count: 32)
        ctx.encrypt(src: zeroBlock, dst: &polyKey)
        // Verify tag constant-time
        let expected = Poly1305.auth(message: ciphertext, key: polyKey)
        guard constantTimeEqual(expected, tag) else {
            throw SSHKeyError.invalidKeyData
        }
        // Decrypt with counter=1
        var ivCounter1 = ivCounter0
        ivCounter1[0] = 1
        ctx.ivSetup(iv: ivCounter1)
        var decrypted = Data(count: ciphertext.count)
        ctx.encrypt(src: ciphertext, dst: &decrypted)
        return decrypted
    }

    /// Constant-time comparison (16-byte tags here)
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return false }
        var diff: UInt8 = 0
        a.withUnsafeBytes { ab in
            b.withUnsafeBytes { bb in
                let ap = ab.bindMemory(to: UInt8.self).baseAddress!
                let bp = bb.bindMemory(to: UInt8.self).baseAddress!
                for i in 0..<a.count {
                    diff |= ap[i] ^ bp[i]
                }
            }
        }
        return diff == 0
    }
}

/// ChaCha20 context matching OpenSSH implementation
private struct ChaCha20Context {
    private var state: [UInt32]
    
    init(key: [UInt8]) {
        self.state = [UInt32](repeating: 0, count: 16)
        keySetup(key: key)
    }
    
    mutating func keySetup(key: [UInt8]) {
        guard key.count >= 32 else { return }
        
        // Constants "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        
        // Key
        for i in 0..<8 {
            let offset = i * 4
            state[4 + i] = UInt32(key[offset]) |
                           UInt32(key[offset + 1]) << 8 |
                           UInt32(key[offset + 2]) << 16 |
                           UInt32(key[offset + 3]) << 24
        }
    }
    
    mutating func ivSetup(iv: Data) {
        // OpenSSH uses 16-byte IV: counter (8 bytes) || nonce (8 bytes)
        if iv.count >= 16 {
            // Counter (first 8 bytes)
            state[12] = UInt32(iv[0]) |
                        UInt32(iv[1]) << 8 |
                        UInt32(iv[2]) << 16 |
                        UInt32(iv[3]) << 24
            state[13] = UInt32(iv[4]) |
                        UInt32(iv[5]) << 8 |
                        UInt32(iv[6]) << 16 |
                        UInt32(iv[7]) << 24
            
            // Nonce (next 8 bytes)
            state[14] = UInt32(iv[8]) |
                        UInt32(iv[9]) << 8 |
                        UInt32(iv[10]) << 16 |
                        UInt32(iv[11]) << 24
            state[15] = UInt32(iv[12]) |
                        UInt32(iv[13]) << 8 |
                        UInt32(iv[14]) << 16 |
                        UInt32(iv[15]) << 24
        } else if iv.count >= 8 {
            // Fallback for 8-byte IV (legacy)
            state[12] = 0
            state[13] = 0
            state[14] = UInt32(iv[0]) |
                        UInt32(iv[1]) << 8 |
                        UInt32(iv[2]) << 16 |
                        UInt32(iv[3]) << 24
            state[15] = UInt32(iv[4]) |
                        UInt32(iv[5]) << 8 |
                        UInt32(iv[6]) << 16 |
                        UInt32(iv[7]) << 24
        }
    }
    
    mutating func encrypt(src: Data, dst: inout Data) {
        var srcOffset = 0
        var dstOffset = 0
        
        while srcOffset < src.count {
            let blockSize = min(64, src.count - srcOffset)
            let keystream = generateKeystream()
            
            for i in 0..<blockSize {
                if dstOffset + i < dst.count {
                    dst[dstOffset + i] = src[srcOffset + i] ^ keystream[i]
                }
            }
            
            srcOffset += blockSize
            dstOffset += blockSize
            
            // Increment counter
            state[12] = state[12] &+ 1
            if state[12] == 0 {
                state[13] = state[13] &+ 1
            }
        }
    }
    
    /// Generate 64-byte keystream block
    private func generateKeystream() -> Data {
        // Working state is a copy of the current state
        var workingState = state
        
        // 20 rounds (10 double-rounds)
        for _ in 0..<10 {
            // Column rounds
            quarterRound(&workingState, 0, 4, 8, 12)
            quarterRound(&workingState, 1, 5, 9, 13)
            quarterRound(&workingState, 2, 6, 10, 14)
            quarterRound(&workingState, 3, 7, 11, 15)
            
            // Diagonal rounds
            quarterRound(&workingState, 0, 5, 10, 15)
            quarterRound(&workingState, 1, 6, 11, 12)
            quarterRound(&workingState, 2, 7, 8, 13)
            quarterRound(&workingState, 3, 4, 9, 14)
        }
        
        // Add initial state
        for i in 0..<16 {
            workingState[i] = workingState[i] &+ state[i]
        }
        
        // Serialize to bytes (little-endian)
        var keystream = Data(count: 64)
        for i in 0..<16 {
            let offset = i * 4
            keystream[offset] = UInt8(workingState[i] & 0xff)
            keystream[offset + 1] = UInt8((workingState[i] >> 8) & 0xff)
            keystream[offset + 2] = UInt8((workingState[i] >> 16) & 0xff)
            keystream[offset + 3] = UInt8((workingState[i] >> 24) & 0xff)
        }
        
        return keystream
    }
    
    /// ChaCha20 quarter round
    private func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]
        state[d] = rotl32(state[d] ^ state[a], 16)
        
        state[c] = state[c] &+ state[d]
        state[b] = rotl32(state[b] ^ state[c], 12)
        
        state[a] = state[a] &+ state[b]
        state[d] = rotl32(state[d] ^ state[a], 8)
        
        state[c] = state[c] &+ state[d]
        state[b] = rotl32(state[b] ^ state[c], 7)
    }
    
    /// Rotate left 32-bit
    private func rotl32(_ value: UInt32, _ bits: Int) -> UInt32 {
        return (value << bits) | (value >> (32 - bits))
    }
}

/// Poly1305 MAC implementation
private struct Poly1305 {
    /// Generate Poly1305 authentication tag
    static func auth(message: Data, key: Data) -> Data {
        guard key.count == 32 else {
            return Data(count: 16)
        }
        
        // Initialize r (first 16 bytes of key)
        var t0 = UInt32(key[0]) | UInt32(key[1]) << 8 | UInt32(key[2]) << 16 | UInt32(key[3]) << 24
        var t1 = UInt32(key[4]) | UInt32(key[5]) << 8 | UInt32(key[6]) << 16 | UInt32(key[7]) << 24
        var t2 = UInt32(key[8]) | UInt32(key[9]) << 8 | UInt32(key[10]) << 16 | UInt32(key[11]) << 24
        var t3 = UInt32(key[12]) | UInt32(key[13]) << 8 | UInt32(key[14]) << 16 | UInt32(key[15]) << 24
        
        // Clamp and compute r values (matching OpenSSH)
        let r0 = t0 & 0x3ffffff
        t0 >>= 26
        t0 |= t1 << 6
        let r1 = t0 & 0x3ffff03
        t1 >>= 20
        t1 |= t2 << 12
        let r2 = t1 & 0x3ffc0ff
        t2 >>= 14
        t2 |= t3 << 18
        let r3 = t2 & 0x3f03fff
        t3 >>= 8
        let r4 = t3 & 0x00fffff
        
        // Precompute multipliers
        let s1 = r1 &* 5
        let s2 = r2 &* 5
        let s3 = r3 &* 5
        let s4 = r4 &* 5
        
        // Initialize h
        var h0: UInt32 = 0
        var h1: UInt32 = 0
        var h2: UInt32 = 0
        var h3: UInt32 = 0
        var h4: UInt32 = 0
        
        // Process message in 16-byte blocks
        var offset = 0
        
        // Process full blocks
        while offset + 16 <= message.count {
            let t0 = UInt32(message[offset]) | UInt32(message[offset+1]) << 8 | UInt32(message[offset+2]) << 16 | UInt32(message[offset+3]) << 24
            let t1 = UInt32(message[offset+4]) | UInt32(message[offset+5]) << 8 | UInt32(message[offset+6]) << 16 | UInt32(message[offset+7]) << 24
            let t2 = UInt32(message[offset+8]) | UInt32(message[offset+9]) << 8 | UInt32(message[offset+10]) << 16 | UInt32(message[offset+11]) << 24
            let t3 = UInt32(message[offset+12]) | UInt32(message[offset+13]) << 8 | UInt32(message[offset+14]) << 16 | UInt32(message[offset+15]) << 24
            
            h0 += t0 & 0x3ffffff
            let temp1 = (UInt64(t1) << 32) | UInt64(t0)
            h1 += UInt32(truncatingIfNeeded: (temp1 >> 26) & 0x3ffffff)
            let temp2 = (UInt64(t2) << 32) | UInt64(t1)
            h2 += UInt32(truncatingIfNeeded: (temp2 >> 20) & 0x3ffffff)
            let temp3 = (UInt64(t3) << 32) | UInt64(t2)
            h3 += UInt32(truncatingIfNeeded: (temp3 >> 14) & 0x3ffffff)
            h4 += (t3 >> 8) | (1 << 24)
            
            // Multiply by r
            let d0 = UInt64(h0) * UInt64(r0) + UInt64(h1) * UInt64(s4) + UInt64(h2) * UInt64(s3) + UInt64(h3) * UInt64(s2) + UInt64(h4) * UInt64(s1)
            let d1 = UInt64(h0) * UInt64(r1) + UInt64(h1) * UInt64(r0) + UInt64(h2) * UInt64(s4) + UInt64(h3) * UInt64(s3) + UInt64(h4) * UInt64(s2)
            let d2 = UInt64(h0) * UInt64(r2) + UInt64(h1) * UInt64(r1) + UInt64(h2) * UInt64(r0) + UInt64(h3) * UInt64(s4) + UInt64(h4) * UInt64(s3)
            let d3 = UInt64(h0) * UInt64(r3) + UInt64(h1) * UInt64(r2) + UInt64(h2) * UInt64(r1) + UInt64(h3) * UInt64(r0) + UInt64(h4) * UInt64(s4)
            let d4 = UInt64(h0) * UInt64(r4) + UInt64(h1) * UInt64(r3) + UInt64(h2) * UInt64(r2) + UInt64(h3) * UInt64(r1) + UInt64(h4) * UInt64(r0)
            
            // Carry propagation
            var c: UInt64
            h0 = UInt32(truncatingIfNeeded: d0) & 0x3ffffff; c = d0 >> 26
            let t1c = d1 + c; h1 = UInt32(truncatingIfNeeded: t1c) & 0x3ffffff; c = t1c >> 26
            let t2c = d2 + c; h2 = UInt32(truncatingIfNeeded: t2c) & 0x3ffffff; c = t2c >> 26
            let t3c = d3 + c; h3 = UInt32(truncatingIfNeeded: t3c) & 0x3ffffff; c = t3c >> 26
            let t4c = d4 + c; h4 = UInt32(truncatingIfNeeded: t4c) & 0x3ffffff; c = t4c >> 26
            h0 = h0 &+ UInt32(truncatingIfNeeded: c * 5)
            
            offset += 16
        }
        
        // Process final partial block if any
        if offset < message.count {
            var mp = [UInt8](repeating: 0, count: 16)
            let remaining = message.count - offset
            for i in 0..<remaining {
                mp[i] = message[offset + i]
            }
            mp[remaining] = 1 // padding bit
            
            let t0 = UInt32(mp[0]) | UInt32(mp[1]) << 8 | UInt32(mp[2]) << 16 | UInt32(mp[3]) << 24
            let t1 = UInt32(mp[4]) | UInt32(mp[5]) << 8 | UInt32(mp[6]) << 16 | UInt32(mp[7]) << 24
            let t2 = UInt32(mp[8]) | UInt32(mp[9]) << 8 | UInt32(mp[10]) << 16 | UInt32(mp[11]) << 24
            let t3 = UInt32(mp[12]) | UInt32(mp[13]) << 8 | UInt32(mp[14]) << 16 | UInt32(mp[15]) << 24
            
            h0 += t0 & 0x3ffffff
            let ptemp1 = (UInt64(t1) << 32) | UInt64(t0)
            h1 += UInt32(truncatingIfNeeded: (ptemp1 >> 26) & 0x3ffffff)
            let ptemp2 = (UInt64(t2) << 32) | UInt64(t1)
            h2 += UInt32(truncatingIfNeeded: (ptemp2 >> 20) & 0x3ffffff)
            let ptemp3 = (UInt64(t3) << 32) | UInt64(t2)
            h3 += UInt32(truncatingIfNeeded: (ptemp3 >> 14) & 0x3ffffff)
            h4 += (t3 >> 8)
            
            // Final multiply
            let d0 = UInt64(h0) * UInt64(r0) + UInt64(h1) * UInt64(s4) + UInt64(h2) * UInt64(s3) + UInt64(h3) * UInt64(s2) + UInt64(h4) * UInt64(s1)
            let d1 = UInt64(h0) * UInt64(r1) + UInt64(h1) * UInt64(r0) + UInt64(h2) * UInt64(s4) + UInt64(h3) * UInt64(s3) + UInt64(h4) * UInt64(s2)
            let d2 = UInt64(h0) * UInt64(r2) + UInt64(h1) * UInt64(r1) + UInt64(h2) * UInt64(r0) + UInt64(h3) * UInt64(s4) + UInt64(h4) * UInt64(s3)
            let d3 = UInt64(h0) * UInt64(r3) + UInt64(h1) * UInt64(r2) + UInt64(h2) * UInt64(r1) + UInt64(h3) * UInt64(r0) + UInt64(h4) * UInt64(s4)
            let d4 = UInt64(h0) * UInt64(r4) + UInt64(h1) * UInt64(r3) + UInt64(h2) * UInt64(r2) + UInt64(h3) * UInt64(r1) + UInt64(h4) * UInt64(r0)
            
            // Carry propagation
            var c: UInt64
            h0 = UInt32(truncatingIfNeeded: d0) & 0x3ffffff; c = d0 >> 26
            let t1c = d1 + c; h1 = UInt32(truncatingIfNeeded: t1c) & 0x3ffffff; c = t1c >> 26
            let t2c = d2 + c; h2 = UInt32(truncatingIfNeeded: t2c) & 0x3ffffff; c = t2c >> 26
            let t3c = d3 + c; h3 = UInt32(truncatingIfNeeded: t3c) & 0x3ffffff; c = t3c >> 26
            let t4c = d4 + c; h4 = UInt32(truncatingIfNeeded: t4c) & 0x3ffffff; c = t4c >> 26
            h0 = h0 &+ UInt32(truncatingIfNeeded: c * 5)
        }
        
        // Final reduction
        var b = h0 >> 26; h0 = h0 & 0x3ffffff
        h1 += b; b = h1 >> 26; h1 = h1 & 0x3ffffff
        h2 += b; b = h2 >> 26; h2 = h2 & 0x3ffffff
        h3 += b; b = h3 >> 26; h3 = h3 & 0x3ffffff
        h4 += b; b = h4 >> 26; h4 = h4 & 0x3ffffff
        h0 += b * 5; b = h0 >> 26; h0 = h0 & 0x3ffffff
        h1 += b
        
        // Compute g = h + 5
        var g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff
        var g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff
        var g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff
        var g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff
        let g4 = h4 &+ b &- (1 << 26)
        
        // b = (g4 >> 31) - 1, nb = ~b
        // In C: if g4 has high bit set (would be negative), (g4 >> 31) = 1, so b = 0
        //        if g4 has high bit clear, (g4 >> 31) = 0, so b = -1 (all bits set)
        let b_mask = (g4 >> 31) == 0 ? UInt32.max : 0
        let nb_mask = ~b_mask
        
        h0 = (h0 & nb_mask) | (g0 & b_mask)
        h1 = (h1 & nb_mask) | (g1 & b_mask)
        h2 = (h2 & nb_mask) | (g2 & b_mask)
        h3 = (h3 & nb_mask) | (g3 & b_mask)
        h4 = (h4 & nb_mask) | (g4 & b_mask)
        
        // Load s (last 16 bytes of key)
        let sk0 = UInt32(key[16]) | UInt32(key[17]) << 8 | UInt32(key[18]) << 16 | UInt32(key[19]) << 24
        let sk1 = UInt32(key[20]) | UInt32(key[21]) << 8 | UInt32(key[22]) << 16 | UInt32(key[23]) << 24
        let sk2 = UInt32(key[24]) | UInt32(key[25]) << 8 | UInt32(key[26]) << 16 | UInt32(key[27]) << 24
        let sk3 = UInt32(key[28]) | UInt32(key[29]) << 8 | UInt32(key[30]) << 16 | UInt32(key[31]) << 24
        
        // Add s
        var f0 = UInt64(h0) | (UInt64(h1) << 26)
        f0 += UInt64(sk0)
        var f1 = UInt64(h1 >> 6) | (UInt64(h2) << 20)
        f1 += UInt64(sk1)
        var f2 = UInt64(h2 >> 12) | (UInt64(h3) << 14)
        f2 += UInt64(sk2)
        var f3 = UInt64(h3 >> 18) | (UInt64(h4) << 8)
        f3 += UInt64(sk3)
        
        // Create tag with carry propagation
        var tag = Data(count: 16)
        tag[0] = UInt8(f0 & 0xff)
        tag[1] = UInt8((f0 >> 8) & 0xff)
        tag[2] = UInt8((f0 >> 16) & 0xff)
        tag[3] = UInt8((f0 >> 24) & 0xff)
        f1 += (f0 >> 32)
        tag[4] = UInt8(f1 & 0xff)
        tag[5] = UInt8((f1 >> 8) & 0xff)
        tag[6] = UInt8((f1 >> 16) & 0xff)
        tag[7] = UInt8((f1 >> 24) & 0xff)
        f2 += (f1 >> 32)
        tag[8] = UInt8(f2 & 0xff)
        tag[9] = UInt8((f2 >> 8) & 0xff)
        tag[10] = UInt8((f2 >> 16) & 0xff)
        tag[11] = UInt8((f2 >> 24) & 0xff)
        f3 += (f2 >> 32)
        tag[12] = UInt8(f3 & 0xff)
        tag[13] = UInt8((f3 >> 8) & 0xff)
        tag[14] = UInt8((f3 >> 16) & 0xff)
        tag[15] = UInt8((f3 >> 24) & 0xff)
        
        return tag
    }
}