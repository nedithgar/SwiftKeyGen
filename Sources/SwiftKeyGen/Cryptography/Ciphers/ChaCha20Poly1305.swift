import Foundation

// MARK: - ChaCha20-Poly1305 (OpenSSH variant) InlineArray / Span optimized

/// ChaCha20-Poly1305 implementation for OpenSSH compatibility
/// Note: OpenSSH uses a custom construction that differs from standard ChaCha20-Poly1305
struct ChaCha20Poly1305OpenSSH {
    
    /// Encrypt data using ChaCha20-Poly1305 (OpenSSH variant)
    /// OpenSSH uses 64-byte keys: 32 bytes for main cipher, 32 bytes for header
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 64 else { throw SSHKeyError.invalidKeyData }
        // OpenSSH layout: first 32 bytes main cipher+MAC key (K2), second 32 bytes header key (unused here)
        var mainKey = InlineArray<32, UInt8>(repeating: 0)
        for index in 0..<32 { mainKey[index] = key[index] }

        // Sequence (nonce) (8 bytes) — copy if provided
        var sequence = InlineArray<8, UInt8>(repeating: 0)
        if iv.count >= 8 {
            let ivSpan = iv.span
            for index in 0..<8 { sequence[index] = ivSpan[index] }
        }

        // 16‑byte IV buffer: counter (8 bytes little‑endian) || sequence (8 bytes)
        var ivCounter0 = InlineArray<16, UInt8>(repeating: 0)
        for index in 0..<8 { ivCounter0[8 + index] = sequence[index] }

        var context = ChaCha20Context(key: mainKey)
        context.ivSetup(ivInline: ivCounter0)

        // Derive Poly1305 key (32 bytes) = first half of keystream block 0
        let polyKeystream = context.generateKeystream() // does NOT mutate external counter state
        var polyKey = InlineArray<32, UInt8>(repeating: 0)
        for index in 0..<32 { polyKey[index] = polyKeystream[index] }

        // Prepare counter=1 for payload (increment low 32 bits)
        var ivCounter1 = ivCounter0
        ivCounter1[0] = 1 // little-endian increment (only first byte needed in this construction)
        context.ivSetup(ivInline: ivCounter1)

        // Encrypt payload streaming (avoid per-block allocations)
        var encryptedData = Data(count: data.count)
        context.encrypt(src: data, dst: &encryptedData)

        // MAC over ciphertext (no AAD) — Poly1305 expects Data key (convert once)
        let tag = Poly1305.auth(message: encryptedData, key: polyKey.toData())
        return encryptedData + tag
    }
    
    /// Decrypt data using ChaCha20-Poly1305 (OpenSSH variant)
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == 64 else { throw SSHKeyError.invalidKeyData }
        guard data.count >= 16 else { throw SSHKeyError.invalidKeyData }

        let ciphertextLength = data.count - 16
        let ciphertext = data.prefix(ciphertextLength)
        let tag = data.suffix(16)

        // Reconstruct sequence
        var sequence = InlineArray<8, UInt8>(repeating: 0)
        if iv.count >= 8 {
            let ivSpan = iv.span
            for index in 0..<8 { sequence[index] = ivSpan[index] }
        }
        var ivCounter0 = InlineArray<16, UInt8>(repeating: 0)
        for index in 0..<8 { ivCounter0[8 + index] = sequence[index] }

        var mainKey = InlineArray<32, UInt8>(repeating: 0)
        for index in 0..<32 { mainKey[index] = key[index] }
        var context = ChaCha20Context(key: mainKey)
        context.ivSetup(ivInline: ivCounter0)

        // Derive poly key
        let polyKeystream = context.generateKeystream()
        var polyKey = InlineArray<32, UInt8>(repeating: 0)
        for index in 0..<32 { polyKey[index] = polyKeystream[index] }

        let expected = Poly1305.auth(message: Data(ciphertext), key: polyKey.toData())
        guard constantTimeEqual(expected, tag) else { throw SSHKeyError.invalidKeyData }

        // Decrypt (counter=1)
        var ivCounter1 = ivCounter0
        ivCounter1[0] = 1
        context.ivSetup(ivInline: ivCounter1)
        var decryptedData = Data(count: ciphertextLength)
        context.encrypt(src: Data(ciphertext), dst: &decryptedData)
        return decryptedData
    }

    /// Constant-time comparison (16-byte tags here)
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return false }
        let spanA = a.span
        let spanB = b.span
        var diff: UInt8 = 0
        for index in 0..<spanA.count { diff |= spanA[index] ^ spanB[index] }
        return diff == 0
    }
}

/// ChaCha20 context matching OpenSSH implementation
private struct ChaCha20Context {
    private typealias ChaChaState = InlineArray<16, UInt32>
    private var state: ChaChaState

    init(key: InlineArray<32, UInt8>) {
        self.state = ChaChaState(repeating: 0)
        keySetup(key: key)
    }

    mutating func keySetup(key: InlineArray<32, UInt8>) {
        // Constants "expand 32-byte k"
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for index in 0..<8 {
            let offset = index * 4
            state[4 + index] = UInt32(key[offset]) |
                           UInt32(key[offset + 1]) << 8 |
                           UInt32(key[offset + 2]) << 16 |
                           UInt32(key[offset + 3]) << 24
        }
    }

    mutating func ivSetup(ivInline: InlineArray<16, UInt8>) {
        // Counter (first 8 bytes little-endian as two words)
        state[12] = UInt32(ivInline[0]) | UInt32(ivInline[1]) << 8 | UInt32(ivInline[2]) << 16 | UInt32(ivInline[3]) << 24
        state[13] = UInt32(ivInline[4]) | UInt32(ivInline[5]) << 8 | UInt32(ivInline[6]) << 16 | UInt32(ivInline[7]) << 24
        // Nonce (next 8 bytes)
        state[14] = UInt32(ivInline[8]) | UInt32(ivInline[9]) << 8 | UInt32(ivInline[10]) << 16 | UInt32(ivInline[11]) << 24
        state[15] = UInt32(ivInline[12]) | UInt32(ivInline[13]) << 8 | UInt32(ivInline[14]) << 16 | UInt32(ivInline[15]) << 24
    }

    mutating func encrypt(src: Data, dst: inout Data) {
        var srcOffset = 0
        var dstOffset = 0
        while srcOffset < src.count {
            let blockSize = min(64, src.count - srcOffset)
            let keystream = generateKeystream()
            for index in 0..<blockSize { dst[dstOffset + index] = src[srcOffset + index] ^ keystream[index] }
            srcOffset += blockSize
            dstOffset += blockSize
            // Increment 64-bit counter (two 32-bit words little-endian)
            state[12] = state[12] &+ 1
            if state[12] == 0 { state[13] = state[13] &+ 1 }
        }
    }

    /// Generate a 64-byte keystream block without mutating the counter (caller increments outside if needed)
    func generateKeystream() -> InlineArray<64, UInt8> {
        var working = state // copy
        for _ in 0..<10 { // 20 rounds (10 double rounds)
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }
        for index in 0..<16 { working[index] = working[index] &+ state[index] }
        var output = InlineArray<64, UInt8>(repeating: 0)
        for index in 0..<16 {
            let offset = index * 4
            let word = working[index]
            output[offset] = UInt8(word & 0xff)
            output[offset + 1] = UInt8((word >> 8) & 0xff)
            output[offset + 2] = UInt8((word >> 16) & 0xff)
            output[offset + 3] = UInt8((word >> 24) & 0xff)
        }
        return output
    }

    private func quarterRound(_ state: inout ChaChaState, _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]; state[d] = rotateLeft32(state[d] ^ state[a], 16)
        state[c] = state[c] &+ state[d]; state[b] = rotateLeft32(state[b] ^ state[c], 12)
        state[a] = state[a] &+ state[b]; state[d] = rotateLeft32(state[d] ^ state[a], 8)
        state[c] = state[c] &+ state[d]; state[b] = rotateLeft32(state[b] ^ state[c], 7)
    }
    private func rotateLeft32(_ value: UInt32, _ shift: Int) -> UInt32 { (value << shift) | (value >> (32 - shift)) }
}

/// Poly1305 MAC implementation
private struct Poly1305 {
    /// Generate Poly1305 authentication tag
    static func auth(message: Data, key: Data) -> Data {
        guard key.count == 32 else { return Data(count: 16) }
        
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
            var paddedBlock = InlineArray<16, UInt8>(repeating: 0)
            let remaining = message.count - offset
            for index in 0..<remaining {
                paddedBlock[index] = message[offset + index]
            }
            paddedBlock[remaining] = 1 // padding bit
            
            let t0 = UInt32(paddedBlock[0]) | UInt32(paddedBlock[1]) << 8 | UInt32(paddedBlock[2]) << 16 | UInt32(paddedBlock[3]) << 24
            let t1 = UInt32(paddedBlock[4]) | UInt32(paddedBlock[5]) << 8 | UInt32(paddedBlock[6]) << 16 | UInt32(paddedBlock[7]) << 24
            let t2 = UInt32(paddedBlock[8]) | UInt32(paddedBlock[9]) << 8 | UInt32(paddedBlock[10]) << 16 | UInt32(paddedBlock[11]) << 24
            let t3 = UInt32(paddedBlock[12]) | UInt32(paddedBlock[13]) << 8 | UInt32(paddedBlock[14]) << 16 | UInt32(paddedBlock[15]) << 24
            
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
        let selectMask = (g4 >> 31) == 0 ? UInt32.max : 0
        let invertedMask = ~selectMask
        
        h0 = (h0 & invertedMask) | (g0 & selectMask)
        h1 = (h1 & invertedMask) | (g1 & selectMask)
        h2 = (h2 & invertedMask) | (g2 & selectMask)
        h3 = (h3 & invertedMask) | (g3 & selectMask)
        h4 = (h4 & invertedMask) | (g4 & selectMask)
        
        // Load s (last 16 bytes of key)
        let subKey0 = UInt32(key[16]) | UInt32(key[17]) << 8 | UInt32(key[18]) << 16 | UInt32(key[19]) << 24
        let subKey1 = UInt32(key[20]) | UInt32(key[21]) << 8 | UInt32(key[22]) << 16 | UInt32(key[23]) << 24
        let subKey2 = UInt32(key[24]) | UInt32(key[25]) << 8 | UInt32(key[26]) << 16 | UInt32(key[27]) << 24
        let subKey3 = UInt32(key[28]) | UInt32(key[29]) << 8 | UInt32(key[30]) << 16 | UInt32(key[31]) << 24
        
        // Add s
        var f0 = UInt64(h0) | (UInt64(h1) << 26)
        f0 += UInt64(subKey0)
        var f1 = UInt64(h1 >> 6) | (UInt64(h2) << 20)
        f1 += UInt64(subKey1)
        var f2 = UInt64(h2 >> 12) | (UInt64(h3) << 14)
        f2 += UInt64(subKey2)
        var f3 = UInt64(h3 >> 18) | (UInt64(h4) << 8)
        f3 += UInt64(subKey3)
        
        // Create tag with carry propagation
        var tagInline = InlineArray<16, UInt8>(repeating: 0)
        tagInline[0] = UInt8(f0 & 0xff)
        tagInline[1] = UInt8((f0 >> 8) & 0xff)
        tagInline[2] = UInt8((f0 >> 16) & 0xff)
        tagInline[3] = UInt8((f0 >> 24) & 0xff)
        f1 += (f0 >> 32)
        tagInline[4] = UInt8(f1 & 0xff)
        tagInline[5] = UInt8((f1 >> 8) & 0xff)
        tagInline[6] = UInt8((f1 >> 16) & 0xff)
        tagInline[7] = UInt8((f1 >> 24) & 0xff)
        f2 += (f1 >> 32)
        tagInline[8] = UInt8(f2 & 0xff)
        tagInline[9] = UInt8((f2 >> 8) & 0xff)
        tagInline[10] = UInt8((f2 >> 16) & 0xff)
        tagInline[11] = UInt8((f2 >> 24) & 0xff)
        f3 += (f2 >> 32)
        tagInline[12] = UInt8(f3 & 0xff)
        tagInline[13] = UInt8((f3 >> 8) & 0xff)
        tagInline[14] = UInt8((f3 >> 16) & 0xff)
        tagInline[15] = UInt8((f3 >> 24) & 0xff)
        return tagInline.toData()
    }
}
