import Foundation

// MARK: - AES CBC (InlineArray optimized)
// Migration note:
// Uses Swift 6.2 InlineArray for per-block working buffers (16 bytes) to avoid
// allocating temporary Arrays/Data repeatedly. Further optimization (e.g. using
// InlineArray for the 4x4 AES state) can be explored later.

private struct AESBlock {
    private var storage: InlineArray<16, UInt8>
    init(zero: Void = ()) { self.storage = InlineArray(repeating: 0) }
    init(iv data: Data) {
        precondition(data.count == 16, "IV must be 16 bytes")
        var tmp = InlineArray<16, UInt8>(repeating: 0)
        let src = data.span
        var dst = tmp.mutableSpan
        for i in 0..<16 { dst[i] = src[i] }
        self.storage = tmp
    }
    init(data: Data, offset: Int) {
        precondition(offset + 16 <= data.count, "Out of range block load")
        var tmp = InlineArray<16, UInt8>(repeating: 0)
        let src = data.span
        var dst = tmp.mutableSpan
        for i in 0..<16 { dst[i] = src[offset + i] }
        self.storage = tmp
    }
    init(raw: InlineArray<16, UInt8>) { self.storage = raw }
    /// Expose the raw 16-byte block for engine operations without extra copies
    func raw() -> InlineArray<16, UInt8> { storage }
    func toData() -> Data {
        var d = Data(count: 16)
        var outSpan = d.mutableSpan
        let src = storage.span
        for i in 0..<16 { outSpan[i] = src[i] }
        return d
    }
    static func ^ (lhs: AESBlock, rhs: AESBlock) -> AESBlock {
        var out = InlineArray<16, UInt8>(repeating: 0)
        var span = out.mutableSpan
        let l = lhs.storage.span
        let r = rhs.storage.span
        for i in 0..<16 { span[i] = l[i] ^ r[i] }
        return AESBlock(raw: out)
    }
}

/// AES-CBC mode implementation for OpenSSH compatibility
struct AESCBC {
    
    /// Encrypt data using AES-CBC mode
    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Validate inputs
        guard [16, 24, 32].contains(key.count) else {
            throw SSHKeyError.invalidKeyData
        }
        
        guard iv.count == 16 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Ensure data is padded to block size (should already be for OpenSSH)
        guard data.count % 16 == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Get AES instance
        let aes = try AESEngine(key: key)
        
        // Preallocate result buffer
        var result = Data(count: data.count)
        if data.isEmpty { return result }
        var outSpan = result.mutableSpan
        let inSpan = data.span
        var previous = AESBlock(iv: iv)
        var blockBuf = InlineArray<16, UInt8>(repeating: 0)
        for offset in stride(from: 0, to: data.count, by: 16) {
            // Load plaintext block into blockBuf
            var bbSpan = blockBuf.mutableSpan
            for i in 0..<16 { bbSpan[i] = inSpan[offset + i] }
            let plainBlock = AESBlock(raw: blockBuf)
            let xored = plainBlock ^ previous
            // Use InlineArray-based encrypt to avoid transient Data lifetimes in error paths
            let cipherInline = try aes.encryptBlock(xored.raw())
            // Write cipher block to output
            let ci = cipherInline.span
            for i in 0..<16 { outSpan[offset + i] = ci[i] }
            // Chain CBC
            previous = AESBlock(raw: cipherInline)
        }
        return result
    }
    
    /// Decrypt data using AES-CBC mode
    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Validate inputs
        guard [16, 24, 32].contains(key.count) else {
            throw SSHKeyError.invalidKeyData
        }
        
        guard iv.count == 16 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Ensure data is padded to block size
        guard data.count % 16 == 0 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Get AES instance
        let aes = try AESEngine(key: key)
        
        var result = Data(count: data.count)
        if data.isEmpty { return result }
        var outSpan = result.mutableSpan
        let inSpan = data.span
        var previous = AESBlock(iv: iv)
        var blockBuf = InlineArray<16, UInt8>(repeating: 0)
        for offset in stride(from: 0, to: data.count, by: 16) {
            // Load cipher block into blockBuf
            var bbSpan = blockBuf.mutableSpan
            for i in 0..<16 { bbSpan[i] = inSpan[offset + i] }
            let cipherBlock = AESBlock(raw: blockBuf)
            let decryptedData = try aes.decryptBlock(cipherBlock.toData())
            let decrypted = AESBlock(data: decryptedData, offset: 0)
            let plain = decrypted ^ previous
            let plainData = plain.toData()
            let pSpan = plainData.span
            for i in 0..<16 { outSpan[offset + i] = pSpan[i] }
            previous = cipherBlock
        }
        return result
    }
}

