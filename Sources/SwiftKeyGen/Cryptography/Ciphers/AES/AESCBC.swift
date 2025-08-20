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
        for i in 0..<16 { tmp[i] = data[i] }
        self.storage = tmp
    }
    init(data: Data, offset: Int) {
        precondition(offset + 16 <= data.count, "Out of range block load")
        var tmp = InlineArray<16, UInt8>(repeating: 0)
        for i in 0..<16 { tmp[i] = data[offset + i] }
        self.storage = tmp
    }
    init(raw: InlineArray<16, UInt8>) { self.storage = raw }
    func toData() -> Data {
        var d = Data(count: 16)
        for i in 0..<16 { d[i] = storage[i] }
        return d
    }
    static func ^ (lhs: AESBlock, rhs: AESBlock) -> AESBlock {
        var out = InlineArray<16, UInt8>(repeating: 0)
        for i in 0..<16 { out[i] = lhs.storage[i] ^ rhs.storage[i] }
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
        var previous = AESBlock(iv: iv)
        for offset in stride(from: 0, to: data.count, by: 16) {
            let plainBlock = AESBlock(data: data, offset: offset)
            let xored = plainBlock ^ previous
            let cipherData = try aes.encryptBlock(xored.toData())
            result.replaceSubrange(offset..<(offset + 16), with: cipherData)
            previous = AESBlock(data: cipherData, offset: 0)
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
        var previous = AESBlock(iv: iv)
        for offset in stride(from: 0, to: data.count, by: 16) {
            let cipherBlock = AESBlock(data: data, offset: offset)
            let decryptedData = try aes.decryptBlock(cipherBlock.toData())
            let decrypted = AESBlock(data: decryptedData, offset: 0)
            let plain = decrypted ^ previous
            result.replaceSubrange(offset..<(offset + 16), with: plain.toData())
            previous = cipherBlock
        }
        return result
    }
}

