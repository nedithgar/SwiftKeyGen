import Foundation

/// AES-CTR mode implementation (refactored to reuse AESEngine and InlineArray).
/// This removes the duplicated AES core previously present here; AESEngine
/// (InlineArray optimized) is now the single source of truth for block ops.
struct AESCTR {
    private typealias Block = InlineArray<16, UInt8>

    static func encrypt(data: Data, key: Data, iv: Data) throws -> Data {
        // Validate inputs
        guard [16,24,32].contains(key.count), iv.count == 16 else {
            throw SSHKeyError.invalidKeyData
        }

        // Prepare engine
        let engine = try AESEngine(key: key)

        // Initialize counter from IV
        var counter = Block(repeating: 0)
        for i in 0..<16 { counter[i] = iv[i] }

        // Preallocate output
        var output = Data(count: data.count)
        if data.isEmpty { return output }

        output.withUnsafeMutableBytes { outBufRaw in
            let outBuf = outBufRaw.bindMemory(to: UInt8.self)
            data.withUnsafeBytes { inBufRaw in
                let inBuf = inBufRaw.bindMemory(to: UInt8.self)
                var keystream: Block = Block(repeating: 0)
                for offset in stride(from: 0, to: data.count, by: 16) {
                    // Encrypt counter -> keystream block
                    keystream = try! engine.encryptBlock(counter) // engine variant avoids Data alloc
                    let chunk = min(16, data.count - offset)
                    for i in 0..<chunk {
                        outBuf[offset + i] = inBuf[offset + i] ^ keystream[i]
                    }
                    increment(&counter)
                }
            }
        }
        return output
    }

    static func decrypt(data: Data, key: Data, iv: Data) throws -> Data {
        try encrypt(data: data, key: key, iv: iv) // Symmetric in CTR mode
    }

    @inline(__always) private static func increment(_ counter: inout Block) {
        for i in (0..<16).reversed() {
            if counter[i] == 0xFF { counter[i] = 0 } else { counter[i] &+= 1; break }
        }
    }
}