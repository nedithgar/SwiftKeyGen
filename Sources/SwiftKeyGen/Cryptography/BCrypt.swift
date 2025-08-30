import Foundation
import CommonCrypto

/// Full bcrypt_pbkdf implementation for OpenSSH compatibility
/// Based on OpenSSH's bcrypt_pbkdf.c implementation
struct BCryptPBKDF {
    
    private static let bcryptWords = 8
    private static let bcryptHashSize = bcryptWords * 4
    
    /// Derives a key using bcrypt_pbkdf algorithm
    /// - Parameters:
    ///   - password: The password to derive from
    ///   - salt: The salt to use
    ///   - outputByteCount: Number of bytes to generate
    ///   - rounds: Number of rounds to perform
    /// - Returns: The derived key
    static func deriveKey(
        password: String,
        salt: Data,
        outputByteCount: Int,
        rounds: Int
    ) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Validate parameters
        guard rounds >= 1,
              !passwordData.isEmpty,
              !salt.isEmpty,
              outputByteCount > 0,
              outputByteCount <= bcryptHashSize * bcryptHashSize,
              salt.count <= (1 << 20) else {
            throw SSHKeyError.invalidKeyData
        }
        
        let stride = (outputByteCount + bcryptHashSize - 1) / bcryptHashSize
        let amt = (outputByteCount + stride - 1) / stride
        
        // Create countsalt: salt + 4 byte counter
        var countsalt = Data(salt)
        countsalt.append(contentsOf: [0, 0, 0, 0])
        
        // Hash the password with SHA512
        let sha2pass = sha512(passwordData)
        
        // Generate key
        var key = Data(repeating: 0, count: outputByteCount)
        var keyOffset = 0
        
        for count in 1...UInt32((outputByteCount + bcryptHashSize - 1) / bcryptHashSize) {
            // Update counter in countsalt (big-endian)
            countsalt[salt.count + 0] = UInt8((count >> 24) & 0xff)
            countsalt[salt.count + 1] = UInt8((count >> 16) & 0xff)
            countsalt[salt.count + 2] = UInt8((count >> 8) & 0xff)
            countsalt[salt.count + 3] = UInt8(count & 0xff)
            
            // First round: hash countsalt
            let sha2salt = sha512(countsalt)
            
            // Perform bcrypt hash
            var tmpout = try bcryptHash(sha2pass: sha2pass, sha2salt: sha2salt)
            var out = tmpout
            
            // Subsequent rounds
            for _ in 1..<rounds {
                // Hash previous output
                let sha2salt = sha512(tmpout)
                tmpout = try bcryptHash(sha2pass: sha2pass, sha2salt: sha2salt)
                
                // XOR with accumulated result
                for j in 0..<out.count {
                    out[j] ^= tmpout[j]
                }
            }
            
            // Output key material non-linearly
            let currentAmt = min(amt, outputByteCount - keyOffset)
            for i in 0..<currentAmt {
                let dest = i * stride + Int(count - 1)
                if dest >= outputByteCount {
                    break
                }
                key[dest] = out[i]
            }
            keyOffset += Int(currentAmt)
        }
        
        return key
    }
    
    /// Performs SHA512 hash
    private static func sha512(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes { bytes in
            _ = CC_SHA512(bytes.bindMemory(to: UInt8.self).baseAddress!, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    
    /// Performs bcrypt hash operation
    private static func bcryptHash(sha2pass: Data, sha2salt: Data) throws -> Data {
        var state = BlowfishContext()
        let ciphertext: [UInt8] = Array("OxychromaticBlowfishSwatDynamite".utf8)
        
        // Key expansion
    state.initializeState()
        sha2salt.withUnsafeBytes { saltBuffer in
            sha2pass.withUnsafeBytes { passBuffer in
                let saltSpan = Span(_unsafeElements: saltBuffer.bindMemory(to: UInt8.self))
                let passSpan = Span(_unsafeElements: passBuffer.bindMemory(to: UInt8.self))
                state.expandSaltAndKey(salt: saltSpan, key: passSpan)
                
                // 64 rounds of expansion
                for _ in 0..<64 {
                    state.expandKey(key: saltSpan)
                    state.expandKey(key: passSpan)
                }
            }
        }
        
        // Convert ciphertext to UInt32 array
        var cdata = [UInt32](repeating: 0, count: bcryptWords)
        var j = 0
        for i in 0..<bcryptWords {
            cdata[i] = stream2word(data: ciphertext, databytes: UInt16(ciphertext.count), current: &j)
        }
        
        // 64 rounds of encryption
        for _ in 0..<64 {
            state.encrypt(data: &cdata, blocks: bcryptWords / 2)
        }
        
        // Convert result to bytes (big-endian)
        var out = Data(repeating: 0, count: bcryptHashSize)
        for i in 0..<bcryptWords {
            out[4 * i + 3] = UInt8((cdata[i] >> 24) & 0xff)
            out[4 * i + 2] = UInt8((cdata[i] >> 16) & 0xff)
            out[4 * i + 1] = UInt8((cdata[i] >> 8) & 0xff)
            out[4 * i + 0] = UInt8(cdata[i] & 0xff)
        }
        
        return out
    }
    
    /// Converts byte stream to word
    private static func stream2word(data: [UInt8], databytes: UInt16, current: inout Int) -> UInt32 {
        var temp: UInt32 = 0
        
        for _ in 0..<4 {
            if current >= databytes {
                current = 0
            }
            temp = (temp << 8) | UInt32(data[current])
            current += 1
        }
        
        return temp
    }
}