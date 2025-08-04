import Foundation
import Crypto
import _CryptoExtras

/// Cipher information structure matching OpenSSH
struct CipherInfo {
    let name: String
    let blockSize: Int
    let keyLen: Int
    let ivLen: Int
    let authLen: Int
    let flags: CipherFlags
    
    struct CipherFlags: OptionSet {
        let rawValue: Int
        
        static let cbc = CipherFlags(rawValue: 1 << 0)
        static let chachaPoly = CipherFlags(rawValue: 1 << 1)
        static let aesCtr = CipherFlags(rawValue: 1 << 2)
        static let aesGcm = CipherFlags(rawValue: 1 << 3)
        static let none = CipherFlags(rawValue: 1 << 4)
    }
}

/// Cipher manager for OpenSSH private key encryption
enum Cipher {
    /// Supported ciphers matching OpenSSH
    static let supportedCiphers: [CipherInfo] = [
        // CBC mode ciphers
        CipherInfo(name: "3des-cbc", blockSize: 8, keyLen: 24, ivLen: 0, authLen: 0, flags: .cbc),
        CipherInfo(name: "aes128-cbc", blockSize: 16, keyLen: 16, ivLen: 0, authLen: 0, flags: .cbc),
        CipherInfo(name: "aes192-cbc", blockSize: 16, keyLen: 24, ivLen: 0, authLen: 0, flags: .cbc),
        CipherInfo(name: "aes256-cbc", blockSize: 16, keyLen: 32, ivLen: 0, authLen: 0, flags: .cbc),
        
        // CTR mode ciphers
        CipherInfo(name: "aes128-ctr", blockSize: 16, keyLen: 16, ivLen: 0, authLen: 0, flags: .aesCtr),
        CipherInfo(name: "aes192-ctr", blockSize: 16, keyLen: 24, ivLen: 0, authLen: 0, flags: .aesCtr),
        CipherInfo(name: "aes256-ctr", blockSize: 16, keyLen: 32, ivLen: 0, authLen: 0, flags: .aesCtr),
        
        // GCM mode ciphers
        CipherInfo(name: "aes128-gcm@openssh.com", blockSize: 16, keyLen: 16, ivLen: 12, authLen: 16, flags: .aesGcm),
        CipherInfo(name: "aes256-gcm@openssh.com", blockSize: 16, keyLen: 32, ivLen: 12, authLen: 16, flags: .aesGcm),
        
        // ChaCha20-Poly1305
        CipherInfo(name: "chacha20-poly1305@openssh.com", blockSize: 8, keyLen: 64, ivLen: 0, authLen: 16, flags: .chachaPoly),
        
        // No encryption
        CipherInfo(name: "none", blockSize: 8, keyLen: 0, ivLen: 0, authLen: 0, flags: .none)
    ]
    
    /// Get cipher info by name
    static func cipherByName(_ name: String) -> CipherInfo? {
        return supportedCiphers.first { $0.name == name }
    }
    
    /// Get default cipher name
    static let defaultCipher = "aes256-ctr"
    
    /// Encrypt data using the specified cipher
    static func encrypt(
        data: Data,
        cipher: String,
        key: Data,
        iv: Data
    ) throws -> Data {
        guard cipherByName(cipher) != nil else {
            throw SSHKeyError.unsupportedCipher(cipher)
        }
        
        switch cipher {
        case "aes128-ctr", "aes192-ctr", "aes256-ctr":
            return try AESCTR.encrypt(data: data, key: key, iv: iv)
            
        case "aes128-cbc", "aes192-cbc", "aes256-cbc":
            return try AESCBC.encrypt(data: data, key: key, iv: iv)
            
        case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
            return try AESGCM.encrypt(data: data, key: key, iv: iv)
            
        case "3des-cbc":
            return try TripleDESCBC.encrypt(data: data, key: key, iv: iv)
            
        case "chacha20-poly1305@openssh.com":
            return try ChaCha20Poly1305OpenSSH.encrypt(data: data, key: key, iv: iv)
            
        case "none":
            return data
            
        default:
            throw SSHKeyError.unsupportedCipher(cipher)
        }
    }
    
    /// Decrypt data using the specified cipher
    static func decrypt(
        data: Data,
        cipher: String,
        key: Data,
        iv: Data
    ) throws -> Data {
        guard cipherByName(cipher) != nil else {
            throw SSHKeyError.unsupportedCipher(cipher)
        }
        
        switch cipher {
        case "aes128-ctr", "aes192-ctr", "aes256-ctr":
            return try AESCTR.decrypt(data: data, key: key, iv: iv)
            
        case "aes128-cbc", "aes192-cbc", "aes256-cbc":
            return try AESCBC.decrypt(data: data, key: key, iv: iv)
            
        case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
            return try AESGCM.decrypt(data: data, key: key, iv: iv)
            
        case "3des-cbc":
            return try TripleDESCBC.decrypt(data: data, key: key, iv: iv)
            
        case "chacha20-poly1305@openssh.com":
            return try ChaCha20Poly1305OpenSSH.decrypt(data: data, key: key, iv: iv)
            
        case "none":
            return data
            
        default:
            throw SSHKeyError.unsupportedCipher(cipher)
        }
    }
    
    /// Get the required key+iv size for a cipher
    static func getKeyIVSize(cipher: String) -> (keySize: Int, ivSize: Int)? {
        guard let cipherInfo = cipherByName(cipher) else {
            return nil
        }
        
        let ivSize = cipherInfo.ivLen > 0 ? cipherInfo.ivLen : cipherInfo.blockSize
        return (cipherInfo.keyLen, ivSize)
    }
}

// MARK: - AES CBC Implementation is in AESCBC.swift

// MARK: - AES GCM Implementation is in AESGCM.swift

// MARK: - Triple DES CBC Implementation is in TripleDES.swift

// MARK: - ChaCha20-Poly1305 Implementation is in ChaCha20Poly1305.swift