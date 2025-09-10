import Foundation
import Crypto

/// PEM encryption support for OpenSSL compatibility
public struct PEMEncryption {
    
    /// Supported ciphers for PEM encryption
    public enum PEMCipher: String, CaseIterable {
        case aes128CBC = "AES-128-CBC"
        case aes192CBC = "AES-192-CBC" 
        case aes256CBC = "AES-256-CBC"
        case des3CBC = "DES-EDE3-CBC"
        
        var keySize: Int {
            switch self {
            case .aes128CBC: return 16
            case .aes192CBC: return 24
            case .aes256CBC: return 32
            case .des3CBC: return 24
            }
        }
        
        var ivSize: Int {
            switch self {
            case .aes128CBC, .aes192CBC, .aes256CBC: return 16
            case .des3CBC: return 8
            }
        }
        
        var blockSize: Int {
            switch self {
            case .aes128CBC, .aes192CBC, .aes256CBC: return 16
            case .des3CBC: return 8
            }
        }
    }
    
    /// EVP_BytesToKey implementation for OpenSSL compatibility
    /// This is the legacy key derivation function used by OpenSSL for PEM encryption
    static func evpBytesToKey(password: String, salt: Data, keyLen: Int, ivLen: Int) -> (key: Data, iv: Data) {
        guard let passwordData = password.data(using: .utf8) else {
            return (Data(), Data())
        }
        
        var derived = Data()
        var block = Data()
        
        // Keep generating blocks until we have enough bytes
        while derived.count < (keyLen + ivLen) {
            // First iteration: MD5(password + salt)
            // Subsequent iterations: MD5(previous_block + password + salt)
            let toHash = block + passwordData + salt
            
            // Use MD5 (required for OpenSSL compatibility)
            let digest = Insecure.MD5.hash(data: toHash)
            block = Data(digest)
            derived.append(block)
        }
        
        // Extract key and IV from derived data
        let key = derived.prefix(keyLen)
        let iv = derived.dropFirst(keyLen).prefix(ivLen)
        
        return (key, iv)
    }
    
    /// Generate a random salt
    static func generateSalt() throws -> Data {
        var salt = Data(count: 8)
        let result = salt.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, 8, bytes.baseAddress!)
        }
        
        guard result == errSecSuccess else {
            throw SSHKeyError.randomGenerationFailed
        }
        
        return salt
    }
    
    /// Apply PKCS#7 padding
    static func pkcs7Pad(data: Data, blockSize: Int) -> Data {
        let paddingLength = blockSize - (data.count % blockSize)
        let padding = Data(repeating: UInt8(paddingLength), count: paddingLength)
        return data + padding
    }
    
    /// Remove PKCS#7 padding
    static func pkcs7Unpad(data: Data, blockSize: Int) throws -> Data {
        guard !data.isEmpty else {
            throw SSHKeyError.invalidPadding
        }
        
        let paddingLength = Int(data[data.count - 1])
        
        guard paddingLength > 0 && paddingLength <= blockSize else {
            throw SSHKeyError.invalidPadding
        }
        
        guard data.count >= paddingLength else {
            throw SSHKeyError.invalidPadding
        }
        
        // Verify all padding bytes have the same value
        let paddingStart = data.count - paddingLength
        for i in paddingStart..<data.count {
            if data[i] != UInt8(paddingLength) {
                throw SSHKeyError.invalidPadding
            }
        }
        
        return data.prefix(paddingStart)
    }
    
    /// Encrypt data for PEM format using specified cipher
    /// Returns encrypted data and IV (for DEK-Info header)
    static func encrypt(data: Data, passphrase: String, cipher: PEMCipher) throws -> (encryptedData: Data, iv: Data) {
        // Generate random IV (not salt)
        // Traditional OpenSSL PEM format uses a random IV stored in DEK-Info
        var iv = Data(count: cipher.ivSize)
        let ivResult = iv.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, cipher.ivSize, bytes.baseAddress!)
        }
        guard ivResult == errSecSuccess else {
            throw SSHKeyError.randomGenerationFailed
        }
        
        // Derive key from password using the IV as salt
        // Traditional OpenSSL PEM uses the first 8 bytes of IV as salt for key derivation
        let salt = iv.prefix(8)
        let (key, _) = evpBytesToKey(
            password: passphrase,
            salt: salt,
            keyLen: cipher.keySize,
            ivLen: 0  // We don't need to derive IV, we already have it
        )
        
        // Apply PKCS#7 padding
        let paddedData = pkcs7Pad(data: data, blockSize: cipher.blockSize)
        
        // Encrypt based on cipher
        let encryptedData: Data
        switch cipher {
        case .aes128CBC, .aes192CBC, .aes256CBC:
            encryptedData = try AESCBC.encrypt(data: paddedData, key: key, iv: iv)
        case .des3CBC:
            encryptedData = try TripleDESCBC.encrypt(data: paddedData, key: key, iv: iv)
        }
        
        return (encryptedData, iv)
    }
    
    /// Decrypt PEM encrypted data
    static func decrypt(data: Data, passphrase: String, cipher: PEMCipher, iv: Data) throws -> Data {
        // Use first 8 bytes of IV as salt for key derivation
        let salt = iv.prefix(8)
        
        // Derive only the key from password (IV is provided)
        let (key, _) = evpBytesToKey(
            password: passphrase,
            salt: salt,
            keyLen: cipher.keySize,
            ivLen: 0
        )
        
        // Decrypt based on cipher
        let decryptedData: Data
        switch cipher {
        case .aes128CBC, .aes192CBC, .aes256CBC:
            decryptedData = try AESCBC.decrypt(data: data, key: key, iv: iv)
        case .des3CBC:
            decryptedData = try TripleDESCBC.decrypt(data: data, key: key, iv: iv)
        }
        
        // Remove PKCS#7 padding
        return try pkcs7Unpad(data: decryptedData, blockSize: cipher.blockSize)
    }
    
    /// Format encrypted data as PEM with appropriate headers
    static func formatEncryptedPEM(
        type: String,
        encryptedData: Data,
        cipher: PEMCipher,
        salt: Data
    ) -> String {
        var pem = "-----BEGIN \(type)-----\n"
        pem += "Proc-Type: 4,ENCRYPTED\n"
        pem += "DEK-Info: \(cipher.rawValue),\(salt.hexEncodedString())\n"
        pem += "\n"
        
        // Base64 encode with 64-character lines
        let base64 = encryptedData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        pem += base64
        if !base64.hasSuffix("\n") {
            pem += "\n"
        }
        
        pem += "-----END \(type)-----"
        
        return pem
    }
}

// MARK: - Helper Extensions

extension Data {
    /// Convert data to uppercase hex string
    func hexEncodedString() -> String {
        return map { String(format: "%02X", $0) }.joined()
    }
}
