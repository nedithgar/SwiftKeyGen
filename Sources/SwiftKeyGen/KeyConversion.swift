import Foundation
import Crypto
import _CryptoExtras

public enum KeyFormat {
    case openssh
    case pem
    case pkcs8
    case rfc4716
}

public struct KeyConverter {
    
    // RFC4716 format constants
    private static let SSH_COM_PUBLIC_BEGIN = "---- BEGIN SSH2 PUBLIC KEY ----"
    private static let SSH_COM_PUBLIC_END = "---- END SSH2 PUBLIC KEY ----"
    
    /// Convert a key to PEM format
    public static func toPEM(key: any SSHKey, passphrase: String? = nil) throws -> String {
        switch key {
        case let ed25519Key as Ed25519Key:
            return try ed25519ToPEM(ed25519Key, passphrase: passphrase)
            
        case let rsaKey as RSAKey:
            return try rsaToPEM(rsaKey, passphrase: passphrase)
            
        case let ecdsaKey as ECDSAKey:
            return try ecdsaToPEM(ecdsaKey, passphrase: passphrase)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Convert a key to PKCS#8 format
    public static func toPKCS8(key: any SSHKey, passphrase: String? = nil) throws -> Data {
        switch key {
        case let ed25519Key as Ed25519Key:
            return try ed25519ToPKCS8(ed25519Key, passphrase: passphrase)
            
        case let rsaKey as RSAKey:
            return try rsaToPKCS8(rsaKey, passphrase: passphrase)
            
        case let ecdsaKey as ECDSAKey:
            return try ecdsaToPKCS8(ecdsaKey, passphrase: passphrase)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Convert a public key to RFC4716 format
    public static func toRFC4716(key: any SSHKey) throws -> String {
        // Get the public key data
        let publicKeyData = key.publicKeyData()
        
        // Format the comment
        let comment = key.comment ?? "\(NSUserName())@\(ProcessInfo.processInfo.hostName)"
        
        // Build RFC4716 format
        var output = SSH_COM_PUBLIC_BEGIN + "\n"
        output += "Comment: \"\(comment)\"\n"
        
        // Base64 encode with 70-character line width
        let base64 = publicKeyData.base64EncodedString()
        var index = base64.startIndex
        
        while index < base64.endIndex {
            let endIndex = base64.index(index, offsetBy: 70, limitedBy: base64.endIndex) ?? base64.endIndex
            output += String(base64[index..<endIndex]) + "\n"
            index = endIndex
        }
        
        output += SSH_COM_PUBLIC_END
        
        return output
    }
    
    // MARK: - Ed25519 Conversion
    
    private static func ed25519ToPEM(_ key: Ed25519Key, passphrase: String?) throws -> String {
        let privateKeyData = key.privateKeyData()
        
        // Build PEM structure
        var pem = "-----BEGIN PRIVATE KEY-----\n"
        
        // Create PKCS#8 structure for Ed25519
        var pkcs8 = Data()
        
        // Version (0)
        pkcs8.append(contentsOf: [0x30, 0x2e, 0x02, 0x01, 0x00])
        
        // Algorithm identifier for Ed25519
        pkcs8.append(contentsOf: [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70])
        
        // Private key
        pkcs8.append(contentsOf: [0x04, 0x22, 0x04, 0x20])
        pkcs8.append(privateKeyData)
        
        let base64 = pkcs8.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        pem += base64
        pem += "\n-----END PRIVATE KEY-----"
        
        return pem
    }
    
    private static func ed25519ToPKCS8(_ key: Ed25519Key, passphrase: String?) throws -> Data {
        let pem = try ed25519ToPEM(key, passphrase: passphrase)
        return Data(pem.utf8)
    }
    
    // MARK: - RSA Conversion
    
    private static func rsaToPEM(_ key: RSAKey, passphrase: String?) throws -> String {
        // Swift Crypto's RSA private key can export PEM directly
        if passphrase != nil {
            throw SSHKeyError.unsupportedOperation("Encrypted PEM not supported by Swift Crypto")
        }
        
        return key.privateKey.pemRepresentation
    }
    
    private static func rsaToPKCS8(_ key: RSAKey, passphrase: String?) throws -> Data {
        // PKCS#8 wrapper for RSA
        let pem = try rsaToPEM(key, passphrase: passphrase)
        return Data(pem.utf8)
    }
    
    // MARK: - ECDSA Conversion
    
    private static func ecdsaToPEM(_ key: ECDSAKey, passphrase: String?) throws -> String {
        // ECDSA PEM conversion
        let privateKeyData = key.privateKeyData()
        
        var pem = "-----BEGIN EC PRIVATE KEY-----\n"
        let base64 = privateKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        pem += base64
        pem += "\n-----END EC PRIVATE KEY-----"
        
        return pem
    }
    
    private static func ecdsaToPKCS8(_ key: ECDSAKey, passphrase: String?) throws -> Data {
        let pem = try ecdsaToPEM(key, passphrase: passphrase)
        return Data(pem.utf8)
    }
    
    /// Export a key in multiple formats
    public static func exportKey(
        _ key: any SSHKey,
        formats: Set<KeyFormat>,
        basePath: String,
        passphrase: String? = nil
    ) throws -> [KeyFormat: String] {
        var results: [KeyFormat: String] = [:]
        
        for format in formats {
            let path: String
            let data: Data
            
            switch format {
            case .openssh:
                path = basePath
                data = try OpenSSHPrivateKey.serialize(
                    key: key,
                    passphrase: passphrase,
                    comment: key.comment
                )
                
            case .pem:
                path = basePath + ".pem"
                let pemString = try toPEM(key: key, passphrase: passphrase)
                data = Data(pemString.utf8)
                
            case .pkcs8:
                path = basePath + ".p8"
                data = try toPKCS8(key: key, passphrase: passphrase)
                
            case .rfc4716:
                path = basePath + ".rfc"
                let rfc4716String = try toRFC4716(key: key)
                data = Data(rfc4716String.utf8)
            }
            
            try data.write(to: URL(fileURLWithPath: path))
            results[format] = path
        }
        
        return results
    }
}