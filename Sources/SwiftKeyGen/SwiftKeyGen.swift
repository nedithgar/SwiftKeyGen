import Foundation
import Crypto
import _CryptoExtras

public struct SwiftKeyGen {
    
    public static func generateKey(type: KeyType, bits: Int? = nil, comment: String? = nil) throws -> any SSHKey {
        switch type {
        case .ed25519:
            let privateKey = Curve25519.Signing.PrivateKey()
            return Ed25519Key(privateKey: privateKey, comment: comment)
            
        case .rsa:
            let keySize = bits ?? type.defaultBits
            guard [2048, 3072, 4096].contains(keySize) else {
                throw SSHKeyError.invalidKeySize(keySize)
            }
            
            let privateKey: _RSA.Signing.PrivateKey
            switch keySize {
            case 2048:
                privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
            case 3072:
                privateKey = try _RSA.Signing.PrivateKey(keySize: .bits3072)
            case 4096:
                privateKey = try _RSA.Signing.PrivateKey(keySize: .bits4096)
            default:
                throw SSHKeyError.invalidKeySize(keySize)
            }
            return RSAKey(privateKey: privateKey, comment: comment)
            
        case .ecdsa256:
            let privateKey = P256.Signing.PrivateKey()
            return ECDSAKey(p256Key: privateKey, comment: comment)
            
        case .ecdsa384:
            let privateKey = P384.Signing.PrivateKey()
            return ECDSAKey(p384Key: privateKey, comment: comment)
            
        case .ecdsa521:
            let privateKey = P521.Signing.PrivateKey()
            return ECDSAKey(p521Key: privateKey, comment: comment)
        }
    }
    
    public static func generateKeyPair(type: KeyType, bits: Int? = nil, comment: String? = nil) throws -> KeyPair {
        let key = try generateKey(type: type, bits: bits, comment: comment)
        return KeyPair(privateKey: key)
    }
}
