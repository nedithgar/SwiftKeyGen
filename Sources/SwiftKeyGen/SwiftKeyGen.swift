import Foundation
import Crypto

public struct SwiftKeyGen {
    
    /// Convert RSA key to PEM format
    public static func rsaToPEM(_ key: RSAKey) throws -> String {
        return try key.privateKey.pkcs1PEMRepresentation()
    }
    
    /// Convert RSA public key to PEM format
    public static func rsaPublicKeyToPEM(_ key: RSAKey) throws -> String {
        return try key.privateKey.publicKey.pkcs1PEMRepresentation()
    }
    
    public static func generateKey(type: KeyType, bits: Int? = nil, comment: String? = nil) throws -> any SSHKey {
        switch type {
        case .ed25519:
            let privateKey = Curve25519.Signing.PrivateKey()
            return Ed25519Key(privateKey: privateKey, comment: comment)
            
        case .rsa:
            return try RSAKeyGenerator.generate(bits: bits, comment: comment)
            
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
