import Foundation
import Crypto

/// High-level factory for generating and converting SSH keys.
///
/// This type exposes the public entry points used by the CLI and library
/// consumers to generate key material and perform common conversions.
public struct SwiftKeyGen {
    
    /// Convert an RSA private key to PKCS#1 PEM.
    ///
    /// - Parameter key: The RSA key to export.
    /// - Returns: A PEM string beginning with "-----BEGIN RSA PRIVATE KEY-----".
    /// - Throws: ``SSHKeyError`` if encoding fails.
    public static func rsaToPEM(_ key: RSAKey) throws -> String {
        return try key.privateKey.pkcs1PEMRepresentation()
    }
    
    /// Convert an RSA public key to PKCS#1 PEM.
    ///
    /// - Parameter key: The RSA key whose public component will be exported.
    /// - Returns: A PEM string beginning with "-----BEGIN RSA PUBLIC KEY-----".
    /// - Throws: ``SSHKeyError`` if encoding fails.
    public static func rsaPublicKeyToPEM(_ key: RSAKey) throws -> String {
        return try key.privateKey.publicKey.pkcs1PEMRepresentation()
    }
    
    /// Generate a new private key of the requested type.
    ///
    /// - Parameters:
    ///   - type: Desired key algorithm.
    ///   - bits: Optional size override for algorithms that support it (e.g. RSA).
    ///   - comment: Optional key comment that will be appended in public output.
    /// - Returns: A concrete type conforming to ``SSHKey``.
    /// - Throws: ``SSHKeyError`` if the generation parameters are invalid.
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
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Generate a new key pair.
    ///
    /// - Parameters:
    ///   - type: Desired key algorithm.
    ///   - bits: Optional size override for algorithms that support it (e.g. RSA).
    ///   - comment: Optional key comment that will be appended in public output.
    /// - Returns: A ``KeyPair`` wrapper containing both private and public material.
    /// - Throws: ``SSHKeyError`` if the generation parameters are invalid.
    public static func generateKeyPair(type: KeyType, bits: Int? = nil, comment: String? = nil) throws -> KeyPair {
        let key = try generateKey(type: type, bits: bits, comment: comment)
        return KeyPair(privateKey: key)
    }
}
