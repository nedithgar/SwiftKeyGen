import Foundation
import Crypto
import _CryptoExtras

/// Ed25519 private key using CryptoKit.
public struct Ed25519Key: SSHKey {
    public let keyType = KeyType.ed25519
    public var comment: String?
    
    public let privateKey: Curve25519.Signing.PrivateKey
    
    init(privateKey: Curve25519.Signing.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }
    
    /// Initialize from a 32‑byte raw private key seed.
    public init(privateKeyData: Data, comment: String? = nil) throws {
        guard privateKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        self.comment = comment
    }
    
    /// Return the SSH wire‑format public key (type, 32‑byte key).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(privateKey.publicKey.rawRepresentation)
        return encoder.encode()
    }
    
    /// Return the raw 32‑byte private key seed.
    public func privateKeyData() -> Data {
        // For full OpenSSH format, we'll implement that separately
        return privateKey.rawRepresentation
    }
    
    /// Return the OpenSSH public key string for `authorized_keys`.
    public func publicKeyString() -> String {
        let publicData = publicKeyData()
        var result = keyType.rawValue + " " + publicData.base64EncodedString()
        
        if let comment = comment {
            result += " " + comment
        }
        
        return result
    }
    
    /// Compute a fingerprint for the public key.
    public func fingerprint(hash: HashFunction, format: FingerprintFormat = .base64) -> String {
        let publicKey = publicKeyData()
        let digestData: Data
        let prefix: String
        
        switch hash {
        case .md5:
            let digest = Insecure.MD5.hash(data: publicKey)
            digestData = Data(digest)
            prefix = ""
            
        case .sha256:
            let digest = SHA256.hash(data: publicKey)
            digestData = Data(digest)
            prefix = "SHA256:"
            
        case .sha512:
            let digest = SHA512.hash(data: publicKey)
            digestData = Data(digest)
            prefix = "SHA512:"
        }
        
        switch format {
        case .hex:
            if hash == .md5 {
                return digestData.hexEncodedString(separator: ":")
            } else {
                return prefix + digestData.hexEncodedString()
            }

        case .base64:
            let base64 = digestData.base64EncodedStringStrippingPadding()
            return prefix + base64
            
        case .bubbleBabble:
            return BubbleBabble.encode(digestData)
        }
    }
    
    /// Create an SSH‑formatted signature for `data`.
    func sign(data: Data) throws -> Data {
        let signature = try privateKey.signature(for: data)
        
        // Return SSH formatted signature
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(Data(signature))
        return encoder.encode()
    }
    
    /// Verify a signature for `data`.
    ///
    /// Accepts either raw Ed25519 signatures or SSH‑formatted signatures.
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format if needed
        if signature.count > 4 {
            var decoder = SSHDecoder(data: signature)
            if let sigType = try? decoder.decodeString() {
                // This is SSH format, extract the actual signature
                if sigType == keyType.rawValue,
                   let sigData = try? decoder.decodeData() {
                    return privateKey.publicKey.isValidSignature(sigData, for: data)
                }
            }
        }
        // Fall back to raw signature
        return privateKey.publicKey.isValidSignature(signature, for: data)
    }
}

/// Factory for generating Ed25519 keys.
public struct Ed25519KeyGenerator: SSHKeyGenerator {
    /// Generate a new Ed25519 private key. The `bits` parameter is ignored.
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> Ed25519Key {
        // Ed25519 has a fixed key size, ignore bits parameter
        let privateKey = Curve25519.Signing.PrivateKey()
        return Ed25519Key(privateKey: privateKey, comment: comment)
    }
}
