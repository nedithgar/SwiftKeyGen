import Foundation
import Crypto

public struct ECDSAKey: SSHKey {
    public let keyType: KeyType
    public var comment: String?
    
    internal enum PrivateKeyStorage {
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
    }
    
    internal let privateKeyStorage: PrivateKeyStorage
    
    init(p256Key: P256.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa256
        self.privateKeyStorage = .p256(p256Key)
        self.comment = comment
    }
    
    init(p384Key: P384.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa384
        self.privateKeyStorage = .p384(p384Key)
        self.comment = comment
    }
    
    init(p521Key: P521.Signing.PrivateKey, comment: String? = nil) {
        self.keyType = .ecdsa521
        self.privateKeyStorage = .p521(p521Key)
        self.comment = comment
    }
    
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        
        // Encode curve identifier
        let curveIdentifier: String
        let publicKeyData: Data
        
        switch privateKeyStorage {
        case .p256(let key):
            curveIdentifier = "nistp256"
            publicKeyData = key.publicKey.x963Representation
        case .p384(let key):
            curveIdentifier = "nistp384"
            publicKeyData = key.publicKey.x963Representation
        case .p521(let key):
            curveIdentifier = "nistp521"
            publicKeyData = key.publicKey.x963Representation
        }
        
        encoder.encodeString(curveIdentifier)
        encoder.encodeData(publicKeyData)
        
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Return raw private key data for now
        switch privateKeyStorage {
        case .p256(let key):
            return key.rawRepresentation
        case .p384(let key):
            return key.rawRepresentation
        case .p521(let key):
            return key.rawRepresentation
        }
    }
    
    public func publicKeyString() -> String {
        let publicData = publicKeyData()
        var result = keyType.rawValue + " " + publicData.base64EncodedString()
        
        if let comment = comment {
            result += " " + comment
        }
        
        return result
    }
    
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
                return digestData.map { String(format: "%02x", $0) }.joined(separator: ":")
            } else {
                return prefix + digestData.map { String(format: "%02x", $0) }.joined()
            }
            
        case .base64:
            let base64 = digestData.base64EncodedString()
                .trimmingCharacters(in: CharacterSet(charactersIn: "="))
            return prefix + base64
            
        case .bubbleBabble:
            return BubbleBabble.encode(digestData)
        }
    }
    
    func sign(data: Data) throws -> Data {
        // Sign the data (CryptoKit handles hashing internally based on curve)
        let ecdsaSignature: Data
        switch privateKeyStorage {
        case .p256(let key):
            // P256 uses SHA256 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p384(let key):
            // P384 uses SHA384 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p521(let key):
            // P521 uses SHA512 internally
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        }
        
        // Parse r and s from the signature
        let keySize: Int
        switch keyType {
        case .ecdsa256:
            keySize = 32
        case .ecdsa384:
            keySize = 48
        case .ecdsa521:
            keySize = 66
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        guard ecdsaSignature.count == keySize * 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let r = ecdsaSignature.prefix(keySize)
        let s = ecdsaSignature.suffix(keySize)
        
        // Encode in SSH format
        var sigEncoder = SSHEncoder()
        sigEncoder.encodeBigInt(r)
        sigEncoder.encodeBigInt(s)
        
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(sigEncoder.encode())
        
        return encoder.encode()
    }
    
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Create a public-only version of this key and use it for verification
        let publicOnlyKey = self.publicOnlyKey() as! ECDSAPublicKey
        return try publicOnlyKey.verify(signature: signature, for: data)
    }
    
    /// Get raw signature without SSH formatting (for internal use)
    func rawSignature(for data: Data) throws -> Data {
        // Get the raw ECDSA signature
        let ecdsaSignature: Data
        switch privateKeyStorage {
        case .p256(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p384(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        case .p521(let key):
            let signature = try key.signature(for: data)
            ecdsaSignature = signature.rawRepresentation
        }
        
        // Determine key size
        let keySize: Int
        switch keyType {
        case .ecdsa256:
            keySize = 32
        case .ecdsa384:
            keySize = 48
        case .ecdsa521:
            keySize = 66
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        guard ecdsaSignature.count == keySize * 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let r = ecdsaSignature.prefix(keySize)
        let s = ecdsaSignature.suffix(keySize)
        
        // For certificates, we need to return r,s encoded in SSH format
        // This matches what the verifier expects
        var sigEncoder = SSHEncoder()
        sigEncoder.encodeBigInt(r)
        sigEncoder.encodeBigInt(s)
        
        return sigEncoder.encode()
    }
    
    /// PEM representation of the private key in PKCS#8 format
    public var pemRepresentation: String {
        switch privateKeyStorage {
        case .p256(let key):
            return key.pemRepresentation
        case .p384(let key):
            return key.pemRepresentation
        case .p521(let key):
            return key.pemRepresentation
        }
    }
    
    /// Verify raw signature without SSH formatting (for internal use)
    func verifyRawSignature(_ signature: Data, for data: Data) throws -> Bool {
        // Parse the SSH encoded signature (r, s components)
        var decoder = SSHDecoder(data: signature)
        let r = try decoder.decodeData()
        let s = try decoder.decodeData()
        
        // Combine r and s into raw signature format
        let rawSignature = r + s
        
        switch privateKeyStorage {
        case .p256(let key):
            guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        case .p384(let key):
            guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        case .p521(let key):
            guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.publicKey.isValidSignature(ecdsaSignature, for: data)
        }
    }
}

public struct ECDSAKeyGenerator {
    public static func generateP256(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P256.Signing.PrivateKey()
        return ECDSAKey(p256Key: privateKey, comment: comment)
    }
    
    public static func generateP384(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P384.Signing.PrivateKey()
        return ECDSAKey(p384Key: privateKey, comment: comment)
    }
    
    public static func generateP521(comment: String? = nil) throws -> ECDSAKey {
        let privateKey = P521.Signing.PrivateKey()
        return ECDSAKey(p521Key: privateKey, comment: comment)
    }
    
    public static func generate(curve: KeyType, comment: String? = nil) throws -> ECDSAKey {
        switch curve {
        case .ecdsa256:
            return try generateP256(comment: comment)
        case .ecdsa384:
            return try generateP384(comment: comment)
        case .ecdsa521:
            return try generateP521(comment: comment)
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
}