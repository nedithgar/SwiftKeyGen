import Foundation
import Crypto
import BigInt

/// Ed25519 public key (no private key operations)
public struct Ed25519PublicKey: SSHPublicKey {
    public let keyType = KeyType.ed25519
    public var comment: String?
    
    private let publicKey: Curve25519.Signing.PublicKey
    
    /// Initialize from a 32‑byte raw public key.
    /// - Parameters:
    ///   - publicKeyData: The 32‑byte Ed25519 public key.
    ///   - comment: Optional comment appended to the public key string.
    public init(publicKeyData: Data, comment: String? = nil) throws {
        guard publicKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        self.publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        self.comment = comment
    }
    
    /// Return the SSH wire‑format public key (type, 32‑byte key).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(publicKey.rawRepresentation)
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Public-only key has no private key data
        return Data()
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
        // Match OpenSSH behavior: bubblebabble is always over SHA-1
        if format == .bubbleBabble {
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }

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
            // Already handled above
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }
    }
    
    /// Verify a raw Ed25519 signature for `data`.
    public func verify(signature: Data, for data: Data) throws -> Bool {
        // Ed25519 signatures are 64 bytes raw
        guard signature.count == 64 else {
            throw SSHKeyError.invalidSignature
        }
        
        return publicKey.isValidSignature(signature, for: data)
    }
}

/// RSA public key (no private key operations)
public struct RSAPublicKey: SSHPublicKey {
    public let keyType = KeyType.rsa
    public var comment: String?
    
    private let publicKey: Insecure.RSA.PublicKey
    
    /// Initialize from big‑endian modulus (`n`) and exponent (`e`).
    public init(modulus: Data, exponent: Data, comment: String? = nil) throws {
        // Create Insecure.RSA.PublicKey from modulus and exponent
        self.publicKey = try Insecure.RSA.PublicKey(modulus: modulus, exponent: exponent)
        self.comment = comment
    }
    
    /// Return the SSH wire‑format public key (type, e, n).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeBigInt(publicKey.exponentData)
        encoder.encodeBigInt(publicKey.modulusData)
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Public-only key has no private key data
        return Data()
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
        // Match OpenSSH behavior: bubblebabble is always over SHA-1
        if format == .bubbleBabble {
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }

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
            // Already handled above
            return BubbleBabble.encode(publicKey.sha1DataInsecure())
        }
    }
    
    /// Verify an SSH‑formatted RSA signature for `data`.
    public func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        // Verify based on signature type
        switch signatureType {
        case "ssh-rsa":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha1)
        case "rsa-sha2-256":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha256)
        case "rsa-sha2-512":
            return try Insecure.RSA.verify(signatureBlob, for: data, with: publicKey, hashAlgorithm: .sha512)
        default:
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
    }
}

/// ECDSA public key (no private key operations)
public struct ECDSAPublicKey: SSHPublicKey {
    public let keyType: KeyType
    public var comment: String?
    
    private let curveName: String
    private let publicKeyPoint: Data
    
    private enum PublicKeyStorage {
        case p256(P256.Signing.PublicKey)
        case p384(P384.Signing.PublicKey)
        case p521(P521.Signing.PublicKey)
    }
    private let publicKey: PublicKeyStorage?
    
    /// Initialize from a curve name and uncompressed EC point in X9.63 format.
    /// - Parameters:
    ///   - keyType: Must be one of ``KeyType/ecdsa256``, ``KeyType/ecdsa384``, or ``KeyType/ecdsa521``.
    ///   - curveName: OpenSSH curve identifier (e.g. "nistp256").
    ///   - publicKeyPoint: Uncompressed point bytes starting with 0x04.
    ///   - comment: Optional comment appended to the public key string.
    public init(keyType: KeyType, curveName: String, publicKeyPoint: Data, comment: String? = nil) throws {
        guard [.ecdsa256, .ecdsa384, .ecdsa521].contains(keyType) else {
            throw SSHKeyError.unsupportedKeyType
        }
        
        self.keyType = keyType
        self.curveName = curveName
        self.publicKeyPoint = publicKeyPoint
        self.comment = comment
        
        // Try to create the appropriate public key from the point
        switch keyType {
        case .ecdsa256:
            if let key = try? P256.Signing.PublicKey(x963Representation: publicKeyPoint) {
                self.publicKey = .p256(key)
            } else {
                self.publicKey = nil
            }
        case .ecdsa384:
            if let key = try? P384.Signing.PublicKey(x963Representation: publicKeyPoint) {
                self.publicKey = .p384(key)
            } else {
                self.publicKey = nil
            }
        case .ecdsa521:
            if let key = try? P521.Signing.PublicKey(x963Representation: publicKeyPoint) {
                self.publicKey = .p521(key)
            } else {
                self.publicKey = nil
            }
        default:
            self.publicKey = nil
        }
    }
    
    /// Return the SSH wire‑format public key (type, curve, point).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeString(curveName)
        encoder.encodeData(publicKeyPoint)
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Public-only key has no private key data
        return Data()
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
    
    /// Verify an SSH‑formatted ECDSA signature for `data`.
    public func verify(signature: Data, for data: Data) throws -> Bool {
        guard let publicKey = publicKey else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        // Verify that signature type matches key type
        guard signatureType == keyType.rawValue else {
            throw SSHKeyError.signatureMismatch
        }
        
        // Parse ECDSA signature (r,s values)
        var sigDecoder = SSHDecoder(data: signatureBlob)
        let r = try sigDecoder.decodeData()
        let s = try sigDecoder.decodeData()
        
        // Ensure r and s are the correct size (mpint can add/remove leading 0x00)
        switch publicKey {
        case .p256(let key):
            // P256 uses 32-byte values
            let combined = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 32)
            
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: combined)
            return key.isValidSignature(signature, for: data)
            
        case .p384(let key):
            // P384 uses 48-byte values
            let combined = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 48)
            
            let signature = try P384.Signing.ECDSASignature(rawRepresentation: combined)
            return key.isValidSignature(signature, for: data)
            
        case .p521(let key):
            // P521 uses 66-byte values
            let combined = ECDSAEncoding.rawSignature(r: r, s: s, componentLength: 66)
            
            let signature = try P521.Signing.ECDSASignature(rawRepresentation: combined)
            return key.isValidSignature(signature, for: data)
        }
    }
}

// MARK: - Extensions

extension SSHKey {
    /// Create a public‑only key value from a private key.
    public func publicOnlyKey() -> any SSHPublicKey {
        switch self {
        case let ed25519Key as Ed25519Key:
            // Extract public key data from Ed25519Key
            let publicKeyData = ed25519Key.publicKeyData()
            var decoder = SSHDecoder(data: publicKeyData)
            _ = try! decoder.decodeString() // Skip key type
            let rawPublicKey = try! decoder.decodeData()
            
            return try! Ed25519PublicKey(
                publicKeyData: rawPublicKey,
                comment: ed25519Key.comment
            )
            
        case let rsaKey as RSAKey:
            // Extract modulus and exponent from public key data
            let publicData = rsaKey.publicKeyData()
            var decoder = SSHDecoder(data: publicData)
            _ = try! decoder.decodeString() // Skip type
            let e = try! decoder.decodeData()
            let n = try! decoder.decodeData()
            
            return try! RSAPublicKey(
                modulus: n,
                exponent: e,
                comment: rsaKey.comment
            )
            
        case let ecdsaKey as ECDSAKey:
            // Extract curve and point from public key data
            let publicData = ecdsaKey.publicKeyData()
            var decoder = SSHDecoder(data: publicData)
            _ = try! decoder.decodeString() // Skip type
            let curveName = try! decoder.decodeString()
            let publicPoint = try! decoder.decodeData()
            
            return try! ECDSAPublicKey(
                keyType: ecdsaKey.keyType,
                curveName: curveName,
                publicKeyPoint: publicPoint,
                comment: ecdsaKey.comment
            )
            
        default:
            fatalError("Unknown key type")
        }
    }
}
