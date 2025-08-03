import Foundation
import Crypto
import _CryptoExtras

/// Protocol for public-only SSH keys
public protocol SSHPublicKey: SSHKey {
    func verify(signature: Data, for data: Data) throws -> Bool
}


/// Ed25519 public key (no private key operations)
public struct Ed25519PublicKey: SSHPublicKey {
    public let keyType = KeyType.ed25519
    public var comment: String?
    
    private let publicKey: Curve25519.Signing.PublicKey
    
    public init(publicKeyData: Data, comment: String? = nil) throws {
        guard publicKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        self.publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        self.comment = comment
    }
    
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
    
    public func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format if needed
        if signature.count > 4 {
            var decoder = SSHDecoder(data: signature)
            if let sigType = try? decoder.decodeString() {
                // This is SSH format, extract the actual signature
                if sigType == keyType.rawValue,
                   let sigData = try? decoder.decodeData() {
                    return publicKey.isValidSignature(sigData, for: data)
                }
            }
        }
        // Fall back to raw signature
        return publicKey.isValidSignature(signature, for: data)
    }
}

/// RSA public key (no private key operations)
public struct RSAPublicKey: SSHPublicKey {
    public let keyType = KeyType.rsa
    public var comment: String?
    
    private let modulus: Data
    private let exponent: Data
    private let publicKey: _RSA.Signing.PublicKey?
    
    public init(modulus: Data, exponent: Data, comment: String? = nil) throws {
        self.modulus = modulus
        self.exponent = exponent
        self.comment = comment
        
        // Try to create public key from modulus and exponent
        self.publicKey = Self.createPublicKey(modulus: modulus, exponent: exponent)
    }
    
    private static func createPublicKey(modulus: Data, exponent: Data) -> _RSA.Signing.PublicKey? {
        // Create ASN.1 DER representation of RSA public key
        var derBytes = Data()
        
        // SEQUENCE
        derBytes.append(0x30)
        
        // Calculate length of content
        var content = Data()
        
        // Encode modulus as INTEGER
        content.append(0x02) // INTEGER tag
        if modulus.first ?? 0 >= 0x80 {
            // Add leading zero byte for positive number
            content.append(contentsOf: encodeDERLength(modulus.count + 1))
            content.append(0x00)
        } else {
            content.append(contentsOf: encodeDERLength(modulus.count))
        }
        content.append(modulus)
        
        // Encode exponent as INTEGER
        content.append(0x02) // INTEGER tag
        if exponent.first ?? 0 >= 0x80 {
            // Add leading zero byte for positive number
            content.append(contentsOf: encodeDERLength(exponent.count + 1))
            content.append(0x00)
        } else {
            content.append(contentsOf: encodeDERLength(exponent.count))
        }
        content.append(exponent)
        
        // Add length of SEQUENCE
        derBytes.append(contentsOf: encodeDERLength(content.count))
        derBytes.append(content)
        
        // Try to create public key from DER
        return try? _RSA.Signing.PublicKey(derRepresentation: derBytes)
    }
    
    private static func encodeDERLength(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length < 256 {
            return Data([0x81, UInt8(length)])
        } else {
            // For larger lengths (up to 65535)
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        }
    }
    
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeBigInt(exponent)
        encoder.encodeBigInt(modulus)
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Public-only key has no private key data
        return Data()
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
    
    public func verify(signature: Data, for data: Data) throws -> Bool {
        guard let publicKey = publicKey else {
            // Fallback for cases where we couldn't create the public key
            throw SSHKeyError.invalidKeyData
        }
        
        return try Self.verifySignature(signature, for: data, publicKey: publicKey)
    }
    
    static func verifySignature(_ signature: Data, for data: Data, publicKey: _RSA.Signing.PublicKey) throws -> Bool {
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        // Create RSA signature from blob
        guard let rsaSignature = try? _RSA.Signing.RSASignature(rawRepresentation: signatureBlob) else {
            return false
        }
        
        // Verify based on signature algorithm
        switch signatureType {
        case "ssh-rsa":
            // SHA1 signature verification
            return publicKey.isValidSignature(rsaSignature, for: data, padding: .insecurePKCS1v1_5)
            
        case "rsa-sha2-256":
            // SHA256 signature verification
            let digest = SHA256.hash(data: data)
            return publicKey.isValidSignature(rsaSignature, for: digest, padding: .insecurePKCS1v1_5)
            
        case "rsa-sha2-512":
            // SHA512 signature verification  
            let digest = SHA512.hash(data: data)
            return publicKey.isValidSignature(rsaSignature, for: digest, padding: .insecurePKCS1v1_5)
            
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
    
    public init(keyType: KeyType, curveName: String, publicKeyPoint: Data, comment: String? = nil) throws {
        guard [.ecdsa256, .ecdsa384, .ecdsa521].contains(keyType) else {
            throw SSHKeyError.unsupportedKeyType
        }
        
        self.keyType = keyType
        self.curveName = curveName
        self.publicKeyPoint = publicKeyPoint
        self.comment = comment
        
        // Try to create the public key from the point data
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
    
    public func verify(signature: Data, for data: Data) throws -> Bool {
        guard let publicKey = publicKey else {
            throw SSHKeyError.invalidKeyData
        }
        
        switch publicKey {
        case .p256(let key):
            return try Self.verifySignature(signature, for: data, keyType: keyType, publicKey: key)
        case .p384(let key):
            return try Self.verifySignature(signature, for: data, keyType: keyType, publicKey: key)
        case .p521(let key):
            return try Self.verifySignature(signature, for: data, keyType: keyType, publicKey: key)
        }
    }
    
    static func verifySignature<T>(_ signature: Data, for data: Data, keyType: KeyType, publicKey: T) throws -> Bool {
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        // Verify signature type matches key type
        guard signatureType == keyType.rawValue else {
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
        
        // Parse r and s from signature blob
        var sigDecoder = SSHDecoder(data: signatureBlob)
        let r = try sigDecoder.decodeData()
        let s = try sigDecoder.decodeData()
        
        // Get key size
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
        
        // Ensure r and s are the correct size
        // BigInt encoding may add/remove bytes, so we need to handle both cases
        let paddedR: Data
        let paddedS: Data
        
        if r.count < keySize {
            // Pad with zeros at the beginning if too small
            paddedR = Data(repeating: 0, count: keySize - r.count) + r
        } else if r.count > keySize {
            // If larger, check if it's just a leading zero for sign
            if r.count == keySize + 1 && r[0] == 0 {
                // Remove the leading zero
                paddedR = r.dropFirst()
            } else {
                // Otherwise take the last keySize bytes
                paddedR = r.suffix(keySize)
            }
        } else {
            paddedR = r
        }
        
        if s.count < keySize {
            // Pad with zeros at the beginning if too small
            paddedS = Data(repeating: 0, count: keySize - s.count) + s
        } else if s.count > keySize {
            // If larger, check if it's just a leading zero for sign
            if s.count == keySize + 1 && s[0] == 0 {
                // Remove the leading zero
                paddedS = s.dropFirst()
            } else {
                // Otherwise take the last keySize bytes
                paddedS = s.suffix(keySize)
            }
        } else {
            paddedS = s
        }
        
        // Validate sizes before combining
        guard paddedR.count == keySize && paddedS.count == keySize else {
            return false
        }
        
        // Combine r and s
        let rawSignature = paddedR + paddedS
        
        // Verify the signature based on key type (CryptoKit handles hashing internally)
        if let p256Key = publicKey as? P256.Signing.PublicKey {
            if let sig = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature) {
                return p256Key.isValidSignature(sig, for: data)
            }
        } else if let p384Key = publicKey as? P384.Signing.PublicKey {
            if let sig = try? P384.Signing.ECDSASignature(rawRepresentation: rawSignature) {
                return p384Key.isValidSignature(sig, for: data)
            }
        } else if let p521Key = publicKey as? P521.Signing.PublicKey {
            if let sig = try? P521.Signing.ECDSASignature(rawRepresentation: rawSignature) {
                return p521Key.isValidSignature(sig, for: data)
            }
        }
        
        return false
    }
}

// Extension to create public-only keys from full keys
extension SSHKey {
    /// Create a public-only version of this key
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
            // Note: This will always succeed as RSAPublicKey init doesn't actually throw in our implementation
            return try! RSAPublicKey(modulus: n, exponent: e, comment: rsaKey.comment)
            
        case let ecdsaKey as ECDSAKey:
            // Extract curve and point from public key data
            let publicData = ecdsaKey.publicKeyData()
            var decoder = SSHDecoder(data: publicData)
            _ = try! decoder.decodeString() // Skip type
            let curve = try! decoder.decodeString()
            let point = try! decoder.decodeData()
            return try! ECDSAPublicKey(
                keyType: ecdsaKey.keyType,
                curveName: curve,
                publicKeyPoint: point,
                comment: ecdsaKey.comment
            )
            
        default:
            fatalError("Unsupported key type for public-only conversion")
        }
    }
}