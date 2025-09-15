import Foundation
import Crypto

/// RSA private key backed by the project’s RSA implementation.
public struct RSAKey: SSHKey {
    public let keyType = KeyType.rsa
    public var comment: String?
    
    public let privateKey: Insecure.RSA.PrivateKey
    
    init(privateKey: Insecure.RSA.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }
    
    /// Return the SSH wire‑format public key (type, e, n).
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        
        let publicKey = privateKey.publicKey
        encoder.encodeBigInt(publicKey.exponentData)
        encoder.encodeBigInt(publicKey.modulusData)
        
        return encoder.encode()
    }
    
    /// Return the raw private key bytes.
    ///
    /// Note: Full OpenSSH private key serialization is handled elsewhere.
    public func privateKeyData() -> Data {
        // Return PKCS#1 DER-encoded RSA private key (RSAPrivateKey)
        // OpenSSH private key container serialization is handled in Formats/OpenSSH
        if let der = try? privateKey.pkcs1DERRepresentation() {
            return der
        }
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
    
    /// Create an SSH‑formatted signature for `data`.
    ///
    /// Uses `rsa-sha2-256` by default.
    func sign(data: Data) throws -> Data {
        // Default to SHA256 for RSA signatures
        return try signWithAlgorithm(data: data, algorithm: "rsa-sha2-256")
    }
    
    /// Create an SSH‑formatted signature for `data` using `algorithm`.
    /// - Parameter algorithm: One of `ssh-rsa`, `rsa-sha2-256`, or `rsa-sha2-512`.
    func signWithAlgorithm(data: Data, algorithm: String) throws -> Data {
        // Sign the data based on algorithm
        let signatureData: Data
        
        switch algorithm {
        case "ssh-rsa":
            // SHA1 signature for legacy compatibility
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha1)
            
        case "rsa-sha2-256":
            // SHA256 signature (recommended)
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha256)
            
        case "rsa-sha2-512":
            // SHA512 signature
            signatureData = try Insecure.RSA.sign(data, with: privateKey, hashAlgorithm: .sha512)
            
        default:
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
        
        // Encode in SSH format
        var encoder = SSHEncoder()
        encoder.encodeString(algorithm)
        encoder.encodeData(signatureData)
        
        return encoder.encode()
    }
    
    /// Verify an SSH‑formatted signature for `data`.
    func verify(signature: Data, for data: Data) throws -> Bool {
        // Parse SSH signature format
        var decoder = SSHDecoder(data: signature)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        
        let publicKey = privateKey.publicKey
        
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
    
    // Helper property for compatibility with existing code
    var pemRepresentation: String {
        do {
            return try privateKey.pkcs1PEMRepresentation()
        } catch {
            // Return empty string if encoding fails
            return ""
        }
    }
}

/// Factory for generating RSA keys with size validation.
public struct RSAKeyGenerator: SSHKeyGenerator {
    // Constants matching OpenSSH
    private static let SSH_RSA_MINIMUM_MODULUS_SIZE = 1024
    private static let OPENSSL_RSA_MAX_MODULUS_BITS = 16384
    
    /// Generate a new RSA private key.
    ///
    /// - Parameters:
    ///   - bits: Modulus size in bits (multiple of 8). Defaults to ``KeyType/defaultBits`` for RSA.
    ///   - comment: Optional key comment to attach.
    /// - Throws: ``SSHKeyError/invalidKeySize(_:_)`` if the size is out of range.
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> RSAKey {
        let keySize = bits ?? KeyType.rsa.defaultBits
        
        // Validate key size according to OpenSSH standards
        guard keySize >= SSH_RSA_MINIMUM_MODULUS_SIZE else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must be at least \(SSH_RSA_MINIMUM_MODULUS_SIZE) bits")
        }
        
        guard keySize <= OPENSSL_RSA_MAX_MODULUS_BITS else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must not exceed \(OPENSSL_RSA_MAX_MODULUS_BITS) bits")
        }
        
        // Ensure key size is a multiple of 8
        guard keySize % 8 == 0 else {
            throw SSHKeyError.invalidKeySize(keySize, "RSA key size must be a multiple of 8")
        }
        
        // Generate RSA key pair using our implementation
        let (privateKey, _) = try Insecure.RSA.generateKeyPair(bitSize: keySize)
        return RSAKey(privateKey: privateKey, comment: comment)
    }
}
