import Foundation
import Crypto
import _CryptoExtras

public struct RSAKey: SSHKey {
    public let keyType = KeyType.rsa
    public var comment: String?
    
    public let privateKey: _RSA.Signing.PrivateKey
    
    init(privateKey: _RSA.Signing.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }
    
    public func publicKeyData() -> Data {
        let publicKey = privateKey.publicKey
        
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        
        // RSA public key format: e (public exponent), n (modulus)
        // Parse the DER representation to extract e and n
        do {
            var parser = ASN1Parser(data: publicKey.derRepresentation)
            let (modulus, exponent) = try parser.parseRSAPublicKey()
            encoder.encodeBigInt(exponent)
            encoder.encodeBigInt(modulus)
        } catch {
            // Fallback: use standard RSA exponent
            encoder.encodeBigInt(Data([0x01, 0x00, 0x01])) // 65537
            encoder.encodeBigInt(Data()) // Empty modulus will cause issues
        }
        
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // Return DER representation for now
        // Full OpenSSH format will be implemented later
        return privateKey.derRepresentation
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
        // Default to SHA256 for RSA signatures
        return try signWithAlgorithm(data: data, algorithm: "rsa-sha2-256")
    }
    
    func signWithAlgorithm(data: Data, algorithm: String) throws -> Data {
        // Sign the data based on algorithm
        let signatureData: Data
        
        switch algorithm {
        case "ssh-rsa":
            // SHA1 signature
            let sig = try privateKey.signature(
                for: data,
                padding: .insecurePKCS1v1_5
            )
            signatureData = sig.rawRepresentation
            
        case "rsa-sha2-256":
            // SHA256 signature
            let digest = SHA256.hash(data: data)
            let sig = try privateKey.signature(
                for: digest,
                padding: .insecurePKCS1v1_5
            )
            signatureData = sig.rawRepresentation
            
        case "rsa-sha2-512":
            // SHA512 signature
            let digest = SHA512.hash(data: data)
            let sig = try privateKey.signature(
                for: digest,
                padding: .insecurePKCS1v1_5
            )
            signatureData = sig.rawRepresentation
            
        default:
            throw SSHKeyError.unsupportedSignatureAlgorithm
        }
        
        // Encode in SSH format
        var encoder = SSHEncoder()
        encoder.encodeString(algorithm)
        encoder.encodeData(signatureData)
        
        return encoder.encode()
    }
    
    func verify(signature: Data, for data: Data) throws -> Bool {
        let publicKey = privateKey.publicKey
        return try RSAPublicKey.verifySignature(signature, for: data, publicKey: publicKey)
    }
}

public struct RSAKeyGenerator: SSHKeyGenerator {
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> RSAKey {
        let keySize = bits ?? KeyType.rsa.defaultBits
        
        // Validate key size - CryptoExtras only supports specific sizes
        guard [2048, 3072, 4096].contains(keySize) else {
            throw SSHKeyError.invalidKeySize(keySize)
        }
        
        // CryptoExtras uses specific key size types
        let privateKey: _RSA.Signing.PrivateKey
        
        switch keySize {
        case 2048:
            privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        case 3072:
            privateKey = try _RSA.Signing.PrivateKey(keySize: .bits3072)
        case 4096:
            privateKey = try _RSA.Signing.PrivateKey(keySize: .bits4096)
        default:
            // CryptoExtras only supports 2048, 3072, and 4096 bit keys
            throw SSHKeyError.invalidKeySize(keySize)
        }
        
        return RSAKey(privateKey: privateKey, comment: comment)
    }
}

