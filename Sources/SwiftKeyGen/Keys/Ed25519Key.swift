import Foundation
import Crypto
import _CryptoExtras

public struct Ed25519Key: SSHKey {
    public let keyType = KeyType.ed25519
    public var comment: String?
    
    public let privateKey: Curve25519.Signing.PrivateKey
    
    init(privateKey: Curve25519.Signing.PrivateKey, comment: String? = nil) {
        self.privateKey = privateKey
        self.comment = comment
    }
    
    public init(privateKeyData: Data, comment: String? = nil) throws {
        guard privateKeyData.count == 32 else {
            throw SSHKeyError.invalidKeyData
        }
        self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        self.comment = comment
    }
    
    public func publicKeyData() -> Data {
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(privateKey.publicKey.rawRepresentation)
        return encoder.encode()
    }
    
    public func privateKeyData() -> Data {
        // This returns the raw 32-byte private key seed
        // For full OpenSSH format, we'll implement that separately
        return privateKey.rawRepresentation
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
        let signature = try privateKey.signature(for: data)
        
        // Return SSH formatted signature
        var encoder = SSHEncoder()
        encoder.encodeString(keyType.rawValue)
        encoder.encodeData(Data(signature))
        return encoder.encode()
    }
    
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

public struct Ed25519KeyGenerator: SSHKeyGenerator {
    public static func generate(bits: Int? = nil, comment: String? = nil) throws -> Ed25519Key {
        // Ed25519 has a fixed key size, ignore bits parameter
        let privateKey = Curve25519.Signing.PrivateKey()
        return Ed25519Key(privateKey: privateKey, comment: comment)
    }
}