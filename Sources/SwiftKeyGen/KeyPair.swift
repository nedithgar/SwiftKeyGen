import Foundation

public struct KeyPair {
    public let privateKey: any SSHKey
    
    public var publicKeyString: String {
        privateKey.publicKeyString()
    }
    
    public var publicKeyData: Data {
        privateKey.publicKeyData()
    }
    
    public var privateKeyData: Data {
        privateKey.privateKeyData()
    }
    
    public func fingerprint(hash: HashFunction = .sha256, format: FingerprintFormat = .base64) -> String {
        privateKey.fingerprint(hash: hash, format: format)
    }
}