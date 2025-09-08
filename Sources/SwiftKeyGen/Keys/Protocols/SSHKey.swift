import Foundation
import Crypto

public protocol SSHKey {
    var keyType: KeyType { get }
    var comment: String? { get set }
    
    func publicKeyData() -> Data
    func privateKeyData() -> Data
    func publicKeyString() -> String
    func fingerprint(hash: HashFunction, format: FingerprintFormat) -> String
}

public protocol SSHKeyGenerator {
    associatedtype KeyImplementation: SSHKey
    
    static func generate(bits: Int?, comment: String?) throws -> KeyImplementation
}

public enum HashFunction {
    case md5
    case sha256
    case sha512
}

public enum FingerprintFormat {
    case hex
    case base64
    case bubbleBabble
}