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

public enum SSHKeyError: Error, LocalizedError, Equatable {
    case unsupportedKeyType
    case invalidKeySize(Int, String? = nil)
    case generationFailed(String)
    case serializationFailed(String)
    case invalidKeyData
    case fileOperationFailed(String)
    case invalidFormat
    case passphraseRequired
    case invalidPassphrase
    case unsupportedSignatureAlgorithm
    case unsupportedOperation(String)
    case unsupportedCipher
    case incompatibleSignatureAlgorithm
    
    public var errorDescription: String? {
        switch self {
        case .unsupportedKeyType:
            return "Unsupported key type"
        case .invalidKeySize(let size, let message):
            if let message = message {
                return message
            }
            return "Invalid key size: \(size)"
        case .generationFailed(let reason):
            return "Key generation failed: \(reason)"
        case .serializationFailed(let reason):
            return "Key serialization failed: \(reason)"
        case .invalidKeyData:
            return "Invalid key data"
        case .fileOperationFailed(let reason):
            return "File operation failed: \(reason)"
        case .invalidFormat:
            return "Invalid key format"
        case .passphraseRequired:
            return "Passphrase required for encrypted key"
        case .invalidPassphrase:
            return "Invalid passphrase"
        case .unsupportedSignatureAlgorithm:
            return "Unsupported signature algorithm"
        case .unsupportedOperation(let reason):
            return "Unsupported operation: \(reason)"
        case .unsupportedCipher:
            return "Unsupported cipher"
        case .incompatibleSignatureAlgorithm:
            return "Signature algorithm is not compatible with the key type"
        }
    }
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