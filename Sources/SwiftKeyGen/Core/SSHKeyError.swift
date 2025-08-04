import Foundation

/// Errors that can occur during SSH key operations
public enum SSHKeyError: Error, LocalizedError, Equatable {
    case invalidKeyData
    case invalidKeySize(Int, String)
    case unsupportedKeyType
    case unsupportedOperation(String)
    case unsupportedSignatureAlgorithm
    case invalidSignature
    case invalidCertificate
    case invalidPadding
    case passphraseRequired
    case wrongPassphrase
    case encryptionFailed
    case decryptionFailed
    case randomGenerationFailed
    case invalidFingerprint
    case invalidComment
    case fileNotFound(String)
    case fileReadError(String)
    case fileWriteError(String)
    case permissionDenied(String)
    case conversionError(String)
    case parsingError(String)
    case encodingError(String)
    case invalidFormat
    case unsupportedCipher(String)
    case invalidPassphrase
    case incompatibleSignatureAlgorithm
    case certificateNotSigned
    case serializationFailed(String)
    case fileOperationFailed(String)
    case generationFailed(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeyData:
            return "Invalid key data"
        case .invalidKeySize(let size, let message):
            return "Invalid key size \(size): \(message)"
        case .unsupportedKeyType:
            return "Unsupported key type"
        case .unsupportedOperation(let operation):
            return "Unsupported operation: \(operation)"
        case .unsupportedSignatureAlgorithm:
            return "Unsupported signature algorithm"
        case .invalidSignature:
            return "Invalid signature"
        case .invalidCertificate:
            return "Invalid certificate"
        case .invalidPadding:
            return "Invalid padding"
        case .passphraseRequired:
            return "Passphrase required for encrypted key"
        case .wrongPassphrase:
            return "Wrong passphrase"
        case .encryptionFailed:
            return "Encryption failed"
        case .decryptionFailed:
            return "Decryption failed"
        case .randomGenerationFailed:
            return "Random number generation failed"
        case .invalidFingerprint:
            return "Invalid fingerprint"
        case .invalidComment:
            return "Invalid comment"
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .fileReadError(let path):
            return "Error reading file: \(path)"
        case .fileWriteError(let path):
            return "Error writing file: \(path)"
        case .permissionDenied(let path):
            return "Permission denied: \(path)"
        case .conversionError(let message):
            return "Conversion error: \(message)"
        case .parsingError(let message):
            return "Parsing error: \(message)"
        case .encodingError(let message):
            return "Encoding error: \(message)"
        case .invalidFormat:
            return "Invalid format"
        case .unsupportedCipher(let cipher):
            return "Unsupported cipher: \(cipher)"
        case .invalidPassphrase:
            return "Invalid passphrase"
        case .incompatibleSignatureAlgorithm:
            return "Signature algorithm is not compatible with the key type"
        case .certificateNotSigned:
            return "Certificate is not signed"
        case .serializationFailed(let reason):
            return "Key serialization failed: \(reason)"
        case .fileOperationFailed(let reason):
            return "File operation failed: \(reason)"
        case .generationFailed(let reason):
            return "Key generation failed: \(reason)"
        }
    }
}