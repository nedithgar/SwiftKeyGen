import Foundation

public enum KeyType: String, CaseIterable {
    case rsa = "ssh-rsa"
    case ed25519 = "ssh-ed25519"
    case ecdsa256 = "ecdsa-sha2-nistp256"
    case ecdsa384 = "ecdsa-sha2-nistp384"
    case ecdsa521 = "ecdsa-sha2-nistp521"
    
    public var defaultBits: Int {
        switch self {
        case .rsa:
            return 3072
        case .ed25519:
            return 256
        case .ecdsa256:
            return 256
        case .ecdsa384:
            return 384
        case .ecdsa521:
            return 521
        }
    }
    
    public var algorithmName: String {
        switch self {
        case .rsa:
            return "RSA"
        case .ed25519:
            return "ED25519"
        case .ecdsa256, .ecdsa384, .ecdsa521:
            return "ECDSA"
        }
    }
}