import Foundation

/// Supported SSH key algorithms.
public enum KeyType: String, CaseIterable, Codable {
    case rsa = "ssh-rsa"
    case ed25519 = "ssh-ed25519"
    case ecdsa256 = "ecdsa-sha2-nistp256"
    case ecdsa384 = "ecdsa-sha2-nistp384"
    case ecdsa521 = "ecdsa-sha2-nistp521"
    
    /// Default bit size for this algorithm.
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
    
    /// A human‑readable algorithm family name.
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
