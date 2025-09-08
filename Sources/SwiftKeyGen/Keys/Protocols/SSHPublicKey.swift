import Foundation

/// Protocol for public-only SSH keys
public protocol SSHPublicKey: SSHKey {
    func verify(signature: Data, for data: Data) throws -> Bool
}