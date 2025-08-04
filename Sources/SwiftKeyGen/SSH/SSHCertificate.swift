import Foundation
import Crypto
import _CryptoExtras

/// SSH Certificate types
public enum SSHCertificateType: UInt32 {
    case user = 1
    case host = 2
    
    var description: String {
        switch self {
        case .user: return "user"
        case .host: return "host"
        }
    }
}

/// Critical options for SSH certificates
public enum SSHCertificateOption: String {
    case forceCommand = "force-command"
    case sourceAddress = "source-address"
    case verifyRequired = "verify-required"
}

/// Extensions for SSH certificates
public enum SSHCertificateExtension: String {
    case permitX11Forwarding = "permit-X11-forwarding"
    case permitAgentForwarding = "permit-agent-forwarding"
    case permitPortForwarding = "permit-port-forwarding"
    case permitPty = "permit-pty"
    case permitUserRc = "permit-user-rc"
    case noTouchRequired = "no-touch-required"
}

/// SSH Certificate structure
public struct SSHCertificate {
    // Certificate data
    public var certBlob: Data?
    public var type: SSHCertificateType
    public var serial: UInt64
    public var keyId: String
    public var principals: [String]
    public var validAfter: UInt64  // Unix timestamp
    public var validBefore: UInt64 // Unix timestamp
    public var criticalOptions: [(String, String)]
    public var extensions: [String]
    public var signatureKey: (any SSHKey)?
    public var signatureType: String?
    
    /// Maximum number of principals allowed
    public static let maxPrincipals = 256
    
    public init(type: SSHCertificateType) {
        self.type = type
        self.serial = 0
        self.keyId = ""
        self.principals = []
        self.validAfter = 0
        self.validBefore = UInt64.max
        self.criticalOptions = []
        self.extensions = []
    }
    
    /// Set validity period
    public mutating func setValidity(from: Date, to: Date) {
        self.validAfter = UInt64(from.timeIntervalSince1970)
        self.validBefore = UInt64(to.timeIntervalSince1970)
    }
    
    /// Add a critical option
    public mutating func addCriticalOption(_ option: SSHCertificateOption, value: String) {
        criticalOptions.append((option.rawValue, value))
    }
    
    /// Add an extension
    public mutating func addExtension(_ ext: SSHCertificateExtension) {
        extensions.append(ext.rawValue)
    }
    
    /// Check if certificate is valid at a given time
    public func isValid(at date: Date = Date()) -> Bool {
        let timestamp = UInt64(date.timeIntervalSince1970)
        return timestamp >= validAfter && timestamp <= validBefore
    }
    
    /// Format validity period as string
    public func formatValidity() -> String {
        if validAfter == 0 && validBefore == UInt64.max {
            return "forever"
        } else if validBefore == UInt64.max {
            let from = Date(timeIntervalSince1970: Double(validAfter))
            return "from \(formatDate(from)) to forever"
        } else if validAfter == 0 {
            let to = Date(timeIntervalSince1970: Double(validBefore))
            return "from always to \(formatDate(to))"
        } else {
            let from = Date(timeIntervalSince1970: Double(validAfter))
            let to = Date(timeIntervalSince1970: Double(validBefore))
            return "from \(formatDate(from)) to \(formatDate(to))"
        }
    }
    
    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }
    
    /// Encode critical options to SSH wire format
    func encodeCriticalOptions() -> Data {
        var encoder = SSHEncoder()
        
        for (name, value) in criticalOptions {
            encoder.encodeString(name)
            
            var optionEncoder = SSHEncoder()
            optionEncoder.encodeString(value)
            encoder.encodeData(optionEncoder.encode())
        }
        
        return encoder.encode()
    }
    
    /// Encode extensions to SSH wire format
    func encodeExtensions() -> Data {
        var encoder = SSHEncoder()
        
        for name in extensions {
            encoder.encodeString(name)
            encoder.encodeData(Data()) // Empty data for boolean extensions
        }
        
        return encoder.encode()
    }
}

/// Extension to make SSHKey certificable
public extension SSHKey {
    /// Convert key to certified key
    func toCertified(type: SSHCertificateType = .user) -> CertifiedKey {
        return CertifiedKey(key: self, certificateType: type)
    }
}

/// A key with an attached certificate
public class CertifiedKey {
    public let originalKey: any SSHKey
    public var certificate: SSHCertificate
    public private(set) var certifiedKeyType: String
    
    public init(key: any SSHKey, certificateType: SSHCertificateType = .user) {
        self.originalKey = key
        self.certificate = SSHCertificate(type: certificateType)
        
        // Determine certified key type
        switch key.keyType {
        case .ed25519:
            self.certifiedKeyType = "ssh-ed25519-cert-v01@openssh.com"
        case .rsa:
            self.certifiedKeyType = "ssh-rsa-cert-v01@openssh.com"
        case .ecdsa256:
            self.certifiedKeyType = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        case .ecdsa384:
            self.certifiedKeyType = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        case .ecdsa521:
            self.certifiedKeyType = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
        }
    }
    
    /// Get the public key data in certificate format
    public func publicKeyData() throws -> Data {
        guard let certBlob = certificate.certBlob else {
            throw SSHKeyError.certificateNotSigned
        }
        
        var encoder = SSHEncoder()
        encoder.encodeString(certifiedKeyType)
        encoder.encodeData(certBlob)
        
        return encoder.encode()
    }
    
    /// Get the certificate as a public key string (for .pub files)
    public func publicKeyString() -> String {
        guard let certBlob = certificate.certBlob else {
            return ""
        }
        
        // For .pub files, we need the certificate type string IN the blob
        // So we create a new blob with the type string prepended
        var encoder = SSHEncoder()
        encoder.encodeString(certifiedKeyType)
        encoder.data.append(certBlob)
        
        let base64 = encoder.encode().base64EncodedString()
        var result = "\(certifiedKeyType) \(base64)"
        
        if !certificate.keyId.isEmpty {
            result += " \(certificate.keyId)"
        } else if let comment = originalKey.comment {
            result += " \(comment)"
        }
        
        return result
    }
    
    /// Get the certificate info as a string
    public func certificateInfo() -> String {
        var info = "Type: \(certifiedKeyType) \(certificate.type.description) certificate\n"
        info += "Key ID: \"\(certificate.keyId)\"\n"
        info += "Serial: \(certificate.serial)\n"
        info += "Valid: \(certificate.formatValidity())\n"
        
        info += "Principals:\n"
        if certificate.principals.isEmpty {
            info += "    (none)\n"
        } else {
            for principal in certificate.principals {
                info += "    \(principal)\n"
            }
        }
        
        info += "Critical Options:\n"
        if certificate.criticalOptions.isEmpty {
            info += "    (none)\n"
        } else {
            for (option, value) in certificate.criticalOptions {
                info += "    \(option) \(value)\n"
            }
        }
        
        info += "Extensions:\n"
        if certificate.extensions.isEmpty {
            info += "    (none)\n"
        } else {
            for ext in certificate.extensions {
                info += "    \(ext)\n"
            }
        }
        
        if let signatureKey = certificate.signatureKey {
            let fingerprint = signatureKey.fingerprint(hash: .sha256, format: .base64)
            info += "Signing CA: \(signatureKey.keyType.rawValue) \(fingerprint)"
            if let sigType = certificate.signatureType {
                info += " (using \(sigType))"
            }
            info += "\n"
        }
        
        return info
    }
}

