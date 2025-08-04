import Foundation
import Crypto
import _CryptoExtras

/// Certificate Authority for signing SSH certificates
public struct CertificateAuthority {
    
    /// Sign a public key to create a certificate
    public static func signCertificate(
        publicKey: any SSHKey,
        caKey: any SSHKey,
        keyId: String,
        principals: [String] = [],
        serial: UInt64? = nil,
        validFrom: Date = Date(),
        validTo: Date? = nil,
        certificateType: SSHCertificateType = .user,
        criticalOptions: [(SSHCertificateOption, String)] = [],
        extensions: [SSHCertificateExtension] = [],
        signatureAlgorithm: String? = nil
    ) throws -> CertifiedKey {
        // Validate inputs
        guard principals.count <= SSHCertificate.maxPrincipals else {
            throw SSHKeyError.tooManyPrincipals
        }
        
        // Create certified key
        let certifiedKey = publicKey.toCertified(type: certificateType)
        
        // Configure certificate
        certifiedKey.certificate.keyId = keyId
        certifiedKey.certificate.principals = principals
        certifiedKey.certificate.serial = serial ?? generateSerial()
        
        // Set validity period
        let defaultValidityDays = certificateType == .host ? 365 : 30
        let validUntil = validTo ?? validFrom.addingTimeInterval(Double(defaultValidityDays) * 24 * 60 * 60)
        certifiedKey.certificate.setValidity(from: validFrom, to: validUntil)
        
        // Add critical options
        for (option, value) in criticalOptions {
            certifiedKey.certificate.addCriticalOption(option, value: value)
        }
        
        // Add extensions - default extensions based on certificate type
        var finalExtensions = extensions
        if finalExtensions.isEmpty {
            if certificateType == .user {
                // Default user certificate extensions
                finalExtensions = [
                    .permitX11Forwarding,
                    .permitAgentForwarding,
                    .permitPortForwarding,
                    .permitPty,
                    .permitUserRc
                ]
            }
            // Host certificates typically have no default extensions
        }
        
        for ext in finalExtensions {
            certifiedKey.certificate.addExtension(ext)
        }
        
        // Set signature key
        certifiedKey.certificate.signatureKey = caKey
        
        // Determine signature algorithm
        let finalSignatureAlgorithm: String
        if let providedAlgorithm = signatureAlgorithm {
            // Validate the provided algorithm is compatible with the CA key type
            switch caKey.keyType {
            case .rsa:
                guard ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"].contains(providedAlgorithm) else {
                    throw SSHKeyError.incompatibleSignatureAlgorithm
                }
            case .ed25519:
                guard providedAlgorithm == "ssh-ed25519" else {
                    throw SSHKeyError.incompatibleSignatureAlgorithm
                }
            case .ecdsa256:
                guard providedAlgorithm == "ecdsa-sha2-nistp256" else {
                    throw SSHKeyError.incompatibleSignatureAlgorithm
                }
            case .ecdsa384:
                guard providedAlgorithm == "ecdsa-sha2-nistp384" else {
                    throw SSHKeyError.incompatibleSignatureAlgorithm
                }
            case .ecdsa521:
                guard providedAlgorithm == "ecdsa-sha2-nistp521" else {
                    throw SSHKeyError.incompatibleSignatureAlgorithm
                }
            }
            finalSignatureAlgorithm = providedAlgorithm
        } else {
            // Use default algorithm for the key type
            switch caKey.keyType {
            case .rsa:
                finalSignatureAlgorithm = "rsa-sha2-512"  // Default to SHA-512 like OpenSSH
            case .ed25519:
                finalSignatureAlgorithm = "ssh-ed25519"
            case .ecdsa256:
                finalSignatureAlgorithm = "ecdsa-sha2-nistp256"
            case .ecdsa384:
                finalSignatureAlgorithm = "ecdsa-sha2-nistp384"
            case .ecdsa521:
                finalSignatureAlgorithm = "ecdsa-sha2-nistp521"
            }
        }
        certifiedKey.certificate.signatureType = finalSignatureAlgorithm
        
        // Generate the certificate blob
        let certBlob = try generateCertificateBlob(
            certifiedKey: certifiedKey,
            caKey: caKey,
            signatureAlgorithm: finalSignatureAlgorithm
        )
        
        certifiedKey.certificate.certBlob = certBlob
        
        return certifiedKey
    }
    
    /// Generate certificate blob
    private static func generateCertificateBlob(
        certifiedKey: CertifiedKey,
        caKey: any SSHKey,
        signatureAlgorithm: String
    ) throws -> Data {
        let publicKey = certifiedKey.originalKey
        let certificate = certifiedKey.certificate
        // Generate random nonce
        var nonce = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            nonce[i] = UInt8.random(in: 0...255)
        }
        
        var encoder = SSHEncoder()
        
        // Add nonce
        encoder.encodeData(Data(nonce))
        
        // Add public key data (without the type prefix)
        let publicKeyData = publicKey.publicKeyData()
        var decoder = SSHDecoder(data: publicKeyData)
        _ = try decoder.decodeString() // Skip the key type
        let remainingData = try decoder.decodeBytes(count: decoder.remaining)
        let keyData = Data(remainingData)
        encoder.data.append(keyData)
        
        // Add certificate fields
        encoder.encodeUInt64(certificate.serial)
        encoder.encodeUInt32(certificate.type.rawValue)
        encoder.encodeString(certificate.keyId)
        
        // Encode principals
        var principalsEncoder = SSHEncoder()
        for principal in certificate.principals {
            principalsEncoder.encodeString(principal)
        }
        encoder.encodeData(principalsEncoder.encode())
        
        // Add validity period
        encoder.encodeUInt64(certificate.validAfter)
        encoder.encodeUInt64(certificate.validBefore)
        
        // Add critical options
        encoder.encodeData(certificate.encodeCriticalOptions())
        
        // Add extensions
        encoder.encodeData(certificate.encodeExtensions())
        
        // Reserved field
        encoder.encodeData(Data())
        
        // Add CA public key
        encoder.encodeData(caKey.publicKeyData())
        
        // Now we need to sign everything we've encoded so far
        let dataToSign = encoder.encode()
        
        // Sign the certificate blob directly (no type string prefix)
        let signature = try signCertificateData(
            data: dataToSign,
            caKey: caKey,
            algorithm: signatureAlgorithm
        )
        
        // Create final certificate blob
        var finalEncoder = SSHEncoder()
        finalEncoder.data = dataToSign
        
        // Add signature blob
        var sigEncoder = SSHEncoder()
        sigEncoder.encodeString(signatureAlgorithm)
        sigEncoder.encodeData(signature)
        finalEncoder.encodeData(sigEncoder.encode())
        
        return finalEncoder.encode()
    }
    
    /// Sign certificate data
    private static func signCertificateData(
        data: Data,
        caKey: any SSHKey,
        algorithm: String
    ) throws -> Data {
        switch caKey {
        case let ed25519Key as Ed25519Key:
            // For Ed25519, just return the raw signature
            let signature = try ed25519Key.privateKey.signature(for: data)
            return Data(signature)
            
        case let rsaKey as RSAKey:
            // Sign based on the specified algorithm
            switch algorithm {
            case "ssh-rsa":
                return try Insecure.RSA.sign(data, with: rsaKey.privateKey, hashAlgorithm: .sha1)
            case "rsa-sha2-256":
                return try Insecure.RSA.sign(data, with: rsaKey.privateKey, hashAlgorithm: .sha256)
            case "rsa-sha2-512":
                return try Insecure.RSA.sign(data, with: rsaKey.privateKey, hashAlgorithm: .sha512)
            default:
                throw SSHKeyError.unsupportedSignatureAlgorithm
            }
            
        case let ecdsaKey as ECDSAKey:
            // For ECDSA, get raw signature
            return try ecdsaKey.rawSignature(for: data)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Generate a random serial number
    private static func generateSerial() -> UInt64 {
        return UInt64.random(in: 1...UInt64.max)
    }
}

// Add new error cases
extension SSHKeyError {
    static let tooManyPrincipals = SSHKeyError.invalidKeyData
}