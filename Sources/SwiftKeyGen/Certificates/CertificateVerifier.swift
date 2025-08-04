import Foundation
import Crypto
import _CryptoExtras

/// Result of certificate verification
public enum CertificateVerificationResult: Equatable {
    case valid
    case invalidSignature
    case expired
    case notYetValid
    case invalidPrincipal
    case invalidCertificateType
    case caKeyMismatch
    case error(String)
}

/// Certificate verification options
public struct CertificateVerificationOptions {
    public var requirePrincipal: Bool = false
    public var allowedPrincipals: [String] = []
    public var verifyTime: Date = Date()
    public var expectedCertificateType: SSHCertificateType?
    public var wildcardPrincipalMatching: Bool = true
    
    public init() {}
}

/// Certificate verifier
public struct CertificateVerifier {
    
    /// Verify a certificate
    public static func verifyCertificate(
        _ certifiedKey: CertifiedKey,
        caKey: (any SSHKey)? = nil,
        options: CertificateVerificationOptions = CertificateVerificationOptions()
    ) -> CertificateVerificationResult {
        let cert = certifiedKey.certificate
        
        // Check certificate type if specified
        if let expectedType = options.expectedCertificateType {
            if cert.type != expectedType {
                return .invalidCertificateType
            }
        }
        
        // Check validity period
        let verifyTimestamp = UInt64(options.verifyTime.timeIntervalSince1970)
        if verifyTimestamp < cert.validAfter {
            return .notYetValid
        }
        if verifyTimestamp > cert.validBefore {
            return .expired
        }
        
        // Check principals if required
        if options.requirePrincipal {
            if cert.principals.isEmpty && !options.allowedPrincipals.isEmpty {
                return .invalidPrincipal
            }
            
            if !options.allowedPrincipals.isEmpty {
                let hasValidPrincipal = cert.principals.contains { principal in
                    options.allowedPrincipals.contains { allowed in
                        if options.wildcardPrincipalMatching {
                            // Check if the allowed hostname matches the principal pattern
                            return matchesPrincipal(allowed, pattern: principal)
                        } else {
                            return principal == allowed
                        }
                    }
                }
                
                if !hasValidPrincipal {
                    return .invalidPrincipal
                }
            }
        }
        
        // Verify signature if CA key is provided
        if let caKey = caKey {
            // Check if the signature key in the certificate matches the provided CA key
            if let certSignatureKey = cert.signatureKey {
                let caKeyData = caKey.publicKeyData()
                let certSignatureKeyData = certSignatureKey.publicKeyData()
                if caKeyData != certSignatureKeyData {
                    return .caKeyMismatch
                }
            }
            
            // Verify the signature
            if let certBlob = cert.certBlob {
                do {
                    let isValid = try verifySignature(
                        certBlob: certBlob,
                        caKey: caKey,
                        signatureType: cert.signatureType ?? "",
                        certifiedKey: certifiedKey
                    )
                    
                    if !isValid {
                        return .invalidSignature
                    }
                } catch {
                    return .error("Signature verification failed: \(error)")
                }
            } else {
                return .error("Certificate blob is missing")
            }
        }
        
        return .valid
    }
    
    /// Verify certificate signature
    private static func verifySignature(
        certBlob: Data,
        caKey: any SSHKey,
        signatureType: String,
        certifiedKey: CertifiedKey
    ) throws -> Bool {
        // The signed data includes the certificate type string prefix
        // We need to reconstruct it
        var signedDataEncoder = SSHEncoder()
        signedDataEncoder.encodeString(certifiedKey.certifiedKeyType)
        
        // The certificate blob contains everything including the signature
        // We need to extract the data that was signed and the signature
        
        var decoder = SSHDecoder(data: certBlob)
        
        // Skip through the certificate fields to find where the signature starts
        _ = try decoder.decodeData() // nonce
        
        // The certificate has the public key data WITHOUT the key type string
        // Skip public key data based on the certified key type
        switch certifiedKey.originalKey.keyType {
        case .ed25519:
            _ = try decoder.decodeData() // public key
        case .rsa:
            _ = try decoder.decodeData() // e
            _ = try decoder.decodeData() // n
        case .ecdsa256, .ecdsa384, .ecdsa521:
            _ = try decoder.decodeString() // curve name
            _ = try decoder.decodeData() // public key point
        }
        
        // Skip serial (8 bytes)
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeUInt32() // type
        _ = try decoder.decodeString() // key_id
        _ = try decoder.decodeData() // principals
        // Skip validity period (16 bytes)
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeUInt32()
        _ = try decoder.decodeData() // critical options
        _ = try decoder.decodeData() // extensions
        _ = try decoder.decodeData() // reserved
        _ = try decoder.decodeData() // CA key
        
        // Everything before the signature is the blob data to append
        let blobDataLength = certBlob.count - decoder.remaining
        signedDataEncoder.data.append(certBlob[..<blobDataLength])
        
        // This is the complete signed data (type string + blob without signature)
        let signedData = signedDataEncoder.encode()
        
        // Read and parse the signature
        let signatureBlob = try decoder.decodeData()
        var sigDecoder = SSHDecoder(data: signatureBlob)
        let sigType = try sigDecoder.decodeString()
        let signature = try sigDecoder.decodeData()
        
        // Verify the signature type matches
        guard sigType == signatureType else {
            throw SSHKeyError.signatureMismatch
        }
        
        // Verify signature based on key type
        switch caKey {
        case let ed25519Key as Ed25519Key:
            // Ed25519 expects raw signature
            let publicKey = ed25519Key.privateKey.publicKey
            return publicKey.isValidSignature(signature, for: signedData)
            
        case let ed25519PublicKey as Ed25519PublicKey:
            // Public-only Ed25519 key expects raw signature
            return try ed25519PublicKey.verify(signature: signature, for: signedData)
            
        case let rsaKey as RSAKey:
            // RSA expects SSH formatted signature (which signatureBlob already is)
            return try rsaKey.verify(signature: signatureBlob, for: signedData)
            
        case let rsaPublicKey as RSAPublicKey:
            // Public-only RSA key needs SSH formatted signature (which signatureBlob already is)
            return try rsaPublicKey.verify(signature: signatureBlob, for: signedData)
            
        case let ecdsaKey as ECDSAKey:
            // ECDSA expects raw signature
            // For consistency with ECDSAPublicKey, use the same verification approach
            var sigEncoder = SSHEncoder()
            sigEncoder.encodeString(sigType)
            sigEncoder.encodeData(signature)
            let sshSignature = sigEncoder.encode()
            return try ecdsaKey.verify(signature: sshSignature, for: signedData)
            
        case let ecdsaPublicKey as ECDSAPublicKey:
            // Public-only ECDSA key needs SSH formatted signature
            // The signature from the certificate is already SSH-encoded r,s components
            var sigEncoder = SSHEncoder()
            sigEncoder.encodeString(sigType)
            sigEncoder.encodeData(signature)
            let sshSignature = sigEncoder.encode()
            return try ecdsaPublicKey.verify(signature: sshSignature, for: signedData)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Match principal with wildcard support
    private static func matchesPrincipal(_ principal: String, pattern: String) -> Bool {
        // Direct match
        if principal == pattern {
            return true
        }
        
        // Handle wildcard patterns
        if pattern.contains("*") {
            // Special case: *.domain.com should match one.domain.com but not one.two.domain.com
            if pattern.hasPrefix("*.") {
                let domain = String(pattern.dropFirst(2))
                
                // Check if principal ends with the domain
                guard principal.hasSuffix(domain) else {
                    return false
                }
                
                // Check if it's exactly the domain (no match)
                if principal == domain {
                    return false
                }
                
                // Get the prefix before the domain
                let prefixEndIndex = principal.index(principal.endIndex, offsetBy: -(domain.count + 1))
                if prefixEndIndex < principal.startIndex {
                    return false
                }
                
                let prefix = String(principal[..<prefixEndIndex])
                
                // The prefix should not contain dots (only one level of subdomain)
                return !prefix.contains(".")
            }
            
            // Generic wildcard matching (for other patterns)
            let parts = pattern.split(separator: "*", omittingEmptySubsequences: false)
            var currentIndex = principal.startIndex
            
            for (i, part) in parts.enumerated() {
                if part.isEmpty {
                    continue
                }
                
                if i == 0 && !pattern.hasPrefix("*") {
                    // Pattern doesn't start with *, so principal must start with this part
                    if !principal.hasPrefix(String(part)) {
                        return false
                    }
                    currentIndex = principal.index(currentIndex, offsetBy: part.count)
                } else if i == parts.count - 1 && !pattern.hasSuffix("*") {
                    // Pattern doesn't end with *, so principal must end with this part
                    if !principal.hasSuffix(String(part)) {
                        return false
                    }
                } else {
                    // Find this part in the remaining string
                    if let range = principal[currentIndex...].range(of: String(part)) {
                        currentIndex = range.upperBound
                    } else {
                        return false
                    }
                }
            }
            
            return true
        }
        
        return false
    }
}


// Add new error cases
extension SSHKeyError {
    static let signatureMismatch = SSHKeyError.invalidFormat
}