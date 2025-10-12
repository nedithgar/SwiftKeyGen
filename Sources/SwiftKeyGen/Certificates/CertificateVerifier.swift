import Foundation
import Crypto
import _CryptoExtras

/// The outcome of verifying an SSH certificate.
///
/// This result communicates whether a certificate is currently valid under the
/// provided verification options and, if not, the specific reason verification
/// failed. Use this to make precise policy decisions (e.g., prompt the user,
/// deny a connection, or fall back to a different trust path).
public enum CertificateVerificationResult: Equatable {
    /// The certificate is valid under the provided options.
    case valid
    /// The signature on the certificate could not be verified.
    case invalidSignature
    /// The certificate is expired at the verification time.
    case expired
    /// The certificate is not yet valid at the verification time.
    case notYetValid
    /// The principals do not satisfy the verification options.
    case invalidPrincipal
    /// The certificate type does not match the expected type.
    case invalidCertificateType
    /// The provided CA key does not match the one embedded in the certificate.
    case caKeyMismatch
    /// A non‑structured error occurred with a diagnostic message.
    ///
    /// This case is returned for unexpected parsing/verification problems where
    /// a richer, structured failure does not apply. The associated message is
    /// suitable for logs and diagnostics but should not be relied on for
    /// programmatic branching.
    case error(String)
}

/// Options controlling certificate verification behavior.
///
/// These options mirror `ssh-keygen`/OpenSSH semantics for validating user and
/// host certificates. By default, verification checks temporal validity and
/// optionally enforces principal matching and CA signature verification.
public struct CertificateVerificationOptions {
    /// Require that at least one allowed principal matches.
    ///
    /// - Note: If `true` and `allowedPrincipals` is empty while the
    ///   certificate lists zero principals, verification returns
    ///   ``CertificateVerificationResult/invalidPrincipal``.
    public var requirePrincipal: Bool = false
    /// Allowed principals (usernames or hostnames) to match.
    ///
    /// When ``wildcardPrincipalMatching`` is enabled, patterns like
    /// `*.example.com` match exactly one subdomain level (e.g.,
    /// `host.example.com`, but not `a.b.example.com`).
    public var allowedPrincipals: [String] = []
    /// The time at which to evaluate validity.
    ///
    /// Defaults to `Date()` (now). `validAfter` and `validBefore` checks are
    /// performed using the certificate’s UNIX epoch timestamps.
    public var verifyTime: Date = Date()
    /// If set, require the certificate to be of this type.
    ///
    /// When provided, the certificate’s ``SSHCertificate/type`` must equal this
    /// value or verification returns
    /// ``CertificateVerificationResult/invalidCertificateType``.
    public var expectedCertificateType: SSHCertificateType?
    /// Whether wildcard principals (e.g., `*.example.com`) are matched.
    ///
    /// - Important: `*.example.com` matches `a.example.com` but not
    ///   `a.b.example.com`. Generic `*` segments in other positions are also
    ///   supported and treated as “match any substring”.
    public var wildcardPrincipalMatching: Bool = true
    
    /// Creates a new set of verification options with sensible defaults.
    ///
    /// - Defaults:
    ///   - ``requirePrincipal``: `false`
    ///   - ``allowedPrincipals``: `[]`
    ///   - ``verifyTime``: `Date()` (current time)
    ///   - ``expectedCertificateType``: `nil` (don’t enforce)
    ///   - ``wildcardPrincipalMatching``: `true`
    public init() {}
}

/// Verifies OpenSSH user and host certificates.
///
/// The verifier enforces validity windows, optional principal matching (with
/// limited wildcard support), and—when a CA key is provided—signature
/// verification and CA key matching against the certificate’s embedded
/// signature key.
public struct CertificateVerifier {
    
    /// Verifies a certificate against the supplied options and CA key.
    ///
    /// If ``caKey`` is `nil`, only structural checks are performed (e.g., time
    /// validity, certificate type, and optional principal matching). When a CA
    /// key is supplied (public or private), the verifier also ensures the
    /// certificate’s embedded signature key matches the provided CA key and the
    /// signature over the certificate blob is valid.
    ///
    /// - Parameters:
    ///   - certifiedKey: The certified key and associated certificate to verify.
    ///   - caKey: The certificate authority key to verify the signature with.
    ///     Pass `nil` to skip signature verification.
    ///   - options: Verification options controlling principal, time, and type
    ///     checks. Defaults to ``CertificateVerificationOptions``.
    /// - Returns: A ``CertificateVerificationResult`` explaining the outcome.
    /// - Discussion: The function never throws. Unexpected conditions are
    ///   surfaced as ``CertificateVerificationResult/error(_:)`` with a
    ///   diagnostic string suitable for logging.
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
        default:
            throw SSHKeyError.unsupportedKeyType
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
