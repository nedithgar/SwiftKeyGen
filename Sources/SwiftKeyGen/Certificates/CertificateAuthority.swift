import Foundation
import Crypto
import _CryptoExtras

/// Certificate Authority utilities for SSH certificates.
///
/// Creates and signs OpenSSH v01 certificates for supported key types
/// (RSA, ECDSA P‑256/P‑384/P‑521, and Ed25519). The primary entry point is
/// ``CertificateAuthority/signCertificate(publicKey:caKey:keyId:principals:serial:validFrom:validTo:certificateType:criticalOptions:extensions:signatureAlgorithm:)``,
/// which returns a ``CertifiedKey`` containing both the original key and its
/// attached certificate blob.
///
/// Behavior aligns with `ssh-keygen` where practical:
/// - Default validity is “forever” unless `validFrom`/`validTo` is provided.
/// - `.user` certificates receive standard permissions when no `extensions`
///   are supplied (X11/agent/port forwarding, PTY, user rc).
/// - Signature algorithm defaults to a sensible choice for the CA key type.
///
/// - SeeAlso: ``CertificateVerifier``, ``CertificateManager``
///
/// ### Example: Sign a user certificate
/// ```swift
/// let caKey = try SwiftKeyGen.generateKey(type: .ed25519)
/// let userKey = try SwiftKeyGen.generateKey(type: .ed25519)
///
/// let cert = try CertificateAuthority.signCertificate(
///     publicKey: userKey,
///     caKey: caKey,
///     keyId: "john.doe",
///     principals: ["john", "jdoe"],
///     validFrom: Date(),
///     validTo: Date().addingTimeInterval(30 * 24 * 60 * 60)
/// )
///
/// try CertificateManager.saveCertificate(cert, to: "~/.ssh/id_ed25519-cert.pub")
/// ```
public struct CertificateAuthority {
    
    /// Signs an SSH certificate for the given key using the provided CA key.
    ///
    /// This creates an OpenSSH v01 certificate that is attached to `publicKey` and
    /// returns a `CertifiedKey` containing both the original key and its certificate.
    /// The certificate is signed by `caKey` and includes the supplied metadata
    /// (key ID, principals, validity window, critical options, and extensions).
    ///
    /// Default behavior closely follows `ssh-keygen`:
    /// - If neither `validFrom` nor `validTo` is provided, the certificate is valid
    ///   “forever” (from 0 to `UInt64.max`).
    /// - If only `validFrom` is provided, `validBefore` remains `UInt64.max`.
    /// - If only `validTo` is provided, `validAfter` remains 0.
    /// - For `.user` certificates, if `extensions` is empty, standard user
    ///   permissions are added: `permit-X11-forwarding`, `permit-agent-forwarding`,
    ///   `permit-port-forwarding`, `permit-pty`, and `permit-user-rc`.
    /// - If `signatureAlgorithm` is not specified, a sensible default is chosen
    ///   for the CA key type (RSA → `rsa-sha2-512`, Ed25519 → `ssh-ed25519`,
    ///   ECDSA P-256/384/521 → `ecdsa-sha2-nistp256/384/521`).
    ///
    /// - Parameters:
    ///   - publicKey: The subject key to certify. Supports RSA, ECDSA
    ///     (P‑256/P‑384/P‑521), and Ed25519.
    ///   - caKey: The certificate authority private key used to sign the
    ///     certificate. Its type must be compatible with `signatureAlgorithm` (if
    ///     provided).
    ///   - keyId: A free‑form identifier recorded in the certificate’s key ID field
    ///     (useful for auditing and tracking).
    ///   - principals: Allowed principals for the certificate. For `.user` this is
    ///     a list of usernames; for `.host` it is hostnames/wildcards. Limited to
    ///     `SSHCertificate.maxPrincipals`. Defaults to an empty list.
    ///   - serial: Optional serial number. If `nil`, a random non‑zero serial is
    ///     generated.
    ///   - validFrom: Optional start of the validity window. See default behavior
    ///     notes above.
    ///   - validTo: Optional end of the validity window. See default behavior
    ///     notes above.
    ///   - certificateType: The certificate type, `.user` (default) or `.host`.
    ///     Drives default extension selection.
    ///   - criticalOptions: Critical options to embed in the certificate (e.g.,
    ///     `.forceCommand`, `.sourceAddress`).
    ///   - extensions: Extensions to include. If empty for `.user`, default user
    ///     permissions are applied as described above.
    ///   - signatureAlgorithm: Explicit signature algorithm to use. If omitted, a
    ///     default matching the CA key type is selected.
    /// - Returns: A `CertifiedKey` containing the original key and its attached
    ///   SSH certificate.
    /// - Throws: `SSHKeyError.tooManyPrincipals` if `principals` exceeds
    ///   `SSHCertificate.maxPrincipals`; `SSHKeyError.incompatibleSignatureAlgorithm`
    ///   if `signatureAlgorithm` does not match `caKey`'s type; other `SSHKeyError`
    ///   values for signing/encoding failures (e.g., unsupported CA key type).
    ///
    /// - SeeAlso: `CertificateVerifier.verifyCertificate(_:caKey:options:)`,
    ///   `CertificateManager.saveCertificate(_:to:comment:)`
    ///
    /// ### Example
    /// ```swift
    /// let caKey = try SwiftKeyGen.generateKey(type: .ed25519)
    /// let userKey = try SwiftKeyGen.generateKey(type: .ed25519)
    ///
    /// let cert = try CertificateAuthority.signCertificate(
    ///     publicKey: userKey,
    ///     caKey: caKey,
    ///     keyId: "john.doe",
    ///     principals: ["john", "jdoe"],
    ///     validFrom: Date(),
    ///     validTo: Date().addingTimeInterval(30 * 24 * 60 * 60),
    ///     certificateType: .user
    /// )
    ///
    /// try CertificateManager.saveCertificate(cert, to: "~/.ssh/id_ed25519-cert.pub")
    /// ```
    public static func signCertificate(
        publicKey: any SSHKey,
        caKey: any SSHKey,
        keyId: String,
        principals: [String] = [],
        serial: UInt64? = nil,
        validFrom: Date? = nil,
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
        // If neither validFrom nor validTo is specified, use the default "forever" behavior
        if let validFrom = validFrom, let validTo = validTo {
            certifiedKey.certificate.setValidity(from: validFrom, to: validTo)
        } else if let validFrom = validFrom {
            // If only validFrom is specified, set it but keep validBefore as UInt64.max
            certifiedKey.certificate.validAfter = UInt64(validFrom.timeIntervalSince1970)
            // validBefore remains UInt64.max from init
        } else if let validTo = validTo {
            // If only validTo is specified, keep validAfter as 0 and set validBefore
            certifiedKey.certificate.validBefore = UInt64(validTo.timeIntervalSince1970)
        }
        // Otherwise, both remain at their defaults (0 and UInt64.max = "forever")
        
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
        
        // Add certificate type string first
        encoder.encodeString(certifiedKey.certifiedKeyType)
        
        // Add nonce
        encoder.encodeData(Data(nonce))
        
        // Add public key data (without the type prefix)
        // We need to extract the raw components from the public key data
        let publicKeyData = publicKey.publicKeyData()
        var decoder = SSHDecoder(data: publicKeyData)
        _ = try decoder.decodeString() // Skip the key type
        
        // Now encode the remaining public key components based on key type
        switch publicKey.keyType {
        case .ed25519:
            // Ed25519: just the public key bytes (32 bytes)
            let publicKeyBytes = try decoder.decodeData()
            encoder.encodeData(publicKeyBytes)
            
        case .rsa:
            // RSA: e then n (exponent then modulus) 
            // Note: publicKeyData() encodes as e, n but we already read those
            let exponent = try decoder.decodeData()
            let modulus = try decoder.decodeData()
            encoder.encodeData(exponent)
            encoder.encodeData(modulus)
            
        case .ecdsa256, .ecdsa384, .ecdsa521:
            // ECDSA: curve name then public key point
            let curveName = try decoder.decodeString()
            let publicKeyPoint = try decoder.decodeData()
            encoder.encodeString(curveName)
            encoder.encodeData(publicKeyPoint)
        }
        
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
        
        // Create final certificate blob (without the type string for storage)
        var finalEncoder = SSHEncoder()
        
        // Extract the blob data without the type string
        var blobDecoder = SSHDecoder(data: dataToSign)
        _ = try blobDecoder.decodeString() // Skip the type string
        let blobWithoutType = Data(try blobDecoder.decodeBytes(count: blobDecoder.remaining))
        
        finalEncoder.data = blobWithoutType
        
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
            // For RSA, we need to get just the raw signature blob
            // RSAKey.signWithAlgorithm returns SSH-formatted signature, but we need just the raw part
            let sshSignature = try rsaKey.signWithAlgorithm(data: data, algorithm: algorithm)
            
            // Extract the raw signature from the SSH format
            var decoder = SSHDecoder(data: sshSignature)
            _ = try decoder.decodeString() // Skip signature type
            return try decoder.decodeData() // Return just the raw signature
            
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
