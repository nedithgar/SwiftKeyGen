import Foundation
import Crypto
import _CryptoExtras

/// Parses OpenSSH v01 SSH certificates into strongly typed models.
///
/// `CertificateParser` decodes OpenSSH certificate public key strings
/// (the `*-cert-v01@openssh.com` form produced by `ssh-keygen -L/-s`) and
/// returns a `CertifiedKey` that bundles the parsed public key together with
/// its `SSHCertificate` metadata.
///
/// Supported certificate algorithms:
/// - `ssh-ed25519-cert-v01@openssh.com`
/// - `ssh-rsa-cert-v01@openssh.com`
/// - `ecdsa-sha2-nistp256-cert-v01@openssh.com`
/// - `ecdsa-sha2-nistp384-cert-v01@openssh.com`
/// - `ecdsa-sha2-nistp521-cert-v01@openssh.com`
///
/// The parser performs structural validation and field extraction but does not
/// perform signature verification. Use the certificate verification utilities
/// in the Certificates module to verify trust and validity.
public struct CertificateParser {
    
    /// Parses an OpenSSH certificate from its public key string representation.
    ///
    /// This method expects the full OpenSSH certificate line as typically found
    /// in `authorized_keys`-style files, for example:
    ///
    /// ```text
    /// ssh-ed25519-cert-v01@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAI… optional-comment
    /// ```
    ///
    /// The function validates the key type suffix (`-cert-v01@openssh.com`),
    /// Base64‑decodes the payload, and delegates to ``parseCertificateData(_:keyType:comment:)``.
    ///
    /// - Parameter publicKeyString: The full OpenSSH certificate public key line
    ///   including the certificate key type and Base64 data; an optional trailing
    ///   comment (key ID/label) is allowed and will be preserved when possible.
    /// - Returns: A ``CertifiedKey`` whose ``CertifiedKey/certificate`` contains
    ///   the parsed certificate fields and whose underlying public key matches the
    ///   certificate subject.
    /// - Throws: ``SSHKeyError`` when the string is malformed, not a certificate,
    ///   the payload is not valid Base64, the key type is unsupported, or when any
    ///   field fails to decode.
    public static func parseCertificate(from publicKeyString: String) throws -> CertifiedKey {
        // Split the components
        let components = publicKeyString.trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: .whitespaces)
        
        guard components.count >= 2 else {
            throw SSHKeyError.invalidFormat
        }
        
        let keyType = components[0]
        let base64Data = components[1]
        let comment = components.count > 2 ? components[2...].joined(separator: " ") : nil
        
        // Check if this is a certificate type
        guard keyType.hasSuffix("-cert-v01@openssh.com") else {
            throw SSHKeyError.notACertificate
        }
        
        // Decode base64
        guard let keyData = Data(base64Encoded: base64Data) else {
            throw SSHKeyError.invalidBase64
        }
        
        return try parseCertificateData(keyData, keyType: keyType, comment: comment)
    }
    
    /// Parses an OpenSSH certificate from raw decoded data.
    ///
    /// Use this overload when you have already extracted and Base64‑decoded the
    /// certificate payload from an OpenSSH certificate public key string. The
    /// `data` must contain the full SSH wire format beginning with the key type
    /// string, followed by the certificate blob as emitted by OpenSSH.
    ///
    /// - Parameters:
    ///   - data: The Base64‑decoded bytes from the OpenSSH certificate public key
    ///     field. This begins with the key type string and length‑prefixed fields
    ///     that make up the certificate blob.
    ///   - keyType: The certificate key type string as it appeared in the public
    ///     key line (e.g., `ssh-ed25519-cert-v01@openssh.com`). This is validated
    ///     against the content of `data`.
    ///   - comment: Optional trailing comment captured from the public key line;
    ///     preserved on the returned public key when applicable.
    /// - Returns: A ``CertifiedKey`` populated with the parsed certificate fields
    ///   (serial, key ID, principals, validity, critical options, extensions,
    ///   signature key/type) and the subject public key.
    /// - Throws: ``SSHKeyError`` when the data is structurally invalid, the
    ///   certificate type or underlying key type is unsupported, or fields fail
    ///   to decode.
    public static func parseCertificateData(_ data: Data, keyType: String, comment: String? = nil) throws -> CertifiedKey {
        var decoder = SSHDecoder(data: data)
        
        // Read and verify key type
        let readKeyType = try decoder.decodeString()
        guard readKeyType == keyType else {
            throw SSHKeyError.invalidFormat
        }
        
        // Read certificate blob
        // The OpenSSH public key payload for certificates is:
        //   string keytype || certificate-blob
        // where certificate-blob is NOT wrapped in a single length field.
        // It consists of a sequence of length‑prefixed fields ending with the
        // signature. Therefore, after consuming the key type string, the
        // remainder of the data is the certificate blob.
        let certBlobData = try decoder.decodeBytes(count: decoder.remaining)
        var certDecoder = SSHDecoder(data: Data(certBlobData))
        
        // Parse certificate components
        // Read nonce
        _ = try certDecoder.decodeData() // nonce (32 bytes)
        
        // Determine the underlying key type and parse public key
        let underlyingKey: any SSHKey
        let certificateType: SSHCertificateType
        
        switch keyType {
        case "ssh-ed25519-cert-v01@openssh.com":
            // Read Ed25519 public key (32 bytes)
            let publicKeyData = try certDecoder.decodeData()
            underlyingKey = try Ed25519PublicKey(publicKeyData: publicKeyData, comment: comment)
            
        case "ssh-rsa-cert-v01@openssh.com":
            // Read RSA public key components
            let e = try certDecoder.decodeData()
            let n = try certDecoder.decodeData()
            underlyingKey = try RSAPublicKey(modulus: n, exponent: e, comment: comment)
            
        case "ecdsa-sha2-nistp256-cert-v01@openssh.com",
             "ecdsa-sha2-nistp384-cert-v01@openssh.com",
             "ecdsa-sha2-nistp521-cert-v01@openssh.com":
            // Read ECDSA public key components
            let curveName = try certDecoder.decodeString()
            let ecPublicKeyData = try certDecoder.decodeData()
            
            // Determine key type from certificate type
            let ecKeyType: KeyType
            switch keyType {
            case "ecdsa-sha2-nistp256-cert-v01@openssh.com":
                ecKeyType = .ecdsa256
            case "ecdsa-sha2-nistp384-cert-v01@openssh.com":
                ecKeyType = .ecdsa384
            case "ecdsa-sha2-nistp521-cert-v01@openssh.com":
                ecKeyType = .ecdsa521
            default:
                throw SSHKeyError.unsupportedKeyType
            }
            
            underlyingKey = try ECDSAPublicKey(
                keyType: ecKeyType,
                curveName: curveName,
                publicKeyPoint: ecPublicKeyData,
                comment: comment
            )
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        // Read certificate fields
        // Decode serial as two UInt32s to make UInt64
        let serialHigh = try certDecoder.decodeUInt32()
        let serialLow = try certDecoder.decodeUInt32()
        let serial = (UInt64(serialHigh) << 32) | UInt64(serialLow)
        let certTypeRaw = try certDecoder.decodeUInt32()
        guard let certType = SSHCertificateType(rawValue: certTypeRaw) else {
            throw SSHKeyError.invalidCertificateType
        }
        certificateType = certType
        
        let keyId = try certDecoder.decodeString()
        
        // Read principals
        let principalsData = try certDecoder.decodeData()
        let principals = try parsePrincipals(principalsData)
        
        // Read validity period
        // Decode validity period as pairs of UInt32s
        let validAfterHigh = try certDecoder.decodeUInt32()
        let validAfterLow = try certDecoder.decodeUInt32()
        let validAfter = (UInt64(validAfterHigh) << 32) | UInt64(validAfterLow)
        
        let validBeforeHigh = try certDecoder.decodeUInt32()
        let validBeforeLow = try certDecoder.decodeUInt32()
        let validBefore = (UInt64(validBeforeHigh) << 32) | UInt64(validBeforeLow)
        
        // Read critical options
        let criticalOptionsData = try certDecoder.decodeData()
        let criticalOptions = try parseCriticalOptions(criticalOptionsData)
        
        // Read extensions
        let extensionsData = try certDecoder.decodeData()
        let extensions = try parseExtensions(extensionsData)
        
        // Read reserved field
        _ = try certDecoder.decodeData()
        
        // Read CA public key
        let caKeyData = try certDecoder.decodeData()
        let caKey = try parseCAKey(caKeyData)
        
        // Read signature
        let signatureData = try certDecoder.decodeData()
        let (signatureType, _) = try parseSignature(signatureData)
        
        // Create certified key
        let certifiedKey = underlyingKey.toCertified(type: certificateType)
        certifiedKey.certificate.certBlob = Data(certBlobData)
        certifiedKey.certificate.serial = serial
        certifiedKey.certificate.keyId = keyId
        certifiedKey.certificate.principals = principals
        certifiedKey.certificate.validAfter = validAfter
        certifiedKey.certificate.validBefore = validBefore
        certifiedKey.certificate.criticalOptions = criticalOptions
        certifiedKey.certificate.extensions = extensions
        certifiedKey.certificate.signatureKey = caKey
        certifiedKey.certificate.signatureType = signatureType
        
        return certifiedKey
    }
    
    /// Parse principals list
    private static func parsePrincipals(_ data: Data) throws -> [String] {
        var principals: [String] = []
        var decoder = SSHDecoder(data: data)
        
        while decoder.remaining > 0 {
            let principal = try decoder.decodeString()
            principals.append(principal)
        }
        
        return principals
    }
    
    /// Parse critical options
    private static func parseCriticalOptions(_ data: Data) throws -> [(String, String)] {
        var options: [(String, String)] = []
        var decoder = SSHDecoder(data: data)
        
        while decoder.remaining > 0 {
            let name = try decoder.decodeString()
            let valueData = try decoder.decodeData()
            
            // Decode the value if it contains data, otherwise use empty string (flag option)
            let value: String
            if valueData.count > 0 {
                var valueDecoder = SSHDecoder(data: valueData)
                value = try valueDecoder.decodeString()
            } else {
                // Flag options like "verify-required" have empty value data
                value = ""
            }
            options.append((name, value))
        }
        
        return options
    }
    
    /// Parse extensions
    private static func parseExtensions(_ data: Data) throws -> [String] {
        var extensions: [String] = []
        var decoder = SSHDecoder(data: data)
        
        while decoder.remaining > 0 {
            let name = try decoder.decodeString()
            _ = try decoder.decodeData() // Value (usually empty for boolean extensions)
            extensions.append(name)
        }
        
        return extensions
    }
    
    /// Parse CA public key
    private static func parseCAKey(_ data: Data) throws -> any SSHKey {
        var decoder = SSHDecoder(data: data)
        let keyType = try decoder.decodeString()
        
        switch keyType {
        case "ssh-ed25519":
            let publicKeyData = try decoder.decodeData()
            return try Ed25519PublicKey(publicKeyData: publicKeyData)
            
        case "ssh-rsa":
            let e = try decoder.decodeData()
            let n = try decoder.decodeData()
            return try RSAPublicKey(modulus: n, exponent: e)
            
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            let curveName = try decoder.decodeString()
            let ecdsaPublicKeyData = try decoder.decodeData()
            
            // Determine key type from key type string
            let ecKeyType: KeyType
            switch keyType {
            case "ecdsa-sha2-nistp256":
                ecKeyType = .ecdsa256
            case "ecdsa-sha2-nistp384":
                ecKeyType = .ecdsa384
            case "ecdsa-sha2-nistp521":
                ecKeyType = .ecdsa521
            default:
                throw SSHKeyError.unsupportedKeyType
            }
            
            return try ECDSAPublicKey(
                keyType: ecKeyType,
                curveName: curveName,
                publicKeyPoint: ecdsaPublicKeyData
            )
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    /// Parse signature
    private static func parseSignature(_ data: Data) throws -> (String, Data) {
        var decoder = SSHDecoder(data: data)
        let signatureType = try decoder.decodeString()
        let signatureBlob = try decoder.decodeData()
        return (signatureType, signatureBlob)
    }
}

// Add new error cases
extension SSHKeyError {
    static let notACertificate = SSHKeyError.invalidFormat
    static let invalidBase64 = SSHKeyError.invalidFormat
    static let invalidCertificateType = SSHKeyError.invalidFormat
}
