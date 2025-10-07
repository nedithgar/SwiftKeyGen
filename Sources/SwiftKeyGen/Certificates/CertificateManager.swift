import Foundation

/// High‑level utilities for working with SSH certificates.
///
/// ``CertificateManager`` provides convenience operations to save, read, generate,
/// verify, and display OpenSSH v01 certificates. It is a stateless façade over
/// lower‑level components such as ``CertificateAuthority``, ``CertificateParser``,
/// and ``CertificateVerifier`` and mirrors common `ssh-keygen` workflows where
/// practical.
///
/// - SeeAlso: ``CertificateAuthority``, ``CertificateVerifier``, ``KeyFileManager``
public struct CertificateManager {
    
    /// Write a certificate public key line to a file.
    ///
    /// Persists the certificate in OpenSSH "authorized_keys" style as a single
    /// line: `<cert-type> <base64-cert> [comment]` followed by a newline. File
    /// permissions are set to `0644`.
    ///
    /// - Parameters:
    ///   - certifiedKey: The key with an attached certificate blob to write.
    ///   - path: Destination file path. `~` is expanded to the user’s home.
    ///   - comment: Optional trailing comment. If `nil`, the original key’s
    ///     comment is used when available.
    /// - Throws: ``SSHKeyError`` if serialization fails, or file I/O errors
    ///   raised by Foundation when writing or setting attributes.
    public static func saveCertificate(
        _ certifiedKey: CertifiedKey,
        to path: String,
        comment: String? = nil
    ) throws {
        let expandedPath = NSString(string: path).expandingTildeInPath
        
        // Get the public key string with certificate
        _ = try certifiedKey.publicKeyData()
        var encoder = SSHEncoder()
        encoder.encodeString(certifiedKey.certifiedKeyType)
        encoder.encodeData(certifiedKey.certificate.certBlob!)
        
        let base64 = encoder.encode().base64EncodedString()
        var output = "\(certifiedKey.certifiedKeyType) \(base64)"
        
        if let comment = comment ?? certifiedKey.originalKey.comment {
            output += " \(comment)"
        }
        
        output += "\n"
        
        try output.write(toFile: expandedPath, atomically: true, encoding: .utf8)
        
        // Set appropriate permissions (readable by all)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: expandedPath
        )
    }
    
    /// Read and parse a certificate from a file.
    ///
    /// Scans the file for the first non‑empty, non‑comment line and attempts to
    /// parse an OpenSSH certificate from it.
    ///
    /// - Parameter path: Path to a file containing a certificate line.
    /// - Returns: A ``CertifiedKey`` containing the original public key and the
    ///   attached certificate.
    /// - Throws: ``SSHKeyError/invalidFormat`` if no valid certificate line is
    ///   found, or file I/O errors raised by Foundation when reading the file.
    public static func readCertificate(from path: String) throws -> CertifiedKey {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let content = try String(contentsOfFile: expandedPath, encoding: .utf8)
        
        // Find the first non-empty, non-comment line
        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty && !trimmed.hasPrefix("#") {
                return try CertificateParser.parseCertificate(from: trimmed)
            }
        }
        
        throw SSHKeyError.invalidFormat
    }
    
    /// Generate and write host certificates for multiple hosts.
    ///
    /// For each host in `hosts`, this method:
    /// - Generates a new host key of `keyType`.
    /// - Signs a `.host` certificate with the CA key from `caKeyPath`.
    /// - Writes the certificate to `"<outputDirectory>/<host>-cert.pub"` with
    ///   permissions `0644`.
    /// - Writes the private key to `"<outputDirectory>/<host>"` with permissions
    ///   `0600` (OpenSSH format).
    ///
    /// - Parameters:
    ///   - hosts: Hostnames to certify. Wildcard principal `*.host` is added for
    ///     each entry.
    ///   - caKeyPath: Filesystem path to the CA private key.
    ///   - caKeyPassphrase: Optional passphrase for the CA key.
    ///   - keyType: Key type to generate for each host (default `.ed25519`).
    ///   - outputDirectory: Directory to write keys and certificates (default
    ///     current directory).
    ///   - validityDays: Validity window in days from now (default `365`).
    ///   - serialStart: Optional starting serial number; if `nil`, a timestamp‑
    ///     based serial is used. The serial increments by 1 for each host.
    /// - Returns: A list of tuples containing the host and the certificate path
    ///   written for that host.
    /// - Throws: ``SSHKeyError`` for key loading, signing, or serialization
    ///   failures; file I/O errors for write or chmod failures.
    public static func generateCertificatesForHosts(
        hosts: [String],
        caKeyPath: String,
        caKeyPassphrase: String? = nil,
        keyType: KeyType = .ed25519,
        outputDirectory: String = ".",
        validityDays: Int = 365,
        serialStart: UInt64? = nil
    ) throws -> [(host: String, certificatePath: String)] {
        // Load CA key
        let caKey = try KeyManager.readPrivateKey(from: caKeyPath, passphrase: caKeyPassphrase)
        
        var results: [(host: String, certificatePath: String)] = []
        var currentSerial = serialStart ?? UInt64(Date().timeIntervalSince1970)
        
        for host in hosts {
            // Generate host key
            let hostKey = try SwiftKeyGen.generateKey(type: keyType)
            
            // Create certificate
            let validFrom = Date()
            let validTo = validFrom.addingTimeInterval(Double(validityDays) * 24 * 60 * 60)
            
            let certifiedKey = try CertificateAuthority.signCertificate(
                publicKey: hostKey,
                caKey: caKey,
                keyId: host,
                principals: [host, "*.\(host)"], // Include wildcard for subdomains
                serial: currentSerial,
                validFrom: validFrom,
                validTo: validTo,
                certificateType: .host
            )
            
            // Save certificate
            let certPath = "\(outputDirectory)/\(host)-cert.pub"
            try saveCertificate(certifiedKey, to: certPath, comment: "host certificate for \(host)")
            
            // Also save the private key
            let keyPath = "\(outputDirectory)/\(host)"
            let serialized = try OpenSSHPrivateKey.serialize(key: hostKey)
            try serialized.write(to: URL(fileURLWithPath: NSString(string: keyPath).expandingTildeInPath))
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: NSString(string: keyPath).expandingTildeInPath)
            
            results.append((host: host, certificatePath: certPath))
            currentSerial += 1
        }
        
        return results
    }
    
    /// Render human‑readable certificate information.
    ///
    /// Returns a formatted description of the certificate along with the
    /// subject public key’s SHA‑256 fingerprint (Base64).
    ///
    /// - Parameter certifiedKey: The certified key to describe.
    /// - Returns: A string suitable for display (multi‑line).
    public static func displayCertificateInfo(_ certifiedKey: CertifiedKey) -> String {
        var info = ""
        info += certifiedKey.certificateInfo()
        
        // Add fingerprint
        let fingerprint = certifiedKey.originalKey.fingerprint(hash: .sha256, format: .base64)
        info += "Public key: \(certifiedKey.originalKey.keyType.rawValue) \(fingerprint)\n"
        
        return info
    }
    
    /// Verify a certificate for a host principal.
    ///
    /// Performs verification with options appropriate for host certificates:
    /// `.host` type, required principal match, and wildcard principal matching
    /// enabled (e.g., `*.example.com`).
    ///
    /// - Parameters:
    ///   - certifiedKey: The certificate to verify.
    ///   - hostname: Hostname that must appear (directly or via wildcard) in the
    ///     certificate’s principals.
    ///   - caKey: Optional CA key to pin verification to a specific authority.
    ///   - date: Verification time override (defaults to `Date()`).
    /// - Returns: A ``CertificateVerificationResult`` with details of the
    ///   verification outcome.
    /// - SeeAlso: ``CertificateVerifier``
    public static func verifyCertificateForHost(
        _ certifiedKey: CertifiedKey,
        hostname: String,
        caKey: (any SSHKey)? = nil,
        at date: Date = Date()
    ) -> CertificateVerificationResult {
        var options = CertificateVerificationOptions()
        options.verifyTime = date
        options.expectedCertificateType = .host
        options.requirePrincipal = true
        options.allowedPrincipals = [hostname]
        options.wildcardPrincipalMatching = true
        
        return CertificateVerifier.verifyCertificate(certifiedKey, caKey: caKey, options: options)
    }
    
    /// Verify a certificate for a user principal.
    ///
    /// Performs verification with options appropriate for user certificates:
    /// `.user` type, required principal match, and no wildcard principal
    /// matching.
    ///
    /// - Parameters:
    ///   - certifiedKey: The certificate to verify.
    ///   - username: Username that must appear in the certificate’s principals.
    ///   - caKey: Optional CA key to pin verification to a specific authority.
    ///   - date: Verification time override (defaults to `Date()`).
    /// - Returns: A ``CertificateVerificationResult`` with details of the
    ///   verification outcome.
    /// - SeeAlso: ``CertificateVerifier``
    public static func verifyCertificateForUser(
        _ certifiedKey: CertifiedKey,
        username: String,
        caKey: (any SSHKey)? = nil,
        at date: Date = Date()
    ) -> CertificateVerificationResult {
        var options = CertificateVerificationOptions()
        options.verifyTime = date
        options.expectedCertificateType = .user
        options.requirePrincipal = true
        options.allowedPrincipals = [username]
        options.wildcardPrincipalMatching = false
        
        return CertificateVerifier.verifyCertificate(certifiedKey, caKey: caKey, options: options)
    }
    
    /// Parse and format certificate information from a single line.
    ///
    /// - Parameter certString: A single OpenSSH certificate line
    ///   (`<type> <base64> [comment]`).
    /// - Returns: Human‑readable certificate information, as produced by
    ///   ``displayCertificateInfo(_:)``.
    /// - Throws: ``SSHKeyError`` if parsing fails.
    public static func parseCertificateString(_ certString: String) throws -> String {
        let certifiedKey = try CertificateParser.parseCertificate(from: certString)
        return displayCertificateInfo(certifiedKey)
    }
    
    /// Create a `.user` certificate with sensible defaults.
    ///
    /// Signs `publicKey` with `caKey` to produce a user certificate with standard
    /// OpenSSH user extensions when none are provided (X11/agent/port
    /// forwarding, PTY, user rc). Optional critical options include
    /// ``SSHCertificateOption/forceCommand`` and ``SSHCertificateOption/sourceAddress``.
    ///
    /// - Parameters:
    ///   - publicKey: The subject key to certify.
    ///   - caKey: The certificate authority private key used to sign the
    ///     certificate.
    ///   - username: The key ID and principal for the certificate.
    ///   - validityDays: Validity window in days starting now (default `30`).
    ///   - forceCommand: Optional forced command (critical option).
    ///   - sourceAddress: Optional source address list (critical option).
    /// - Returns: A ``CertifiedKey`` containing the subject key and attached
    ///   certificate.
    /// - Throws: ``SSHKeyError`` for signing/encoding failures.
    /// - SeeAlso: ``CertificateAuthority/signCertificate(publicKey:caKey:keyId:principals:serial:validFrom:validTo:certificateType:criticalOptions:extensions:signatureAlgorithm:)``
    public static func createUserCertificate(
        publicKey: any SSHKey,
        caKey: any SSHKey,
        username: String,
        validityDays: Int = 30,
        forceCommand: String? = nil,
        sourceAddress: String? = nil
    ) throws -> CertifiedKey {
        let validFrom = Date()
        let validTo = validFrom.addingTimeInterval(Double(validityDays) * 24 * 60 * 60)
        
        var criticalOptions: [(SSHCertificateOption, String)] = []
        if let cmd = forceCommand {
            criticalOptions.append((.forceCommand, cmd))
        }
        if let addr = sourceAddress {
            criticalOptions.append((.sourceAddress, addr))
        }
        
        return try CertificateAuthority.signCertificate(
            publicKey: publicKey,
            caKey: caKey,
            keyId: username,
            principals: [username],
            validFrom: validFrom,
            validTo: validTo,
            certificateType: .user,
            criticalOptions: criticalOptions
        )
    }
}
