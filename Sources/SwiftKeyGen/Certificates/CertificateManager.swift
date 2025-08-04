import Foundation

/// Certificate manager for working with SSH certificates
public struct CertificateManager {
    
    /// Save a certified key to file
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
    
    /// Read a certificate from file
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
    
    /// Generate certificate files for multiple hosts
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
    
    /// Display certificate information
    public static func displayCertificateInfo(_ certifiedKey: CertifiedKey) -> String {
        var info = ""
        info += certifiedKey.certificateInfo()
        
        // Add fingerprint
        let fingerprint = certifiedKey.originalKey.fingerprint(hash: .sha256, format: .base64)
        info += "Public key: \(certifiedKey.originalKey.keyType.rawValue) \(fingerprint)\n"
        
        return info
    }
    
    /// Check if a certificate is valid for a specific host
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
    
    /// Check if a certificate is valid for a specific user
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
    
    /// Parse and display certificate from string
    public static func parseCertificateString(_ certString: String) throws -> String {
        let certifiedKey = try CertificateParser.parseCertificate(from: certString)
        return displayCertificateInfo(certifiedKey)
    }
    
    /// Create a certificate with default user permissions
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