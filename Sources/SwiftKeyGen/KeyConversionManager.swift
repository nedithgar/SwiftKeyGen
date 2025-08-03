import Foundation
import Crypto

/// Centralized manager for key format conversions
public struct KeyConversionManager {
    
    /// Input/output options for conversion
    public struct ConversionOptions {
        public var input: String = "-"      // Default to stdin
        public var output: String = "-"     // Default to stdout
        public var fromFormat: KeyFormat?   // Auto-detect if nil
        public var toFormat: KeyFormat
        public var passphrase: String?
        
        public init(toFormat: KeyFormat, 
                   fromFormat: KeyFormat? = nil,
                   input: String = "-",
                   output: String = "-",
                   passphrase: String? = nil) {
            self.toFormat = toFormat
            self.fromFormat = fromFormat
            self.input = input
            self.output = output
            self.passphrase = passphrase
        }
    }
    
    /// Convert a key between formats
    public static func convertKey(options: ConversionOptions) throws {
        // Read input
        let inputString: String
        
        if options.input == KeyFileManager.STDIN_STDOUT_FILENAME {
            inputString = try KeyFileManager.readStringFromStdin()
        } else {
            inputString = try String(contentsOfFile: options.input, encoding: .utf8)
        }
        
        // Detect format if not specified
        let sourceFormat = try options.fromFormat ?? detectFormat(from: inputString)
        
        // Parse the key based on format
        let keyData: Data
        let keyType: KeyType
        let comment: String?
        
        switch sourceFormat {
        case .openssh:
            // For private keys, we need different handling
            if inputString.contains("OPENSSH PRIVATE KEY") {
                throw SSHKeyError.unsupportedOperation("OpenSSH private key conversion not yet implemented")
            }
            // Parse as public key
            let parsed = try KeyParser.parsePublicKey(inputString.trimmingCharacters(in: .whitespacesAndNewlines))
            keyData = parsed.data
            keyType = parsed.type
            comment = parsed.comment
            
        case .rfc4716:
            let parsed = try KeyParser.parseRFC4716(inputString)
            keyData = parsed.data
            keyType = parsed.type
            comment = parsed.comment
            
        case .pem, .pkcs8:
            // Try to parse as PEM format
            if PEMParser.isPEMFormat(inputString) {
                let pemType = PEMParser.detectPEMType(inputString) ?? ""
                
                if pemType.contains("RSA") {
                    let rsaPublicKey = try PEMParser.parseRSAPublicKey(inputString)
                    keyData = rsaPublicKey.publicKeyData()
                    keyType = .rsa
                    comment = rsaPublicKey.comment
                } else if pemType.contains("PUBLIC KEY") && !pemType.contains("RSA") {
                    // Could be ECDSA or Ed25519 in PKCS8 format
                    // Try to determine the key type by parsing the ASN.1 structure
                    do {
                        let ecdsaPublicKey = try PEMParser.parseECDSAPublicKey(inputString)
                        keyData = ecdsaPublicKey.publicKeyData()
                        keyType = ecdsaPublicKey.keyType
                        comment = ecdsaPublicKey.comment
                    } catch {
                        // If ECDSA parsing fails, try Ed25519
                        let ed25519PublicKey = try PEMParser.parseEd25519PublicKey(inputString)
                        keyData = ed25519PublicKey.publicKeyData()
                        keyType = .ed25519
                        comment = ed25519PublicKey.comment
                    }
                } else {
                    throw SSHKeyError.unsupportedOperation("Unsupported PEM type: \(pemType)")
                }
            } else {
                throw SSHKeyError.invalidFormat
            }
        }
        
        // Create a temporary public key for conversion
        let publicKey = try createPublicKey(from: keyData, type: keyType, comment: comment)
        
        // Convert to target format
        let outputString: String
        
        switch options.toFormat {
        case .openssh:
            outputString = publicKey.publicKeyString()
            
        case .rfc4716:
            outputString = try KeyConverter.toRFC4716(key: publicKey)
            
        case .pem, .pkcs8:
            throw SSHKeyError.unsupportedOperation("PEM/PKCS8 export requires private key")
        }
        
        // Write output
        if options.output == KeyFileManager.STDIN_STDOUT_FILENAME {
            KeyFileManager.writeStringToStdout(outputString)
            if !outputString.hasSuffix("\n") {
                KeyFileManager.writeStringToStdout("\n")
            }
        } else {
            try outputString.write(toFile: options.output, atomically: true, encoding: .utf8)
        }
    }
    
    /// Detect the format of key data
    public static func detectFormat(from keyString: String) throws -> KeyFormat {
        let trimmed = keyString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
            return .openssh
        } else if KeyParser.isRFC4716Format(trimmed) {
            return .rfc4716
        } else if PEMParser.isPEMFormat(trimmed) {
            let pemType = PEMParser.detectPEMType(trimmed) ?? ""
            if pemType.contains("RSA") && pemType.contains("PRIVATE") {
                return .pem
            } else if pemType.contains("EC") && pemType.contains("PRIVATE") {
                return .pem
            } else if pemType == "PRIVATE KEY" || pemType == "PUBLIC KEY" {
                return .pkcs8
            } else if pemType.contains("RSA PUBLIC KEY") {
                return .pem
            } else {
                return .pem
            }
        } else if trimmed.hasPrefix("ssh-") || trimmed.hasPrefix("ecdsa-") {
            return .openssh
        } else {
            throw SSHKeyError.unsupportedOperation("Unable to detect key format")
        }
    }
    
    /// Create a public key object from raw data
    private static func createPublicKey(from data: Data, type: KeyType, comment: String?) throws -> any SSHPublicKey {
        var decoder = SSHDecoder(data: data)
        let keyTypeInData = try decoder.decodeString()
        
        guard keyTypeInData == type.rawValue else {
            throw SSHKeyError.invalidKeyData
        }
        
        switch type {
        case .ed25519:
            let publicKeyBytes = try decoder.decodeData()
            guard publicKeyBytes.count == 32 else {
                throw SSHKeyError.invalidKeyData
            }
            return try Ed25519PublicKey(publicKeyData: publicKeyBytes, comment: comment)
            
        case .rsa:
            let exponent = try decoder.decodeData()
            let modulus = try decoder.decodeData()
            return try RSAPublicKey(modulus: modulus, exponent: exponent, comment: comment)
            
        case .ecdsa256, .ecdsa384, .ecdsa521:
            let curveIdentifier = try decoder.decodeString()
            let publicKeyData = try decoder.decodeData()
            
            switch type {
            case .ecdsa256:
                guard curveIdentifier == "nistp256" else {
                    throw SSHKeyError.invalidKeyData
                }
                return try ECDSAPublicKey(keyType: type, curveName: curveIdentifier, publicKeyPoint: publicKeyData, comment: comment)
                
            case .ecdsa384:
                guard curveIdentifier == "nistp384" else {
                    throw SSHKeyError.invalidKeyData
                }
                return try ECDSAPublicKey(keyType: type, curveName: curveIdentifier, publicKeyPoint: publicKeyData, comment: comment)
                
            case .ecdsa521:
                guard curveIdentifier == "nistp521" else {
                    throw SSHKeyError.invalidKeyData
                }
                return try ECDSAPublicKey(keyType: type, curveName: curveIdentifier, publicKeyPoint: publicKeyData, comment: comment)
                
            default:
                throw SSHKeyError.unsupportedKeyType
            }
        }
    }
    
    /// Convert multiple keys in batch
    public static func batchConvert(files: [String], options: ConversionOptions) throws -> [(input: String, output: String, success: Bool, error: Error?)] {
        var results: [(input: String, output: String, success: Bool, error: Error?)] = []
        
        for file in files {
            var fileOptions = options
            fileOptions.input = file
            
            // Generate output filename if writing to files
            if options.output != KeyFileManager.STDIN_STDOUT_FILENAME {
                let inputURL = URL(fileURLWithPath: file)
                let baseName = inputURL.deletingPathExtension().lastPathComponent
                let outputExt: String
                
                switch options.toFormat {
                case .openssh: outputExt = "pub"
                case .rfc4716: outputExt = "rfc"
                case .pem: outputExt = "pem"
                case .pkcs8: outputExt = "p8"
                }
                
                fileOptions.output = inputURL.deletingLastPathComponent()
                    .appendingPathComponent("\(baseName).\(outputExt)")
                    .path
            }
            
            do {
                try convertKey(options: fileOptions)
                results.append((input: file, output: fileOptions.output, success: true, error: nil))
            } catch {
                results.append((input: file, output: fileOptions.output, success: false, error: error))
            }
        }
        
        return results
    }
}