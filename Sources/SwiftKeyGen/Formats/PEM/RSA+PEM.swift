import Foundation
import Crypto
import _CryptoExtras
import BigInt

extension PEMParser {
    
    /// Parse an RSA private key from PEM format
    /// Supports both encrypted and unencrypted PKCS#1 format
    public static func parseRSAPrivateKey(_ pemString: String, passphrase: String? = nil) throws -> RSAKey {
        let trimmedPEM = pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check if it's encrypted
        if isEncryptedPEM(trimmedPEM) {
            guard let passphrase = passphrase else {
                throw SSHKeyError.passphraseRequired
            }
            return try parseEncryptedRSAPrivateKey(trimmedPEM, passphrase: passphrase)
        } else {
            return try parseUnencryptedRSAPrivateKey(trimmedPEM)
        }
    }
    
    /// Check if PEM is encrypted
    private static func isEncryptedPEM(_ pemString: String) -> Bool {
        return pemString.contains("Proc-Type:") && pemString.contains("DEK-Info:")
    }
    
    /// Parse unencrypted RSA private key
    private static func parseUnencryptedRSAPrivateKey(_ pemString: String) throws -> RSAKey {
        // Extract base64 content
        let base64Content = extractBase64FromPEM(pemString, type: "RSA PRIVATE KEY")
        guard let derData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse PKCS#1 format
        return try parseRSAPrivateKeyFromDER(derData)
    }
    
    /// Parse encrypted RSA private key
    private static func parseEncryptedRSAPrivateKey(_ pemString: String, passphrase: String) throws -> RSAKey {
        // Extract headers and encrypted data
        let lines = pemString.split(separator: "\n").map { String($0) }
        
        var procType: String?
        var dekInfo: String?
        var base64Lines: [String] = []
        var inBody = false
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") {
                continue
            } else if line.hasPrefix("-----END") {
                break
            } else if line.hasPrefix("Proc-Type:") {
                procType = line.replacingOccurrences(of: "Proc-Type:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("DEK-Info:") {
                dekInfo = line.replacingOccurrences(of: "DEK-Info:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.isEmpty {
                inBody = true
            } else if inBody {
                base64Lines.append(line)
            }
        }
        
        guard let dekInfoStr = dekInfo else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse DEK-Info: cipher,iv
        let dekParts = dekInfoStr.split(separator: ",").map { String($0) }
        guard dekParts.count == 2 else {
            throw SSHKeyError.invalidKeyData
        }
        
        let cipherName = dekParts[0]
        let ivHex = dekParts[1]
        
        guard let cipher = PEMEncryption.PEMCipher(rawValue: cipherName) else {
            throw SSHKeyError.unsupportedCipher(cipherName)
        }
        
        guard let iv = Data(hexString: ivHex) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decode encrypted data
        let base64Content = base64Lines.joined()
        guard let encryptedData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Decrypt
        let decryptedData = try PEMEncryption.decrypt(
            data: encryptedData,
            passphrase: passphrase,
            cipher: cipher,
            iv: iv
        )
        
        // Parse decrypted DER data
        return try parseRSAPrivateKeyFromDER(decryptedData)
    }
    
    /// Parse RSA private key from DER data (PKCS#1 format)
    private static func parseRSAPrivateKeyFromDER(_ derData: Data) throws -> RSAKey {
        var parser = ASN1Parser(data: derData)
        
        // Parse the outer SEQUENCE
        guard let _ = try parser.parseSequence() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Reset parser to parse inside the sequence
        parser = ASN1Parser(data: derData)
        
        // Skip sequence tag and length
        guard derData.count > 0 && derData[0] == 0x30 else {
            throw SSHKeyError.invalidKeyData
        }
        parser.offset += 1
        _ = try parser.parseLength()
        
        // Parse version (should be 0)
        guard let versionData = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse modulus (n)
        guard let modulusData = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse public exponent (e)
        guard let publicExponentData = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse private exponent (d)
        guard let privateExponentData = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse prime1 (p)
        guard let prime1Data = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse prime2 (q)
        guard let prime2Data = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse exponent1 (dP = d mod (p-1))
        guard let exponent1Data = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse exponent2 (dQ = d mod (q-1))
        guard let exponent2Data = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Parse coefficient (qInv = q^-1 mod p)
        guard let coefficientData = try parser.parseInteger() else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Convert to BigUInt
        let n = BigUInt(modulusData)
        let e = BigUInt(publicExponentData)
        let d = BigUInt(privateExponentData)
        let p = BigUInt(prime1Data)
        let q = BigUInt(prime2Data)
        let dP = BigUInt(exponent1Data)
        let dQ = BigUInt(exponent2Data)
        let qInv = BigUInt(coefficientData)
        
        // Create RSA private key using the stored CRT values
        let privateKey = Insecure.RSA.PrivateKey(
            n: n,
            e: e,
            d: d,
            p: p,
            q: q,
            dP: dP,
            dQ: dQ,
            qInv: qInv
        )
        
        return RSAKey(privateKey: privateKey)
    }
    
    /// Extract base64 content from PEM
    private static func extractBase64FromPEM(_ pemString: String, type: String) -> String {
        let beginMarker = "-----BEGIN \(type)-----"
        let endMarker = "-----END \(type)-----"
        
        let lines = pemString.split(separator: "\n").map { String($0) }
        var base64Lines: [String] = []
        var inBody = false
        
        for line in lines {
            if line.contains(beginMarker) {
                inBody = true
                continue
            } else if line.contains(endMarker) {
                break
            } else if inBody && !line.isEmpty {
                base64Lines.append(line)
            }
        }
        
        return base64Lines.joined()
    }
}



