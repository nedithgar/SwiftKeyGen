import Foundation
import Crypto
import _CryptoExtras
import BigInt

extension PEMParser {
    
    /// Parses an RSA private key from a PEM‐encoded string.
    ///
    /// This method supports classic OpenSSL / OpenSSH style PKCS#1 `RSA PRIVATE KEY` blocks
    /// in both unencrypted form:
    ///
    /// ```text
    /// -----BEGIN RSA PRIVATE KEY-----
    /// <base64>
    /// -----END RSA PRIVATE KEY-----
    /// ```
    ///
    /// and the legacy "traditional" OpenSSL PEM encryption form that includes the
    /// `Proc-Type` and `DEK-Info` headers, e.g.:
    ///
    /// ```text
    /// -----BEGIN RSA PRIVATE KEY-----
    /// Proc-Type: 4,ENCRYPTED
    /// DEK-Info: AES-256-CBC,4F7A0B5C3E8A91F6E2C1D4B5A6C7D8E9
    ///
    /// <base64 ciphertext>
    /// -----END RSA PRIVATE KEY-----
    /// ```
    ///
    /// The encrypted variant requires a passphrase in order to decrypt the PKCS#1
    /// DER payload before parsing. Decryption is delegated to `PEMEncryption` which
    /// implements the OpenSSL EVP_BytesToKey compatible key derivation + cipher flow
    /// for the supported legacy ciphers expressed in the `DEK-Info` field.
    ///
    /// - Important: Only PKCS#1 (`RSA PRIVATE KEY`) blocks are supported here. For
    ///   PKCS#8 (`PRIVATE KEY` / `ENCRYPTED PRIVATE KEY`) you must use the PKCS
    ///   parsing utilities (`PEMParser.parsePrivateKey` or a future dedicated API)
    ///   once implemented. Attempting to pass a PKCS#8 block will result in
    ///   `SSHKeyError.invalidKeyData`.
    ///
    /// - Parameter pemString: The full PEM string including the `-----BEGIN` / `-----END` lines.
    /// - Parameter passphrase: The passphrase used to decrypt an encrypted key. Omit or pass `nil`
    ///   for unencrypted keys.
    /// - Returns: A fully initialized `RSAKey` containing the private key (including CRT components).
    /// - Throws: `SSHKeyError.passphraseRequired` if the PEM is encrypted but no passphrase was provided;
    ///   `SSHKeyError.unsupportedCipher` if the cipher in `DEK-Info` is not recognized;
    ///   `SSHKeyError.invalidKeyData` if the structure, headers, base64 data, or DER payload are malformed.
    ///
    /// ### Discussion
    /// The parser performs minimal normalization (trimming surrounding whitespace/newlines) and then
    /// detects encryption by the presence of both `Proc-Type:` and `DEK-Info:` headers. For decrypted
    /// payloads, the resulting DER is parsed as a PKCS#1 `RSAPrivateKey` ASN.1 sequence extracting
    /// all CRT parameters for efficient operations.
    ///
    /// ### Example
    /// ```swift
    /// let pem = """
    /// -----BEGIN RSA PRIVATE KEY-----\n
    /// MIIBOgIBAAJBALs...snip...\n
    /// -----END RSA PRIVATE KEY-----
    /// """
    /// let rsaKey = try PEMParser.parseRSAPrivateKey(pem)
    /// print(rsaKey.publicKey.opensshString)
    /// ```
    ///
    /// ```swift
    /// let encryptedPEM = """
    /// -----BEGIN RSA PRIVATE KEY-----\n
    /// Proc-Type: 4,ENCRYPTED\n
    /// DEK-Info: AES-256-CBC,4F7A0B5C3E8A91F6E2C1D4B5A6C7D8E9\n
    /// \n
    /// <ciphertext base64>\n
    /// -----END RSA PRIVATE KEY-----
    /// """
    /// let rsaKey = try PEMParser.parseRSAPrivateKey(encryptedPEM, passphrase: "correct horse battery staple")
    /// ```
    ///
    /// Use the returned `RSAKey` for signing, public key extraction, conversion, or fingerprinting through
    /// the higher level `KeyManager` / conversion APIs.
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
        // Extract base64 content between PEM markers
        guard let base64Content = pemString.pemBody(type: "RSA PRIVATE KEY"),
              let derData = Data(base64Encoded: base64Content) else {
            throw SSHKeyError.invalidKeyData
        }
        // Parse PKCS#1 format
        return try parseRSAPrivateKeyFromDER(derData)
    }
    
    /// Parse encrypted RSA private key
    private static func parseEncryptedRSAPrivateKey(_ pemString: String, passphrase: String) throws -> RSAKey {
        // Extract headers and encrypted data
        // Use components(separatedBy:) instead of split() to preserve empty lines
        let lines = pemString.components(separatedBy: "\n")
        
        var dekInfo: String?
        var base64Lines: [String] = []
        var inBody = false
        
        for line in lines {
            if line.hasPrefix("-----BEGIN") {
                continue
            } else if line.hasPrefix("-----END") {
                break
            } else if line.hasPrefix("Proc-Type:") {
                // Ignore Proc-Type header; DEK-Info is authoritative for parameters
                continue
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
        guard let _ = try parser.parseInteger() else {
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
    
    
}
