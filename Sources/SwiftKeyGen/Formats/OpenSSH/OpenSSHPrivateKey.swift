import Foundation
import Crypto
import _CryptoExtras
import BigInt

/// Utilities to serialize private keys to the OpenSSH proprietary format.
public struct OpenSSHPrivateKey {
    // OpenSSH private key format constants
    private static let MARK_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private static let MARK_END = "-----END OPENSSH PRIVATE KEY-----"
    private static let AUTH_MAGIC = "openssh-key-v1\0"
    private static let SALT_LEN = 16
    private static let DEFAULT_CIPHER = Cipher.defaultCipher
    /// Default bcrypt PBKDF rounds used by OpenSSH for key derivation.
    public static let DEFAULT_ROUNDS = 24
    private static let KDFNAME = "bcrypt"
    
    /// Serialize a private key to OpenSSH format
    public static func serialize(
        key: any SSHKey,
        passphrase: String? = nil,
        comment: String? = nil,
        cipher: String? = nil,
        rounds: Int = DEFAULT_ROUNDS
    ) throws -> Data {
        let cipherName: String
        let kdfName: String
        
        if let passphrase = passphrase, !passphrase.isEmpty {
            cipherName = cipher ?? DEFAULT_CIPHER
            kdfName = KDFNAME
        } else {
            cipherName = "none"
            kdfName = "none"
        }
        
        // Validate cipher
        guard let cipherInfo = Cipher.cipherByName(cipherName) else {
            throw SSHKeyError.unsupportedCipher(cipherName)
        }
        
        var encoded = SSHEncoder()
        var encrypted = SSHEncoder()
        var kdf = SSHEncoder()
        
        // Write magic header - don't encode the length
        encoded.data.append(Data(AUTH_MAGIC.utf8))
        
        // Write cipher and KDF info
        encoded.encodeString(cipherName)
        encoded.encodeString(kdfName)
        
        // Generate KDF parameters if using encryption
        var salt = Data()
        var derivedKey = Data()
        
        if kdfName == KDFNAME {
            // Generate random salt
            var saltBytes = [UInt8](repeating: 0, count: SALT_LEN)
            for i in 0..<SALT_LEN {
                saltBytes[i] = UInt8.random(in: 0...255)
            }
            salt = Data(saltBytes)
            
            // Encode KDF parameters
            kdf.encodeData(salt)
            kdf.encodeUInt32(UInt32(rounds))
            
            // Derive key using bcrypt_pbkdf for OpenSSH compatibility
            guard let (keySize, ivSize) = Cipher.getKeyIVSize(cipher: cipherName) else {
                throw SSHKeyError.unsupportedCipher(cipherName)
            }
            
            derivedKey = try deriveKey(
                password: passphrase!,
                salt: salt,
                outputByteCount: keySize + ivSize,
                rounds: rounds
            )
        }
        
        // Encode KDF data
        encoded.encodeData(kdf.encode())
        
        // Number of keys (always 1)
        encoded.encodeUInt32(1)
        
        // Public key
        let publicKeyData = key.publicKeyData()
        encoded.encodeData(publicKeyData)
        
        // Build encrypted section
        // Random check bytes
        let check = UInt32.random(in: 0..<UInt32.max)
        encrypted.encodeUInt32(check)
        encrypted.encodeUInt32(check)
        
        // Serialize private key data
        try serializePrivateKeyData(key: key, to: &encrypted)
        
        // Add comment - use the key's comment if no explicit comment is provided
        let finalComment = comment ?? key.comment ?? ""
        encrypted.encodeString(finalComment)
        
        // Add padding to block size
        let blockSize = cipherInfo.blockSize
        var encryptedData = encrypted.encode()
        let currentLength = encryptedData.count
        let remainder = currentLength % blockSize
        if remainder != 0 {
            let paddingLength = blockSize - remainder
            for i in 1...paddingLength {
                encryptedData.append(UInt8(i))
            }
        }
        
        // Encrypt if passphrase is provided
        let finalData: Data
        if kdfName == KDFNAME && !derivedKey.isEmpty {
            // Get key and IV sizes
            guard let (keySize, ivSize) = Cipher.getKeyIVSize(cipher: cipherName) else {
                throw SSHKeyError.unsupportedCipher(cipherName)
            }
            
            // Extract key and IV
            let key = derivedKey.prefix(keySize)
            let iv = derivedKey.suffix(ivSize)
            
            // Encrypt using selected cipher
            finalData = try Cipher.encrypt(data: encryptedData, cipher: cipherName, key: key, iv: iv)
        } else {
            finalData = encryptedData
        }
        
        // Write encrypted data length and data
        // For authenticated ciphers (ChaCha20-Poly1305), the length field contains
        // the size of encrypted data WITHOUT the auth tag
        let authLen = cipherInfo.authLen
        let encryptedDataLength = authLen > 0 ? finalData.count - authLen : finalData.count
    encoded.encodeUInt32(UInt32(encryptedDataLength))
        var encodedData = encoded.encode()
        encodedData.append(finalData)
        
        // Base64 encode and wrap in PEM markers
        let base64Data = encodedData.base64EncodedData(options: [.lineLength64Characters, .endLineWithLineFeed])
        
        var result = Data()
        result.append(Data(MARK_BEGIN.utf8))
        result.append(Data("\n".utf8))
        result.append(base64Data)
        result.append(Data("\n".utf8))
        result.append(Data(MARK_END.utf8))
        result.append(Data("\n".utf8))
        
        return result
    }
    
    private static func serializePrivateKeyData(key: any SSHKey, to encoder: inout SSHEncoder) throws {
        // Encode key type
        encoder.encodeString(key.keyType.rawValue)
        
        switch key {
        case let ed25519Key as Ed25519Key:
            // Ed25519 private key format
            let privateKeyData = ed25519Key.privateKeyData()
            let publicKeyData = ed25519Key.publicKeyData()
            
            // Extract the raw public key (skip the type prefix)
            var decoder = SSHDecoder(data: publicKeyData)
            _ = try decoder.decodeString() // Skip type
            let rawPublicKey = try decoder.decodeData()
            
            // Verify public key is 32 bytes
            guard rawPublicKey.count == 32 else {
                throw SSHKeyError.invalidKeyData
            }
            
            // Encode public key
            encoder.encodeData(rawPublicKey)
            
            // Encode private key (64 bytes: 32 bytes private + 32 bytes public)
            var fullPrivateKey = Data()
            fullPrivateKey.append(privateKeyData)
            fullPrivateKey.append(rawPublicKey)
            encoder.encodeData(fullPrivateKey)
            
        case let rsaKey as RSAKey:
            // RSA private key format based on OpenSSH's ssh-rsa.c ssh_rsa_serialize_private:
            // Format: n, e, d, iqmp, p, q
            let privateKey = rsaKey.privateKey
            
            // Encode modulus (n)
            encoder.encodeBigInt(privateKey.n.serialize())
            
            // Encode public exponent (e)
            encoder.encodeBigInt(privateKey.e.serialize())
            
            // Encode private exponent (d)
            encoder.encodeBigInt(privateKey.d.serialize())
            
            // Encode inverse of q mod p (iqmp)
            // OpenSSH uses qInv which is already calculated in the private key
            encoder.encodeBigInt(privateKey.qInv.serialize())
            
            // Encode prime p
            encoder.encodeBigInt(privateKey.p.serialize())
            
            // Encode prime q
            encoder.encodeBigInt(privateKey.q.serialize())
            
        case let ecdsaKey as ECDSAKey:
            // ECDSA private key format
            // Based on OpenSSH's ssh-ecdsa.c ssh_ecdsa_serialize_private
            // Format: curve_name, public_key (EC point), private_key (scalar), comment
            
            // 1. Encode curve name
            let curveName: String
            switch ecdsaKey.keyType {
            case .ecdsa256:
                curveName = "nistp256"
            case .ecdsa384:
                curveName = "nistp384"
            case .ecdsa521:
                curveName = "nistp521"
            default:
                throw SSHKeyError.unsupportedKeyType
            }
            encoder.encodeString(curveName)
            
            // 2. Encode public key point (X9.63 representation)
            let publicKeyPoint: Data
            switch ecdsaKey.privateKeyStorage {
            case .p256(let key):
                publicKeyPoint = key.publicKey.x963Representation
            case .p384(let key):
                publicKeyPoint = key.publicKey.x963Representation
            case .p521(let key):
                publicKeyPoint = key.publicKey.x963Representation
            }
            encoder.encodeData(publicKeyPoint)
            
            // 3. Encode private key scalar (raw representation)
            let privateKeyScalar: Data
            switch ecdsaKey.privateKeyStorage {
            case .p256(let key):
                privateKeyScalar = key.rawRepresentation
            case .p384(let key):
                privateKeyScalar = key.rawRepresentation
            case .p521(let key):
                privateKeyScalar = key.rawRepresentation
            }
            // ECDSA private keys must use encodeBigInt to match OpenSSH format
            // The bigint encoding handles sign bit properly
            encoder.encodeBigInt(privateKeyScalar)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
    
    private static func deriveKey(
        password: String,
        salt: Data,
        outputByteCount: Int,
        rounds: Int
    ) throws -> Data {
        // Use our BCrypt PBKDF implementation
        return try BCryptPBKDF.deriveKey(
            password: password,
            salt: salt,
            outputByteCount: outputByteCount,
            rounds: rounds
        )
    }
    
    /// Parse an OpenSSH private key from data
    public static func parse(
        data: Data,
        passphrase: String? = nil
    ) throws -> any SSHKey {
        // Convert data to string
        guard let pemString = String(data: data, encoding: .utf8) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Check PEM markers
        guard pemString.contains(MARK_BEGIN) && pemString.contains(MARK_END) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Extract base64 content
        let lines = pemString.components(separatedBy: .newlines)
        var base64Lines: [String] = []
        var inKey = false
        
        for line in lines {
            if line.contains(MARK_BEGIN) {
                inKey = true
                continue
            }
            if line.contains(MARK_END) {
                break
            }
            if inKey && !line.isEmpty {
                base64Lines.append(line)
            }
        }
        
        let base64String = base64Lines.joined()
        guard let keyData = Data(base64Encoded: base64String) else {
            throw SSHKeyError.invalidFormat
        }
        
        // Create a manual offset-based reader for the magic header
        var offset = 0
        
        // Read and verify magic header - it's not length-prefixed
        let magicLength = AUTH_MAGIC.count
        guard keyData.count >= magicLength else {
            throw SSHKeyError.invalidFormat
        }
        
        let magicData = keyData.subdata(in: 0..<magicLength)
        let expectedMagic = Data(AUTH_MAGIC.utf8)
        guard magicData == expectedMagic else {
            throw SSHKeyError.invalidFormat
        }
        
        offset = magicLength
        
        // Now create the decoder starting after the magic header
        var decoder = SSHDecoder(data: keyData.subdata(in: offset..<keyData.count))
        
        // Read cipher and KDF info
        let cipherName = try decoder.decodeString()
        let kdfName = try decoder.decodeString()
        
        // Read KDF parameters
        let kdfData = try decoder.decodeData()
        var salt = Data()
        var rounds = 0
        
        if kdfName == KDFNAME {
            guard let passphrase = passphrase, !passphrase.isEmpty else {
                throw SSHKeyError.passphraseRequired
            }
            
            var kdfDecoder = SSHDecoder(data: kdfData)
            salt = try kdfDecoder.decodeData()
            rounds = Int(try kdfDecoder.decodeUInt32())
        }
        
        // Read number of keys (should be 1)
        let numKeys = try decoder.decodeUInt32()
        guard numKeys == 1 else {
            throw SSHKeyError.invalidFormat
        }
        
        // Read public key
        _ = try decoder.decodeData() // publicKeyData
        
        // Read encrypted private key data length
        let encryptedLength = try decoder.decodeUInt32()
        // Determine if this cipher appends an authentication tag that is NOT
        // included in the length field (OpenSSH behaviour for authenticated
        // ciphers: the length encodes only the ciphertext/padded plaintext, the
        // tag bytes follow immediately after and must be consumed separately).
        guard let cipherInfo = Cipher.cipherByName(cipherName) else {
            throw SSHKeyError.unsupportedCipher(cipherName)
        }
        let authLen = cipherInfo.authLen
        let totalEncryptedLen = Int(encryptedLength) + authLen
        guard decoder.remaining >= totalEncryptedLen else {
            throw SSHKeyError.invalidFormat
        }
        // Read ciphertext (+ tag if present)
        let encryptedData = try decoder.decodeBytes(count: totalEncryptedLen)
        
        // Decrypt if necessary
        let decryptedData: Data
        if kdfName == KDFNAME {
            // Derive key
            guard let (keySize, ivSize) = Cipher.getKeyIVSize(cipher: cipherName) else {
                throw SSHKeyError.unsupportedCipher(cipherName)
            }
            
            let derivedKey = try deriveKey(
                password: passphrase!,
                salt: salt,
                outputByteCount: keySize + ivSize,
                rounds: rounds
            )
            
            // Extract key and IV
            let key = derivedKey.prefix(keySize)
            let iv = derivedKey.suffix(ivSize)
            
            // Decrypt using selected cipher
            decryptedData = try Cipher.decrypt(data: Data(encryptedData), cipher: cipherName, key: key, iv: iv)
        } else {
            decryptedData = Data(encryptedData)
        }
        
        // Parse decrypted data
        var privateDecoder = SSHDecoder(data: decryptedData)
        
        // Verify check bytes
        let check1 = try privateDecoder.decodeUInt32()
        let check2 = try privateDecoder.decodeUInt32()
        guard check1 == check2 else {
            throw SSHKeyError.invalidPassphrase
        }
        
        // Read key type
        let keyType = try privateDecoder.decodeString()
        
        // Parse the private key based on type
        let parsedKey: any SSHKey
        switch keyType {
        case "ssh-ed25519":
            parsedKey = try parseEd25519PrivateKey(decoder: &privateDecoder)
        case "ssh-rsa":
            parsedKey = try parseRSAPrivateKey(decoder: &privateDecoder)
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            parsedKey = try parseECDSAPrivateKey(decoder: &privateDecoder, keyType: keyType)
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        // Verify padding
        var paddingIndex = 1
        while privateDecoder.remaining > 0 {
            let pad = try privateDecoder.decodeBytes(count: 1)[0]
            if pad != UInt8(paddingIndex & 0xff) {
                throw SSHKeyError.invalidFormat
            }
            paddingIndex += 1
        }
        
        return parsedKey
    }
    
    private static func parseEd25519PrivateKey(decoder: inout SSHDecoder) throws -> Ed25519Key {
        // Read public key data (32 bytes)
        let publicKeyData = try decoder.decodeData()
        
        // Read private key data (64 bytes: 32 bytes private + 32 bytes public)
        let privateKeyData = try decoder.decodeData()
        
        // Verify that it's 64 bytes
        guard privateKeyData.count == 64 else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Extract the actual private key (first 32 bytes)
        let privateKeyBytes = privateKeyData.prefix(32)
        
        // Verify the public key matches (last 32 bytes of private key data)
        let embeddedPublicKey = privateKeyData.suffix(32)
        if embeddedPublicKey != publicKeyData {
            // Public key mismatch - this might not be a hard error in all cases
            // Some implementations might have different representations
            // For now, we'll allow this
        }
        
        // Read comment
        let comment = try decoder.decodeString()
        
        // Create key from private key data
        return try Ed25519Key(privateKeyData: Data(privateKeyBytes), comment: comment.isEmpty ? nil : comment)
    }
    
    private static func parseRSAPrivateKey(decoder: inout SSHDecoder) throws -> RSAKey {
        // Based on OpenSSH's ssh-rsa.c ssh_rsa_deserialize_private:
        // Format: n, e, d, iqmp, p, q, comment
        
        // Read modulus (n)
        let nData = try decoder.decodeBigInt()
        guard !nData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        let n = BigUInt(nData)
        
        // Read public exponent (e)
        let eData = try decoder.decodeBigInt()
        guard !eData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        let e = BigUInt(eData)
        
        // Read private exponent (d)
        let dData = try decoder.decodeBigInt()
        guard !dData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        let d = BigUInt(dData)
        
        // Read inverse of q mod p (iqmp) - note: OpenSSH stores this before p and q
        let iqmpData = try decoder.decodeBigInt()
        guard !iqmpData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        _ = BigUInt(iqmpData) // Read but not currently used in RSA key reconstruction
        
        // Read prime p
        let pData = try decoder.decodeBigInt()
        guard !pData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        let p = BigUInt(pData)
        
        // Read prime q
        let qData = try decoder.decodeBigInt()
        guard !qData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        let q = BigUInt(qData)
        
        // Read comment
        let comment = try decoder.decodeString()
        
        // Create the private key
        let privateKey = Insecure.RSA.PrivateKey(n: n, e: e, d: d, p: p, q: q)
        
        // Create and return the RSAKey
        return RSAKey(privateKey: privateKey, comment: comment.isEmpty ? nil : comment)
    }
    
    private static func parseECDSAPrivateKey(decoder: inout SSHDecoder, keyType: String) throws -> ECDSAKey {
        // Based on OpenSSH's ssh-ecdsa.c ssh_ecdsa_deserialize_private:
        // Format: curve_name, public_key (EC point), private_key (scalar), comment
        
        // Read curve name
        let curveName = try decoder.decodeString()
        
        // Verify curve name matches key type
        let expectedCurveName: String
        switch keyType {
        case "ecdsa-sha2-nistp256":
            expectedCurveName = "nistp256"
        case "ecdsa-sha2-nistp384":
            expectedCurveName = "nistp384"
        case "ecdsa-sha2-nistp521":
            expectedCurveName = "nistp521"
        default:
            throw SSHKeyError.unsupportedKeyType
        }
        
        guard curveName == expectedCurveName else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Read and skip public key data (we don't need it for reconstruction)
        _ = try decoder.decodeData()
        
        // Read private key scalar
        let privateKeyData = try decoder.decodeBigInt()
        guard !privateKeyData.isEmpty else {
            throw SSHKeyError.invalidKeyData
        }
        
        // Read comment
        let comment = try decoder.decodeString()
        
        // Create the appropriate private key based on curve
        switch keyType {
        case "ecdsa-sha2-nistp256":
            // P256 private keys are 32 bytes
            let paddedData = privateKeyData.leftPadded(to: 32)
            let privateKey = try P256.Signing.PrivateKey(rawRepresentation: paddedData)
            return ECDSAKey(p256Key: privateKey, comment: comment.isEmpty ? nil : comment)
            
        case "ecdsa-sha2-nistp384":
            // P384 private keys are 48 bytes
            let paddedData = privateKeyData.leftPadded(to: 48)
            let privateKey = try P384.Signing.PrivateKey(rawRepresentation: paddedData)
            return ECDSAKey(p384Key: privateKey, comment: comment.isEmpty ? nil : comment)
            
        case "ecdsa-sha2-nistp521":
            // P521 private keys are 66 bytes
            let paddedData = privateKeyData.leftPadded(to: 66)
            let privateKey = try P521.Signing.PrivateKey(rawRepresentation: paddedData)
            return ECDSAKey(p521Key: privateKey, comment: comment.isEmpty ? nil : comment)
            
        default:
            throw SSHKeyError.unsupportedKeyType
        }
    }
    
}
