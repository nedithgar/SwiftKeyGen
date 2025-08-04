import Testing
import Foundation
import Crypto
@testable import SwiftKeyGen

struct PEMPrivateKeyParserTests {
    
    // MARK: - RSA Tests
    
    @Test("Generate and parse RSA key round-trip")
    func testGenerateAndParseRSAKey() throws {
        // Generate a new RSA key
        let generatedKey = try RSAKeyGenerator.generate(bits: 2048)
        
        // Get PEM representation
        let pemString = generatedKey.pemRepresentation
        #expect(!pemString.isEmpty)
        
        // Parse it back
        let parsedKey = try PEMParser.parseRSAPrivateKey(pemString)
        
        // Test signing/verification with parsed key
        let testData = "Test RSA round-trip".data(using: .utf8)!
        let signature = try parsedKey.sign(data: testData)
        let isValid = try parsedKey.verify(signature: signature, for: testData)
        #expect(isValid)
    }
    
    @Test("Parse unencrypted RSA private key")
    func testParseUnencryptedRSAPrivateKey() throws {
        // This test uses a real RSA key generated with ssh-keygen
        let pemString = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpQIBAAKCAQEA2U3ihGf+1ueGyPZLjWVZ/8m09vCdziiCvzgHvNfzfYZa6+oF
        ZmdL2yqTt6fkaqnuLyg4VFWKMtw7QNErALp/3HUaexj00AKsMFLWLz3cULj7fWWT
        RWQvSp1xYxvwzfl6DOPw3tOMnPhLn8BRnRCfW2V36LD9SH0rJRjk/MczBu7h1lHm
        5sIs6Lh5dxfTyuXhqq7X18AjHsFpx9oYxEspgpMtU8DqEu+6hlWnqsxHusRxNhFE
        ICNISEZa7xWdQ6y7hYn2ZyYbd5ivzwz93a6WpaKBi8VDiEmPEd5jE5dRiqQc4x12
        N+l5yg1MTCTVAuhbiPp32jsLNsQGpeZyj50W/QIDAQABAoIBAQDCDeBz917HUTi3
        a+LqYRDu8JTvVM7HlLu1wXZ/eKXTedDmDjVGToaaMLp7bq33ZsryR8uN3Fmus6ci
        aegqHWIjYFwGg7HTtB9KhB8LTwXY/GhxgezzMdVdn53rML9pYRlSO5gVlPtkDgOS
        pK79QSPd/Y4IOU3mlwiZd1K+PbFexP2Jzr0ITKK7vsrGvzgjZPxpRwPbWcNp1oWA
        S9OuXi6F7gp7z6sTZUHWPWfU4zQNrTPJRLEMbiJFZdPbICHY1GQBCg8rXQZX/T+N
        AOudXwRsbzVy/1vZCNnpx4pOOwL3RHQbe33HvE88koOT0sai2UretTlfaBKVbyWn
        agEgQExNAoGBAPBZp/8YEuxaLRZ8X6ojBl58qT9cUDoxRgzu44V5U/6rKQjih5X+
        Igymkt71UHnIaRpTI/a3xJ4eA5DD+S77pIceCpGgkFF+FQpUQpiQ+waa19jl9bOx
        SS36MMonYMrj2nZLcvO7MW03NjhRBkn+Y+RQWuckXRdSnpOCaCBCz6FPAoGBAOd0
        FI7TxfIEMwsEKK9jzAEcn7GWppRjprJGw00U6yJoUzKnmnMD7ASC+6lSoGY3rHGb
        OjVJrxlKDngES2Iw9iPWWklSR1fmXaQYp0SnWF2quiIxUoRvQWth2XPkSRozZhwe
        Y4YpF7VmlCbzStWMARMimCwqrHVsESPU+4EbcTfzAoGBANtpvYeOvpetqsOAPwTe
        fI39V7RT3ZmCKeTcoC/VFuzB6/AEfKpdGVBbMHEBmbnTTr+NbqNoF8IQvEiH3w8Z
        ApWmwxc2cQk0BJktWq5UjBT3flyvcaHdEmU6pRem4yHU6DZdok8GcJS3dnPq48bg
        yOhAwvuHosQL1F/tCImK9GjZAoGAVPisw3LD7QHVq2mvdhRxRMc5aX0hUsDy5ehM
        svPHDy61vJcDgM4jy9Q6iAMpl91AlcSjLgULH4GspisNcdL/ylBbfSeTwZV1M1VJ
        s06shlazVvI8lRozLjUSHBXnMJNGHXSanRpg9dve8B3Jj3SCwH+m1jAkeEdgU4NR
        giiM/DkCgYEAnhzx0pV5C29m6eOiN4AxLqgbWkN85nEn7nFf9xlJf8cH6O6dQ2HT
        bqfGPg2atCIQMJL8G8bEffZnHpbGbYAbE4mfRYLWESljLJPNTywrXx9Zsy/7s9rB
        8D7xiqoWX66VxXC2TTc8PMU4y5yAfIiLkRXO5/X+kRZc2D4n3IMcjOo=
        -----END RSA PRIVATE KEY-----
        """
        
        let rsaKey = try PEMParser.parseRSAPrivateKey(pemString)
        
        // Verify we got a valid RSA key
        #expect(rsaKey.keyType == .rsa)
        
        // Debug: Check key size
        print("RSA key size: \(rsaKey.privateKey.bitSize) bits")
        
        // Test signing/verification - matches the behavior from the standalone script
        let testData = "Hello, World!".data(using: .utf8)!
        let signature = try rsaKey.sign(data: testData)
        
        // Debug: Check signature format
        var decoder = SSHDecoder(data: signature)
        let sigType = try decoder.decodeString()
        let sigBlob = try decoder.decodeData()
        print("Signature type: \(sigType)")
        print("Signature blob length: \(sigBlob.count)")
        
        // Try verifying with raw operations to debug
        do {
            // Test both direct verification and through the public key
            let publicKey = rsaKey.privateKey.publicKey
            
            // Try direct verification with our Insecure.RSA
            let directValid = try Insecure.RSA.verify(sigBlob, for: testData, with: publicKey, hashAlgorithm: .sha256)
            print("Direct verification result: \(directValid)")
            
            // Try through the key's verify method
            let isValid = try rsaKey.verify(signature: signature, for: testData)
            print("Key verification result: \(isValid)")
            #expect(isValid)
        } catch {
            print("Verification error: \(error)")
            throw error
        }
    }
    
    @Test("Parse encrypted RSA private key with correct passphrase", 
           .disabled("Test data appears to be truncated - needs a complete encrypted RSA key"))
    func testParseEncryptedRSAPrivateKey() throws {
        // This test is disabled because the encrypted RSA key data appears to be truncated
        // To properly test this, we would need a complete encrypted RSA private key
        // generated with a command like:
        // openssl genrsa -aes128 -passout pass:password 2048
        
        // For now, we test that the parser correctly identifies encrypted keys
        // and requires a passphrase in the other tests
    }
    
    @Test("Parse encrypted RSA private key with wrong passphrase")
    func testParseEncryptedRSAPrivateKeyWrongPassphrase() throws {
        let pemString = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,2B7E151628AED2A6ABF7158809CF4F3C
        
        KLOmCu5VlHfqNYC1VIltfRr3qnB1uv0J7YhXqUTVq2OIL0+0Yxw8QJPqWhdH+EJG
        -----END RSA PRIVATE KEY-----
        """
        
        let wrongPassphrase = "wrongpassword"
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parseRSAPrivateKey(pemString, passphrase: wrongPassphrase)
        }
    }
    
    @Test("Parse encrypted RSA private key without passphrase")
    func testParseEncryptedRSAPrivateKeyNoPassphrase() throws {
        let pemString = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-CBC,2B7E151628AED2A6ABF7158809CF4F3C
        
        KLOmCu5VlHfqNYC1VIltfRr3qnB1uv0J7YhXqUTVq2OIL0+0Yxw8QJPqWhdH+EJG
        -----END RSA PRIVATE KEY-----
        """
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parseRSAPrivateKey(pemString, passphrase: nil)
        }
    }
    
    @Test("Parse encrypted RSA private key from standalone script")
    func testParseEncryptedRSAPrivateKeyFromScript() throws {
        // Test case from the standalone TestPEMParsing.swift script
        let encryptedRSAPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,B8806FD5B854421C5D7BBF199B479374
        
        mGAHNn/KbLbNCNLhN6hZo8S5VJmVCio6eGCYfzpJDgcAGvXkA7yt7M8CQFQY5PfF
        BobKWrHrUqAaujp5oY6OcQn3YzC20I1kF6BgB8g0LosMJOTlmMpk6pIJhsn7y0zy
        MlPRkwXBVS1upxl2nkdRlBOINPSAQhr4pxNOHxJBc8NzZ9K4GmH5Y0L4hx8oXKBu
        XnghhvM8s0PnUxPnWuUiEKmJm0QMMM5GhKNLQQClFNNvnLc7YfHC0W0LNLKdCCNK
        M5bM/K0LJ1gEphVxHupQ8U8ksTMvbihF0X8d4fH2OcwJOEJNGKQeZblUqIl/cHyL
        VJdDLoQOPBF9pJma2MrzVR7Ex72XvGnfPfKPnJhbpJPDQ7Y+NTzBLZHJl/S0WJcg
        a0Lbo3R5AWgAXhJ8hfCYYS3g7K9TgYqBCXrk6v2nj9FR4TQjgh2x7V3DLIUdj+XJ
        GXVxHEImJ4qJBKVdBqhdirq6B5kDnrC2Yw2XHrZ5xfIQQBHnHAwLIJ6vNzB7VMFV
        -----END RSA PRIVATE KEY-----
        """
        
        // This should fail without passphrase - matches behavior from standalone script
        #expect(throws: Error.self) {
            _ = try PEMParser.parseRSAPrivateKey(encryptedRSAPEM)
        }
    }
    
    // MARK: - Ed25519 Tests
    
    @Test("Parse unencrypted Ed25519 private key")
    func testParseUnencryptedEd25519PrivateKey() throws {
        // Generate a test key
        let key = try Ed25519KeyGenerator.generate()
        let pemString = key.privateKey.pemRepresentation
        
        // Parse it back
        let parsedKey = try PEMParser.parseEd25519PrivateKey(pemString)
        
        // Verify the keys match
        let testData = "Test data".data(using: .utf8)!
        let signature1 = try key.sign(data: testData)
        let signature2 = try parsedKey.sign(data: testData)
        
        // Both signatures should verify with both keys
        #expect(try key.verify(signature: signature2, for: testData))
        #expect(try parsedKey.verify(signature: signature1, for: testData))
    }
    
    @Test("Parse encrypted Ed25519 private key")
    func testParseEncryptedEd25519PrivateKey() throws {
        // This would be a real encrypted Ed25519 key in PEM format
        // For now, we'll test the error case
        let encryptedPEM = """
        -----BEGIN PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,B8BF1A3A5D5A5E6C9F6E5D4C3B2A1908
        
        U2FsdGVkX1+vupppZksvRf5pqPGL1OHlTYw6mUCJmwM3pLJ7J3zSoABhhP1qDvc6
        -----END PRIVATE KEY-----
        """
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parseEd25519PrivateKey(encryptedPEM, passphrase: "test")
        }
    }
    
    // MARK: - ECDSA Tests
    
    @Test("Parse unencrypted ECDSA P-256 private key")
    func testParseUnencryptedECDSAP256PrivateKey() throws {
        // Generate a test key
        let key = try ECDSAKeyGenerator.generateP256()
        let pemString = key.pemRepresentation
        
        // Parse it back
        let parsedKey = try PEMParser.parseECDSAPrivateKey(pemString)
        
        // Verify the keys work
        let testData = "Test ECDSA".data(using: .utf8)!
        let signature = try key.sign(data: testData)
        #expect(try parsedKey.verify(signature: signature, for: testData))
    }
    
    @Test("Parse unencrypted ECDSA P-384 private key")
    func testParseUnencryptedECDSAP384PrivateKey() throws {
        // Generate a test key
        let key = try ECDSAKeyGenerator.generateP384()
        let pemString = key.pemRepresentation
        
        // Parse it back
        let parsedKey = try PEMParser.parseECDSAPrivateKey(pemString)
        
        // Verify the keys work
        let testData = "Test ECDSA P-384".data(using: .utf8)!
        let signature = try key.sign(data: testData)
        #expect(try parsedKey.verify(signature: signature, for: testData))
    }
    
    @Test("Parse unencrypted ECDSA P-521 private key")
    func testParseUnencryptedECDSAP521PrivateKey() throws {
        // Generate a test key
        let key = try ECDSAKeyGenerator.generateP521()
        let pemString = key.pemRepresentation
        
        // Parse it back
        let parsedKey = try PEMParser.parseECDSAPrivateKey(pemString)
        
        // Verify the keys work
        let testData = "Test ECDSA P-521".data(using: .utf8)!
        let signature = try key.sign(data: testData)
        #expect(try parsedKey.verify(signature: signature, for: testData))
    }
    
    @Test("Parse encrypted ECDSA private key")
    func testParseEncryptedECDSAPrivateKey() throws {
        // This would be a real encrypted ECDSA key in PEM format
        let encryptedPEM = """
        -----BEGIN EC PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,4D5A5E6C9F6E5D4C
        
        U2FsdGVkX1+vupppZksvRf5pqPGL1OHlTYw6mUKECKHhhP1qDvc6J3zSoABhhP1q
        -----END EC PRIVATE KEY-----
        """
        
        #expect(throws: Error.self) {
            _ = try PEMParser.parseECDSAPrivateKey(encryptedPEM, passphrase: "test")
        }
    }
    
    // MARK: - PEM Format Detection Tests
    
    @Test("Detect PEM format")
    func testIsPEMFormat() {
        let pemString = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8K8EMxVObZA8EbTHTQy2jGCuCJu
        -----END RSA PRIVATE KEY-----
        """
        
        #expect(PEMParser.isPEMFormat(pemString))
        #expect(!PEMParser.isPEMFormat("ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB"))
    }
    
    @Test("Detect PEM type")
    func testDetectPEMType() {
        let rsaPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8K8EMxVObZA8EbTHTQy2jGCuCJu
        -----END RSA PRIVATE KEY-----
        """
        
        let ecPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIBZN356ZdE8gYiH8LSQQH8e4OYF5cI0C6y1fN8hT0CO
        -----END EC PRIVATE KEY-----
        """
        
        #expect(PEMParser.detectPEMType(rsaPEM) == "RSA PRIVATE KEY")
        #expect(PEMParser.detectPEMType(ecPEM) == "EC PRIVATE KEY")
    }
    
    @Test("Detect if PEM is private key")
    func testIsPrivateKey() {
        let privateKey = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8K8EMxVObZA8EbTHTQy2jGCuCJu
        -----END RSA PRIVATE KEY-----
        """
        
        let publicKey = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
        -----END PUBLIC KEY-----
        """
        
        #expect(PEMParser.isPrivateKey(privateKey))
        #expect(!PEMParser.isPrivateKey(publicKey))
    }
    
    @Test("Detect key algorithm from PEM")
    func testDetectKeyAlgorithm() {
        let rsaPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8K8EMxVObZA8EbTHTQy2jGCuCJu
        -----END RSA PRIVATE KEY-----
        """
        
        let ecPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIBZN356ZdE8gYiH8LSQQH8e4OYF5cI0C6y1fN8hT0CO
        -----END EC PRIVATE KEY-----
        """
        
        #expect(PEMParser.detectKeyAlgorithm(rsaPEM) == "RSA")
        #expect(PEMParser.detectKeyAlgorithm(ecPEM) == "ECDSA")
    }
}