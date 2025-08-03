# SwiftKeyGen

A pure Swift implementation of SSH key generation, compatible with OpenSSH formats. SwiftKeyGen provides a modern, type-safe API for generating and managing SSH keys across Apple platforms and Linux.

## Features

### Key Generation
- ✅ **Ed25519** key generation (recommended)
- ✅ **RSA** key generation (2048, 3072, 4096 bits)
- ✅ **ECDSA** key generation (P-256, P-384, P-521)
- ✅ Batch key generation for multiple hosts
- ✅ Generate all key types for a single identity

### Key Management
- ✅ OpenSSH private key format with passphrase encryption
- ✅ Key format conversion (OpenSSH, PEM, PKCS#8, RFC4716)
- ✅ Import public keys from PEM/PKCS#8 formats
- ✅ Import/export keys from stdin/stdout
- ✅ Multiple fingerprint algorithms (SHA256, SHA512, MD5)
- ✅ Fingerprint randomart visualization
- ✅ Key parsing and validation
- ✅ known_hosts file management
- ✅ SSH certificate generation and verification
- ✅ Full signature verification for all key types

### Security & Platform Support
- ✅ Secure file I/O with proper permissions (0600 for private keys)
- ✅ Passphrase-protected private keys
- ✅ Full signature verification (Ed25519, RSA, ECDSA)
- ✅ RSA signatures: ssh-rsa (SHA1), rsa-sha2-256, rsa-sha2-512
- ✅ ECDSA signatures: P-256 (SHA256), P-384 (SHA384), P-521 (SHA512)
- ✅ Cross-platform support (macOS, iOS, Linux)
- ✅ No external dependencies (uses Swift Crypto)

## Installation

### Swift Package Manager

Add SwiftKeyGen to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/yourusername/SwiftKeyGen.git", from: "1.0.0")
]
```

## Usage

### Basic Key Generation

```swift
import SwiftKeyGen

// Generate an Ed25519 key pair (recommended)
let keyPair = try SwiftKeyGen.generateKeyPair(
    type: .ed25519,
    comment: "user@example.com"
)

// Get the public key in OpenSSH format
print(keyPair.publicKeyString)
// Output: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@example.com

// Get the fingerprint in different formats
print(keyPair.fingerprint())
// Output: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

// Get fingerprint with bubble babble format (like ssh-keygen -B)
print(keyPair.fingerprint(hash: .sha256, format: .bubbleBabble))
// Output: xubem-dydek-kysom-puhev-nyroz-byduk-guzex
```

### Save Keys to Files

```swift
// Generate and save keys to files (similar to ssh-keygen)
try KeyFileManager.generateKeyPairFiles(
    type: .ed25519,
    privatePath: "~/.ssh/id_ed25519",
    publicPath: "~/.ssh/id_ed25519.pub",
    comment: "user@example.com"
)
```

### Generate Different Key Types

```swift
// RSA key (3072 bits by default)
let rsaKey = try SwiftKeyGen.generateKeyPair(type: .rsa)

// RSA with standard sizes (hardware accelerated)
let rsa2048 = try SwiftKeyGen.generateKeyPair(type: .rsa, bits: 2048)
let rsa4096 = try SwiftKeyGen.generateKeyPair(type: .rsa, bits: 4096)

// RSA with arbitrary sizes (1024-16384 bits)
let rsa1536 = try SwiftKeyGen.generateKeyPair(type: .rsa, bits: 1536)
let rsa8192 = try SwiftKeyGen.generateKeyPair(type: .rsa, bits: 8192)

// ECDSA keys
let p256Key = try SwiftKeyGen.generateKeyPair(type: .ecdsa256)
let p384Key = try SwiftKeyGen.generateKeyPair(type: .ecdsa384)
let p521Key = try SwiftKeyGen.generateKeyPair(type: .ecdsa521)
```

### Parse and Validate Keys

```swift
// Parse a public key string
let publicKeyString = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"
let (keyType, keyData, comment) = try KeyParser.parsePublicKey(publicKeyString)

// Calculate fingerprint from public key string
let fingerprint = try KeyParser.fingerprint(from: publicKeyString)

// Detect key type
let detectedType = KeyParser.detectKeyType(from: publicKeyString)
```

### Custom Fingerprint Formats

```swift
let keyPair = try SwiftKeyGen.generateKeyPair(type: .ed25519)

// SHA256 (default, OpenSSH 6.8+)
let sha256 = keyPair.fingerprint(hash: .sha256)
// Output: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

// SHA512
let sha512 = keyPair.fingerprint(hash: .sha512)
// Output: SHA512:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

// MD5 (legacy, OpenSSH < 6.8)
let md5 = keyPair.fingerprint(hash: .md5)
// Output: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
```

### Reading and Managing Existing Keys

```swift
// Read a private key
let key = try KeyManager.readPrivateKey(
    from: "~/.ssh/id_ed25519",
    passphrase: "my-passphrase" // optional
)

// Get key info without decryption
let info = try KeyManager.getKeyInfo(keyPath: "~/.ssh/id_ed25519")
print("Key type: \(info.keyType)")
print("Encrypted: \(info.isEncrypted)")
print("Fingerprint: \(info.fingerprint)")

// Verify a passphrase
let isValid = KeyManager.verifyPassphrase(
    keyPath: "~/.ssh/id_ed25519",
    passphrase: "test-pass"
)
```

## Key Types and Recommendations

### Ed25519 (Recommended)
- Best security/performance ratio
- Fixed 256-bit keys
- Small public keys
- Fast signature generation/verification

### RSA
- Wide compatibility
- Supported sizes: Any size from 1024 to 16384 bits (must be multiple of 8)
- Default: 3072 bits (following OpenSSH 9.0+)
- Uses hardware-accelerated CryptoExtras for standard sizes (2048, 3072, 4096)
- Arbitrary key sizes use pure Swift implementation

### ECDSA
- Good performance
- Three NIST curves: P-256, P-384, P-521
- Smaller keys than RSA

## Security Considerations

- Private keys are written with `0600` permissions (owner read/write only)
- Public keys are written with `0644` permissions (owner write, all read)
- Uses secure random number generation from Swift Crypto
- Memory is properly managed by Swift's ARC

## Platform Support

- macOS 13.0+
- iOS 16.0+
- tvOS 16.0+
- watchOS 9.0+
- visionOS 1.0+
- Linux (with Swift 6.1+)

### Passphrase Protection

```swift
// Generate key with passphrase
try KeyFileManager.generateKeyPairFiles(
    type: .ed25519,
    privatePath: "~/.ssh/id_ed25519",
    comment: "user@example.com",
    passphrase: "my-secure-passphrase"
)

// Change passphrase on existing key
try KeyManager.changePassphrase(
    keyPath: "~/.ssh/id_ed25519",
    oldPassphrase: "old-pass",
    newPassphrase: "new-pass"
)

// Remove passphrase
try KeyManager.removePassphrase(
    keyPath: "~/.ssh/id_ed25519",
    currentPassphrase: "current-pass"
)

// Update key comment
try KeyManager.updateComment(
    keyPath: "~/.ssh/id_ed25519",
    passphrase: "pass", // optional if key is encrypted
    newComment: "new-comment@example.com"
)
```

### Key Format Conversion

```swift
let key = try SwiftKeyGen.generateKey(type: .ed25519)

// Convert to PEM format
let pem = try KeyConverter.toPEM(key: key)

// Convert to RFC4716 format (SSH2 public key)
let rfc4716 = try KeyConverter.toRFC4716(key: key)

// Export in multiple formats
let paths = try KeyConverter.exportKey(
    key,
    formats: [.openssh, .pem, .pkcs8, .rfc4716],
    basePath: "~/.ssh/mykey"
)
```

#### Import/Export with stdin/stdout

```swift
// Read key from stdin
let keyData = try KeyFileManager.readFromStdin()

// Write key to stdout
try KeyFileManager.writeStringToStdout(key.publicKeyString())

// Use "-" as filename for stdin/stdout
try KeyFileManager.writeKey(keyPair, to: "-", type: .publicKey)
```

#### RFC4716 Format Support

```swift
// Parse RFC4716 format public key
let rfc4716String = """
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "user@example.com"
AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
---- END SSH2 PUBLIC KEY ----
"""

let parsed = try KeyParser.parseRFC4716(rfc4716String)
print("Key type: \(parsed.type)")
print("Comment: \(parsed.comment ?? "none")")

// Convert between formats
let options = KeyConversionManager.ConversionOptions(
    toFormat: .rfc4716,
    fromFormat: .openssh,
    input: "~/.ssh/id_ed25519.pub",
    output: "~/.ssh/id_ed25519.rfc"
)
try KeyConversionManager.convertKey(options: options)
```

#### PEM/PKCS8 Import Support

```swift
// Parse RSA public key from PEM format
let rsaPublicPEM = """
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxG6eSjsaTT+PPHobLU5fanucnQ4fKjtMXWadqZGjKnKz1o1hFSb6
QpXW5vVphJ/bCZ2dcSflWnvCpmEQbRhJZBV+hG8n9CL2d6TqJmzR8fK3U2Sk4SJy
...
-----END RSA PUBLIC KEY-----
"""

let rsaPublicKey = try PEMParser.parseRSAPublicKey(rsaPublicPEM)
print(rsaPublicKey.publicKeyString()) // OpenSSH format

// Parse RSA private key from PEM format - SUPPORTED!
let rsaPrivatePEM = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZf
...
-----END RSA PRIVATE KEY-----
"""

let rsaPrivateKey = try PEMParser.parseRSAPrivateKey(rsaPrivatePEM)
print(rsaPrivateKey.publicKeyString()) // Extract public key

// Parse ECDSA private key from PEM format - SUPPORTED!
let ecdsaPrivatePEM = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGLlamZU9Z83D3g8VsmdqKhu5u47L4RjSXNe3zxQNXPoAoGCCqGSM49
...
-----END EC PRIVATE KEY-----
"""

let ecdsaPrivateKey = try PEMParser.parseECDSAPrivateKey(ecdsaPrivatePEM)
print(ecdsaPrivateKey.publicKeyString()) // Extract public key

// Note: Ed25519 private key PEM parsing is NOT supported by Swift Crypto
// Use OpenSSH format for Ed25519 keys instead:
let ed25519OpenSSH = try OpenSSHPrivateKey.parse(from: ed25519OpenSSHData)

// Parse ECDSA public key from PKCS8 format
let ecdsaPKCS8 = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW3MgvL1V6nh5Fc3YlVJdQi4XQVQZ
Y8VlhTwnDlJZw1D6XB5bEoqFmL0y6kLPFPWNNXaR8HHM86Y7A1A1vBHZ2g==
-----END PUBLIC KEY-----
"""

let ecdsaPublicKey = try PEMParser.parseECDSAPublicKey(ecdsaPKCS8)
print(ecdsaPublicKey.publicKeyString()) // OpenSSH format

// Parse Ed25519 public key from PKCS8 format
let ed25519PKCS8 = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4L7SfV2U=
-----END PUBLIC KEY-----
"""

let ed25519Key = try PEMParser.parseEd25519PublicKey(ed25519PKCS8)
print(ed25519Key.publicKeyString()) // OpenSSH format

// Automatic format detection and conversion
let detected = try KeyConversionManager.detectFormat(from: pemString)
print("Detected format: \(detected)")
```

### Randomart Visualization

```swift
let key = try SwiftKeyGen.generateKey(type: .ed25519)
let art = RandomArt.generate(for: key)
print(art)
// Output:
// +---[ED25519 256]---+
// |          ...o   |
// |       .   .. .  |
// |      = + .  * o |
// |   . = B + .. E  |
// |    + o S o .    |
// |       o o .     |
// |        .        |
// |                 |
// |                 |
// +-------------------+
```

### Known Hosts Management

```swift
let knownHosts = KnownHostsManager()

// Add a host
try knownHosts.addHost(hostname: "example.com", key: hostKey)

// Verify a host key
let result = try knownHosts.verifyHost("example.com", key: presentedKey)
switch result {
case .valid:
    print("Host key verified")
case .mismatch:
    print("WARNING: Host key has changed!")
case .unknown:
    print("Unknown host")
}

// Hash all hostnames for privacy
try knownHosts.hashHostnames()
```

### Batch Key Generation

```swift
// Generate keys for multiple hosts
let hosts = ["server1", "server2", "server3"]
let results = try await BatchKeyGenerator.generateForHosts(
    hosts: hosts,
    keyType: .ed25519,
    outputDirectory: "~/.ssh/keys/"
)

// Generate all key types for one identity
let allTypes = try await BatchKeyGenerator.generateAllTypes(
    identity: "user@example.com",
    outputDirectory: "~/.ssh/"
)
```

### SSH Certificate Operations

#### Create Certificate Authority (CA)

```swift
// Generate a CA key pair (supports Ed25519, RSA, and ECDSA)
let caKey = try SwiftKeyGen.generateKeyPair(
    type: .ed25519,  // or .rsa, .ecdsa256, .ecdsa384, .ecdsa521
    comment: "organization-ca@example.com"
)

// Save CA keys
try KeyFileManager.generateKeyPairFiles(
    type: .ed25519,
    privatePath: "~/.ssh/ca_key",
    publicPath: "~/.ssh/ca_key.pub",
    comment: "organization-ca@example.com"
)
```

#### Sign User Certificates

```swift
// Load CA key
let caKey = try KeyManager.readPrivateKey(
    from: "~/.ssh/ca_key",
    passphrase: "ca-passphrase"
)

// Generate or load user key
let userKey = try SwiftKeyGen.generateKey(type: .ed25519)

// Sign user certificate
let userCert = try CertificateAuthority.signCertificate(
    publicKey: userKey,
    caKey: caKey,
    keyId: "john.doe",
    principals: ["john", "jdoe"],
    validFrom: Date(),
    validTo: Date().addingTimeInterval(30 * 24 * 60 * 60), // 30 days
    certificateType: .user,
    extensions: [
        .permitX11Forwarding,
        .permitAgentForwarding,
        .permitPortForwarding,
        .permitPty,
        .permitUserRc
    ]
)

// Save certificate
try CertificateManager.saveCertificate(
    userCert,
    to: "~/.ssh/id_ed25519-cert.pub",
    comment: "john.doe@example.com"
)
```

#### Sign Host Certificates

```swift
// Sign host certificate with wildcards
let hostCert = try CertificateAuthority.signCertificate(
    publicKey: hostKey,
    caKey: caKey,
    keyId: "web-server-01",
    principals: ["web.example.com", "*.example.com"],
    serial: 1001,
    validFrom: Date(),
    validTo: Date().addingTimeInterval(365 * 24 * 60 * 60), // 1 year
    certificateType: .host
)
```

#### Add Certificate Restrictions

```swift
// Create restricted user certificate
let restrictedCert = try CertificateManager.createUserCertificate(
    publicKey: userKey,
    caKey: caKey,
    username: "contractor",
    validityDays: 7,
    forceCommand: "/usr/bin/git-shell",
    sourceAddress: "203.0.113.0/24"
)
```

#### Verify Certificates

```swift
// Read and verify a certificate
let cert = try CertificateManager.readCertificate(
    from: "~/.ssh/id_ed25519-cert.pub"
)

// Verify certificate validity (supports RSA, ECDSA, and Ed25519 CA signatures)
let result = CertificateVerifier.verifyCertificate(
    cert,
    caKey: caKey,  // Can be any key type: Ed25519, RSA, or ECDSA
    options: CertificateVerificationOptions()
)

switch result {
case .valid:
    print("Certificate is valid")
case .expired:
    print("Certificate has expired")
case .invalidSignature:
    print("Certificate signature is invalid")
case .invalidPrincipal:
    print("Principal not authorized")
default:
    print("Certificate verification failed")
}

// Verify for specific host
let hostResult = CertificateManager.verifyCertificateForHost(
    cert,
    hostname: "web.example.com",
    caKey: caKey
)

// Verify for specific user
let userResult = CertificateManager.verifyCertificateForUser(
    cert,
    username: "john",
    caKey: caKey
)
```

#### Display Certificate Information

```swift
// Parse and display certificate info
let certInfo = try CertificateManager.parseCertificateString(
    "ssh-ed25519-cert-v01@openssh.com AAAAA..."
)
print(certInfo)
// Output:
// Type: ssh-ed25519-cert-v01@openssh.com user certificate
// Key ID: "john.doe"
// Serial: 12345
// Valid: from 2024-01-01T00:00:00 to 2024-01-31T23:59:59
// Principals:
//     john
//     jdoe
// Critical Options:
//     (none)
// Extensions:
//     permit-X11-forwarding
//     permit-agent-forwarding
//     permit-port-forwarding
//     permit-pty
//     permit-user-rc
// Signing CA: ssh-ed25519 SHA256:...
```

#### Batch Certificate Generation

```swift
// Generate certificates for multiple hosts
let hosts = ["web01", "web02", "db01"]
let results = try CertificateManager.generateCertificatesForHosts(
    hosts: hosts,
    caKeyPath: "~/.ssh/host_ca_key",
    keyType: .ed25519,
    outputDirectory: "/etc/ssh/",
    validityDays: 365
)

for (host, certPath) in results {
    print("Generated certificate for \(host): \(certPath)")
}

```

#### Signature Verification

SwiftKeyGen supports full signature verification for all key types:

```swift
// RSA signature verification (supports multiple algorithms)
let rsaKey = try RSAKeyGenerator.generate(bits: 2048)
let signature = try rsaKey.sign(data: messageData)

// Verify with different RSA signature algorithms
let isValid = try rsaKey.verify(signature: signature, for: messageData)
// Supports: ssh-rsa (SHA1), rsa-sha2-256, rsa-sha2-512

// ECDSA signature verification
let ecdsaKey = try ECDSAKeyGenerator.generateP256()
let ecdsaSignature = try ecdsaKey.sign(data: messageData)
let ecdsaValid = try ecdsaKey.verify(signature: ecdsaSignature, for: messageData)
// Supports: P-256 (SHA256), P-384 (SHA384), P-521 (SHA512)

// Public-key-only verification (for certificates)
let publicKey = rsaKey.publicOnlyKey()
let canVerify = try publicKey.verify(signature: signature, for: messageData)
```

## Roadmap

- [x] SSH certificate generation and signing
- [x] Full signature verification (RSA, ECDSA, Ed25519)
- [ ] DSA key support (legacy)
- [ ] KRL (Key Revocation List) support
- [ ] FIDO/U2F security key support
- [ ] Moduli generation for DH groups
- [ ] SSH agent integration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.