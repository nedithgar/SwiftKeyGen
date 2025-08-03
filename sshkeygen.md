# ssh-keygen Features

## Key Generation
- Generate RSA keys (default 3072 bits)
- Generate DSA keys (legacy, 1024 bits)
- Generate ECDSA keys (256, 384, or 521 bits)
- Generate Ed25519 keys (recommended, fixed size)
- Specify custom bit sizes for RSA keys
- Generate multiple keys in batch mode
- Set custom filenames and paths for keys
- Add comments to keys during generation

## Key Management
- Change or remove passphrases on existing keys
- Add passphrases to unprotected keys
- Update key comments
- Show key fingerprints in multiple formats (MD5, SHA256)
- Display key fingerprints as randomart images
- Test private key passphrases
- Print public key from private key

## Key Conversion
- Convert between OpenSSH and PEM/PKCS8 formats
- Import keys from other SSH implementations
- Export keys to other formats
- Convert SSH1 keys to SSH2 format
- Read keys from standard input
- Output keys to standard output

## Certificate Operations
- Sign user certificates with CA keys
- Sign host certificates with CA keys
- Create certificate authority (CA) keys
- Specify certificate validity periods
- Add principals to certificates
- Add critical options to certificates
- Add extensions to certificates
- Verify certificate signatures
- Show certificate details
- Revoke certificates (KRL generation)

## Host Key Management
- Generate host keys for SSH servers
- Verify host key fingerprints
- Update known_hosts files
- Remove host keys from known_hosts
- Hash hostnames in known_hosts
- Find duplicate hosts in known_hosts
- Check host keys against known_hosts
- Batch update multiple known_hosts entries

## Security Features
- Use hardware security tokens (PKCS#11)
- Generate FIDO/U2F security keys
- Specify resident keys for FIDO devices
- Set PIN requirements for security keys
- Use custom KDF rounds for key encryption
- Specify cipher algorithms for key encryption
- Generate keys with specific security requirements

## Advanced Options
- Moduli generation and testing for DH groups
- Screen DH group exchange moduli
- Generate keys deterministically from seed
- Memory locking to prevent key swapping
- Batch mode operation without user interaction
- Quiet mode for scripting
- Verbose output for debugging

## Key Inspection
- Show key length and type
- Display key creation time
- Check key file permissions
- Validate key file formats
- Compare key fingerprints
- Extract public key components

## Format Support
- OpenSSH private key format (default)
- OpenSSH public key format
- PEM format (PKCS#1)
- PKCS#8 format
- RFC4716 format
- SSH1 format (legacy)

## Special Operations
- Generate keys for SSH certificate authentication
- Create keys compatible with specific SSH versions
- Generate keys with custom rounds for KDF
- Specify OpenSSH version compatibility
- Use custom random seed files
- Override default key locations

## Output Options
- Fingerprint output in hex or base64
- Bubble babble format for fingerprints
- Visual randomart representation
- Machine-readable output formats
- Custom output file specifications
- Control output verbosity levels

## Compatibility Features
- SSH1 protocol support (deprecated)
- Legacy key type support
- Backward compatibility options
- Cross-platform key generation
- Support for various SSH implementations

## Batch Operations
- Process multiple keys from file lists
- Bulk fingerprint generation
- Mass known_hosts updates
- Automated certificate signing
- Scripted key management

## Debugging and Testing
- Verbose mode for troubleshooting
- Debug mode for detailed output
- Key validation and testing
- Performance benchmarking options
- Memory usage optimization

## Integration Features
- SSH agent integration
- PKCS#11 token support
- Hardware security module support
- Key management system integration
- Certificate authority integration