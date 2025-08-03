# SwiftKeyGen Verification Findings

This document contains detailed findings from comparing SwiftKeyGen with the official ssh-keygen implementation from OpenSSH Portable.

## Key Generation Implementation Verification

### Supported Key Types

**ssh-keygen supports:**
- Ed25519 (default since it uses `DEFAULT_KEY_TYPE_NAME = "ed25519"`)
- RSA (default 3072 bits, minimum SSH_RSA_MINIMUM_MODULUS_SIZE)
- ECDSA (default 256 bits, supports 256, 384, 521 curves)
- DSA (legacy, marked for removal)
- XMSS (quantum-resistant, requires WITH_XMSS compilation flag)
- ECDSA-SK (FIDO/U2F security key variant)
- Ed25519-SK (FIDO/U2F security key variant)

**SwiftKeyGen claims to support:**
- ✅ Ed25519 
- ✅ RSA (2048, 3072, 4096 bits)
- ✅ ECDSA (256, 384, 521 bits)
- ❌ DSA (not implemented - correctly noted as legacy)
- ❌ XMSS (not implemented)
- ❌ ECDSA-SK (FIDO/U2F not implemented)
- ❌ Ed25519-SK (FIDO/U2F not implemented)

### Key Generation Details

1. **Default Key Type**: ssh-keygen defaults to Ed25519, which matches SwiftKeyGen's recommendation.

2. **RSA Defaults**: ssh-keygen uses 3072 bits as default (DEFAULT_BITS = 3072), while SwiftKeyGen lists 2048, 3072, 4096 as options.

3. **ECDSA Defaults**: Both use 256 bits as default for ECDSA (DEFAULT_BITS_ECDSA = 256).

## Key Conversion Features

### Format Support in ssh-keygen

The `convert_format` enum in ssh-keygen shows:
- FMT_RFC4716 (default)
- FMT_PKCS8
- FMT_PEM

**Conversion functions found:**
- `do_convert_to_ssh2()` - Converts to RFC4716 format
- `do_convert_to_pkcs8()` - Converts to PKCS#8
- `do_convert_to_pem()` - Converts to PEM
- `do_convert_from_ssh2()` - Reads RFC4716 format
- `do_convert_from_pkcs8()` - Reads PKCS#8
- `do_convert_from_pem()` - Reads PEM

**RFC4716 Format Details:**
- Uses header `---- BEGIN SSH2 PUBLIC KEY ----` and footer `---- END SSH2 PUBLIC KEY ----`
- Includes comment line with format: `Comment: "XXX-bit TYPE, converted by USER@HOST from OpenSSH"`
- Comment must fit in 72 chars (RFC 4716 sec 3.3)
- Handles line continuations with backslash
- Supports both public and private key variants (SSH_COM_PRIVATE_BEGIN)

**SwiftKeyGen claims:**
- ✅ RFC4716 format import/export
- ✅ PEM format import for RSA
- ✅ PKCS#8 format import
- ✅ stdin/stdout support (using "-" as filename)

## Certificate Operations

### Certificate Features in ssh-keygen

**Certificate types:**
- SSH2_CERT_TYPE_USER (default)
- SSH2_CERT_TYPE_HOST (via -h flag)

**Certificate fields:**
- cert_key_type (user or host)
- cert_principals (comma-separated list)
- cert_valid_from / cert_valid_to (validity period)
- Certificate options flags (CERTOPT_X_FWD, CERTOPT_AGENT_FWD, etc.)
- Custom extensions support via cert_ext structure

**Critical Options (from `finalise_cert_exts()`):**
- `force-command` - Forces a specific command
- `source-address` - Restricts source addresses
- `verify-required` - Requires additional verification

**Extensions (non-critical):**
- `permit-X11-forwarding`
- `permit-agent-forwarding`
- `permit-port-forwarding`
- `permit-pty`
- `permit-user-rc`
- `no-touch-required` (for FIDO keys)

**Certificate Signing:**
- Uses `sshkey_certify()` or `sshkey_certify_custom()` for agent signing
- Supports RSA with different signature algorithms (rsa-sha2-256, rsa-sha2-512)
- Certificate format includes: `-cert.pub` suffix for output files

**SwiftKeyGen claims:**
- ✅ Sign user certificates
- ✅ Sign host certificates
- ✅ Create CA keys
- ✅ Specify validity periods
- ✅ Add principals
- ✅ Add critical options
- ✅ Add extensions
- ✅ RSA signature verification (ssh-rsa, rsa-sha2-256, rsa-sha2-512)
- ✅ ECDSA signature verification

## Security Features

### FIDO/U2F Support
- ssh-keygen has extensive FIDO/U2F support via `sk_provider`
- Supports ECDSA-SK and Ed25519-SK key types
- SwiftKeyGen does NOT implement FIDO/U2F support

### KRL (Key Revocation Lists)
- ssh-keygen has full KRL support via krl.h
- Functions: `load_krl()`, `update_krl_from_file()`, `ssh_krl_revoke_cert_by_serial_range()`
- SwiftKeyGen does NOT implement KRL support

## Key Management Features

### Passphrase Handling
- ssh-keygen uses `identity_passphrase` and `identity_new_passphrase`
- Uses `read_passphrase()` with prompt for interactive input
- SwiftKeyGen claims passphrase support ✅

### Fingerprint Support
- ssh-keygen supports multiple hash algorithms (MD5, SHA256, SHA512)
- Supports bubble babble format (`print_bubblebabble`) using SHA1
- Default hash is SSH_FP_HASH_DEFAULT (which is SSH_DIGEST_SHA256)
- Randomart visualization support (SSH_FP_RANDOMART)
- Functions: `sshkey_fingerprint()`, `fingerprint_one_key()`, `fingerprint_private()`
- SwiftKeyGen claims support for MD5, SHA256, SHA512 and randomart ✅
- SwiftKeyGen does NOT support bubble babble format ❌

## Known Hosts Management

ssh-keygen implements:
- Hash hostnames (`hash_hosts`) using `host_hash()` function
- Find specific hosts (`find_host`)
- Delete hosts (`delete_host`)
- Uses `hostkeys_foreach()` for iteration
- Hash format uses HMAC-SHA1 with salt, prefixed with `|1|` (HASH_MAGIC)
- HASH_DELIM character is '|'
- Preserves CA and revocation markers (MRK_NONE check)
- Handles comma-separated hostnames
- Lowercase conversion before hashing
- Wildcard hosts are not hashed

SwiftKeyGen claims:
- ✅ Update known_hosts
- ✅ Remove host keys
- ✅ Hash hostnames
- ✅ Find hosts
- ✅ Check host keys

## Summary of Discrepancies

### Features SwiftKeyGen Claims But May Need Verification:
1. Full RFC4716 conversion compatibility
2. Complete certificate verification for all signature algorithms
3. Known hosts hashing algorithm compatibility

### Features ssh-keygen Has That SwiftKeyGen Lacks:
1. FIDO/U2F security key support (ECDSA-SK, Ed25519-SK)
2. KRL (Key Revocation List) support
3. XMSS quantum-resistant keys
4. DSA keys (legacy, acceptable to not implement)
5. Bubble babble fingerprint format
6. Hardware security module support (PKCS#11)
7. Moduli generation for DH groups

### Implementation Differences:
1. Default RSA key size (ssh-keygen: 3072, SwiftKeyGen: offers 2048/3072/4096)
2. KDF implementation (SwiftKeyGen uses PBKDF2 vs OpenSSH's bcrypt_pbkdf)

## Detailed Implementation Analysis

### Private Key Format Compatibility
- OpenSSH uses bcrypt_pbkdf for key derivation (requires bcrypt_pbkdf.c)
- SwiftKeyGen's PBKDF2 implementation may not be compatible with OpenSSH encrypted keys
- This could affect importing encrypted private keys from ssh-keygen

### Certificate Implementation Accuracy
SwiftKeyGen needs to ensure:
1. Certificate serial numbers are properly generated
2. Certificate validity timestamps match OpenSSH format
3. Critical options are encoded correctly in the certificate blob
4. Extensions are sorted lexically by key (as done by qsort in ssh-keygen)
5. Signature algorithms match exactly (especially for RSA: ssh-rsa vs rsa-sha2-*)

### Known Hosts Hashing Algorithm
ssh-keygen uses:
- HMAC-SHA1 for hostname hashing
- Base64 encoding of the hash
- Format: `|1|<salt>|<hash>`
- SwiftKeyGen must implement the exact same algorithm for compatibility

### RFC4716 Format Compliance
SwiftKeyGen should ensure:
1. Comment line follows the exact format and length restrictions
2. Line wrapping at 72 characters is properly handled
3. Backslash line continuations are processed correctly
4. Both public and private key variants are supported

## Recommendations for SwiftKeyGen

1. **Critical**: Verify bcrypt_pbkdf compatibility or document the limitation
2. **Important**: Add bubble babble fingerprint format for full compatibility
3. **Important**: Implement proper HMAC-SHA1 hashing for known_hosts
4. **Nice to have**: Add support for XMSS keys (quantum-resistant)
5. **Future**: Consider FIDO/U2F support as it becomes more prevalent

## Testing Recommendations

To verify full compatibility, SwiftKeyGen should:
1. Generate keys with ssh-keygen and import them into SwiftKeyGen
2. Generate keys with SwiftKeyGen and use them with OpenSSH
3. Cross-verify certificate signatures between implementations
4. Test known_hosts hashing produces identical results
5. Verify RFC4716 format files are interchangeable