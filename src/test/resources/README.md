# Test Keys for JWT Helper

This directory contains RSA key pairs in P8 (PKCS#8) format for testing the JWTHelper class.

## Generated Keys

### P8 Format Keys (PKCS#8)

#### Encrypted Private Key (with passphrase)
- **File**: `test_private_key_encrypted.p8`
- **Passphrase**: `testPassphrase123`
- **Format**: PKCS#8 format with AES-256 encryption
- **Key Size**: 2048 bits
- **Usage**: For testing .p8 encrypted key loading with passphrase

#### Unencrypted Private Key
- **File**: `test_private_key_unencrypted.p8`
- **Format**: PKCS#8 format without encryption
- **Key Size**: 2048 bits
- **Usage**: For testing .p8 unencrypted key loading

#### Public Keys
- **test_public_key.p8** - Public key for encrypted .p8 private key
- **test_public_key_unencrypted.p8** - Public key for unencrypted .p8 private key

## Generating Keys with OpenSSL

### P8 Format (PKCS#8)

```bash
# Generate encrypted .p8 private key (PKCS#8)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -aes256 -out test_private_key_encrypted.p8 -pass pass:testPassphrase123

# Extract public key from .p8
openssl pkey -in test_private_key_encrypted.p8 -pubout -out test_public_key.p8 \
  -passin pass:testPassphrase123

# Generate unencrypted .p8 private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out test_private_key_unencrypted.p8

# Extract public key
openssl pkey -in test_private_key_unencrypted.p8 -pubout -out test_public_key_unencrypted.p8
```

## Environment Variables for Testing

When running tests, set the following environment variables:

```bash
# P8 format keys
export TEST_PRIVATE_KEY_P8_PATH="src/test/resources/test_private_key_encrypted.p8"
export TEST_PRIVATE_KEY_P8_PASSPHRASE="testPassphrase123"
export TEST_PRIVATE_KEY_P8_PATH_UNENCRYPTED="src/test/resources/test_private_key_unencrypted.p8"
export TEST_PRIVATE_KEY_P8_PASSPHRASE_UNENCRYPTED=""
```

## About P8/PKCS#8 Format

**PKCS#8** is the modern standard format for private keys that:
- Supports multiple encryption algorithms (AES-256, AES-128, etc.)
- Is more flexible and secure than older formats like PKCS#1
- Uses text-based PEM encoding with `-----BEGIN ENCRYPTED PRIVATE KEY-----` or `-----BEGIN PRIVATE KEY-----` headers
- Is widely supported by modern cryptographic libraries and tools

The `.p8` file extension specifically indicates PKCS#8 format and is commonly used for:
- Apple APNs (Apple Push Notification service) keys
- JWT token signing keys
- OAuth and API authentication keys

## Security Note

⚠️ **WARNING**: These keys are for testing purposes only. Never use test keys in production environments!

## File Paths (Absolute)

The absolute paths for the test keys in this project are:
- Encrypted Private Key: `<project-root>/src/test/resources/test_private_key_encrypted.p8`
- Unencrypted Private Key: `<project-root>/src/test/resources/test_private_key_unencrypted.p8`
- Public Key (encrypted): `<project-root>/src/test/resources/test_public_key.p8`
- Public Key (unencrypted): `<project-root>/src/test/resources/test_public_key_unencrypted.p8`
