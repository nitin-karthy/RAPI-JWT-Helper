# JWT Helper for ReadyAPI

A lightweight Java library for generating JWT tokens signed with RSA private keys, specifically designed for use in SmartBear ReadyAPI Groovy scripts.

[![Build and Release JWT Helper](https://github.com/YOUR_USERNAME/JWT-Maker/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_USERNAME/JWT-Maker/actions/workflows/build.yml)

## Features

- ✅ **JWT Token Generation** - Create JWT tokens signed with RS256 (RSA with SHA-256) algorithm
- ✅ **P8/PKCS#8 Key Support** - Works with both encrypted and unencrypted private keys in P8 format
- ✅ **Public Key Fingerprinting** - Generate SHA-256 fingerprints of public keys for verification
- ✅ **Uber JAR** - All dependencies bundled, ready to use in ReadyAPI
- ✅ **Zero Configuration** - No external dependencies or setup required in ReadyAPI
- ✅ **Production Ready** - Comprehensive test coverage and validation

## Quick Start

### 1. Download the JAR

Download the latest `jwt-helper-uber-jar` from the [GitHub Releases](https://github.com/YOUR_USERNAME/JWT-Maker/releases) page or from the [Actions artifacts](https://github.com/YOUR_USERNAME/JWT-Maker/actions).

### 2. Add to ReadyAPI

Copy the JAR file to your ReadyAPI `ext` directory:
- **Windows**: `C:\Program Files\SmartBear\ReadyAPI-X.X.X\bin\ext\`
- **macOS**: `/Applications/ReadyAPI-X.X.X.app/Contents/java/app/bin/ext/`
- **Linux**: `/opt/ReadyAPI-X.X.X/bin/ext/`

Restart ReadyAPI after adding the JAR.

### 3. Use in Groovy Scripts

```groovy
// Define your JWT claims
def claims = [
    sub: "user@example.com",
    name: "John Doe",
    role: "admin",
    iat: System.currentTimeMillis() / 1000,
    exp: System.currentTimeMillis() / 1000 + 3600  // 1 hour expiry
]

// Generate JWT token
def privateKeyPath = "/path/to/your/private_key.p8"
def passphrase = "yourSecretPassphrase"

def jwt = com.smartbear.JWTHelper.make(claims, privateKeyPath, passphrase)

log.info "Generated JWT: ${jwt}"

// Use the JWT in your test
testRunner.testCase.setPropertyValue("authToken", jwt)
```

## API Reference

### `JWTHelper.make()`

Generates a JWT token signed with the provided private key.

**Signature:**
```java
public static String make(
    Map<String, Object> jwtFormat,
    String privateKeyPath,
    String privateKeyPassphrase
)
```

**Parameters:**
- `jwtFormat` - A map of key-value pairs representing JWT claims
- `privateKeyPath` - Full path to the private key file (.p8 format)
- `privateKeyPassphrase` - Passphrase for encrypted keys (use empty string `""` for unencrypted keys)

**Returns:** JWT token as a String

**Example:**
```groovy
def claims = [
    iss: "my-app",
    sub: "user123",
    aud: "api.example.com",
    exp: System.currentTimeMillis() / 1000 + 3600
]

def jwt = com.smartbear.JWTHelper.make(
    claims,
    "/home/user/keys/private_key.p8",
    "myPassphrase123"
)
```

### `JWTHelper.generateFingerprint()`

Generates a SHA-256 fingerprint of a public key for verification purposes.

**Signature:**
```java
public static String generateFingerprint(String publicKeyPath)
```

**Parameters:**
- `publicKeyPath` - Full path to the public key file (.p8 format)

**Returns:** Fingerprint in the format `SHA256:hexstring`

**Example:**
```groovy
def fingerprint = com.smartbear.JWTHelper.generateFingerprint(
    "/home/user/keys/public_key.p8"
)

log.info "Public Key Fingerprint: ${fingerprint}"
// Output: SHA256:8cc989e66cdf9becf168d3e2a9dd66d5d8222cfbe24fdce29959b30c340125a6
```

## ReadyAPI Integration Examples

### Example 1: Bearer Token Authentication

```groovy
// Generate JWT for Bearer token authentication
def claims = [
    sub: context.expand('${#Project#username}'),
    iss: "readyapi-test",
    exp: System.currentTimeMillis() / 1000 + 1800  // 30 minutes
]

def jwt = com.smartbear.JWTHelper.make(
    claims,
    context.expand('${#Project#privateKeyPath}'),
    context.expand('${#Project#privateKeyPassphrase}')
)

// Set as Authorization header for subsequent requests
testRunner.testCase.setPropertyValue("BearerToken", "Bearer ${jwt}")
```

### Example 2: API Key Registration with Fingerprint

```groovy
// Generate fingerprint for API key registration
def publicKeyPath = "/path/to/public_key.p8"
def fingerprint = com.smartbear.JWTHelper.generateFingerprint(publicKeyPath)

// Use fingerprint in API registration request
def registrationPayload = [
    username: "test-user",
    public_key_fingerprint: fingerprint
]

// Convert to JSON and use in request
import groovy.json.JsonBuilder
def json = new JsonBuilder(registrationPayload).toString()
testRunner.testCase.setPropertyValue("registrationPayload", json)
```

### Example 3: OAuth 2.0 JWT Bearer Flow

```groovy
// Generate JWT for OAuth 2.0 JWT Bearer Grant
def now = System.currentTimeMillis() / 1000
def claims = [
    iss: "client-id-12345",
    sub: "user@example.com",
    aud: "https://oauth.example.com/token",
    iat: now,
    exp: now + 300,  // 5 minutes
    scope: "read write"
]

def jwt = com.smartbear.JWTHelper.make(
    claims,
    "/path/to/oauth_private_key.p8",
    "oauthKeyPassword"
)

// Use in OAuth token request
testRunner.testCase.setPropertyValue("client_assertion", jwt)
testRunner.testCase.setPropertyValue("client_assertion_type", 
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
```

### Example 4: Dynamic Claims from Test Data

```groovy
// Build claims dynamically from test data source
def testData = testRunner.testCase.getTestStepByName("DataSource")
def row = testData.currentRow

def claims = [
    sub: row.userId,
    email: row.email,
    role: row.role,
    department: row.department,
    exp: System.currentTimeMillis() / 1000 + 7200  // 2 hours
]

def jwt = com.smartbear.JWTHelper.make(
    claims,
    context.expand('${#Project#privateKeyPath}'),
    context.expand('${#Project#privateKeyPassphrase}')
)

testRunner.testCase.setPropertyValue("userToken", jwt)
```

## Generating Keys for Testing

### Using OpenSSL (Linux/macOS/Git Bash on Windows)

**Generate encrypted private key:**
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -aes256 -out private_key.p8 -pass pass:YourPassphrase123
```

**Extract public key:**
```bash
openssl pkey -in private_key.p8 -pubout -out public_key.p8 \
  -passin pass:YourPassphrase123
```

**Generate unencrypted private key:**
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out private_key_unencrypted.p8
```

**Extract public key from unencrypted private key:**
```bash
openssl pkey -in private_key_unencrypted.p8 -pubout -out public_key.p8
```

## Project Structure

```
JWT-Maker/
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/smartbear/
│   │           └── JWTHelper.java          # Main helper class
│   └── test/
│       ├── java/
│       │   └── com/smartbear/
│       │       └── JWTHelperTest.java      # JUnit tests
│       └── resources/
│           ├── test_private_key_encrypted.p8
│           ├── test_private_key_unencrypted.p8
│           ├── test_public_key.p8
│           └── test_public_key_unencrypted.p8
├── .github/
│   └── workflows/
│       └── build.yml                        # CI/CD pipeline
├── pom.xml                                  # Maven configuration
└── README.md                                # This file
```

## Dependencies

This library uses the following open-source dependencies (all bundled in the uber JAR):

- **JJWT v0.13.0** - JWT creation and signing
- **Bouncy Castle v1.78.1** - Cryptographic operations and key handling
- **Commons IO v2.20.0** - File I/O utilities
- **JUnit Jupiter v6.0.0** - Testing framework (test scope only)

## Building from Source

### Prerequisites
- Java 17 or higher
- Maven 3.6+
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/JWT-Maker.git
cd JWT-Maker

# Build the uber JAR
mvn clean package

# Run tests
mvn test

# The uber JAR will be created at:
# target/jwt.helper-1.0-SNAPSHOT.jar
```

## Testing

The project includes comprehensive JUnit tests covering:
- ✅ JWT generation with encrypted/unencrypted keys
- ✅ Custom claims handling
- ✅ Signature verification
- ✅ Algorithm validation (RS256)
- ✅ Fingerprint generation and validation
- ✅ Error handling and edge cases

Run tests with:
```bash
mvn test
```

## Troubleshooting

### Common Issues

**Issue:** `ClassNotFoundException: com.smartbear.JWTHelper`
- **Solution:** Ensure the JAR is placed in the ReadyAPI `ext` directory and ReadyAPI has been restarted.

**Issue:** `Private key file not found`
- **Solution:** Use absolute paths for key files, not relative paths. Verify the file exists and is readable.

**Issue:** `Error generating JWT token: Unsupported key format`
- **Solution:** Ensure your key is in PKCS#8 format (.p8). Convert if necessary using OpenSSL.

**Issue:** Wrong passphrase error
- **Solution:** Verify the passphrase is correct. For unencrypted keys, use an empty string `""` or `null`.

### Debug Logging

Enable debug logging in your Groovy script:
```groovy
try {
    def jwt = com.smartbear.JWTHelper.make(claims, keyPath, passphrase)
    log.info "JWT generated successfully"
} catch (Exception e) {
    log.error "Failed to generate JWT: ${e.message}"
    log.error "Stack trace: ${e.getStackTrace()}"
    throw e
}
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Never commit private keys** to version control
2. **Use encrypted keys** with strong passphrases in production
3. **Store keys securely** with appropriate file permissions (chmod 600)
4. **Rotate keys regularly** according to your security policy
5. **Set appropriate expiration times** (`exp` claim) on tokens
6. **Use HTTPS/TLS** when transmitting JWTs over networks

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please:
1. Check existing [GitHub Issues](https://github.com/YOUR_USERNAME/JWT-Maker/issues)
2. Create a new issue with detailed information
3. Include ReadyAPI version, Java version, and error messages

## Changelog

### v1.0.0 (Current)
- Initial release
- JWT generation with RS256 algorithm
- Support for P8/PKCS#8 encrypted and unencrypted private keys
- SHA-256 public key fingerprint generation
- Comprehensive test coverage
- GitHub Actions CI/CD pipeline

---

**Made with ❤️ for the SmartBear ReadyAPI community**

