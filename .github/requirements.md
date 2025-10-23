# JWT generation helper to be used in ReadyAPI

## Requirements
- This project will generate an uber jar with all dependencies included.
- The project will just have one main class `JWTHelper` that will be used to generate JWT tokens.
- The main class will have a static method called `make` be invoked from groovy script in ReadyAPI andi it will accept the following arguments
  - `jwtFormat`: A map of key-value pairs representing the JWT claims to be included in the token.
  - `privateKeyPath`: The path to the private key file used for signing the JWT.
  - `privateKeyPassphrase`: The passphrase for the private key file.
- The main class will read the private key from the file specified in the environment variable `privateKeyPathEnvVar`.
- The main class will read the passphrase from the environment variable `privateKeyPassphraseEnvVar`.
- The main class will generate a JWT token signed with the provided private key and including the claims specified in `jwtFormat`.
- The generated JWT token will be returned from the static method `make`.
- Additionally, the JWTHelper class will have a static method `generateFingerprint` to generate SHA256 fingerprint of the public key corresponding to the private key used for signing the JWT.

## Technical Stack
- Java 17
- Maven
- Free open source libraries for JWT generation and signing.
- JUnit
- Github Actions for CI/CD to create uber jar on each commit to main branch.

## Testability requirements
- Generate a public/private key pair for testing purposes using openssl on local arch linux bash shell.
- The private key will be encrypted with a passphrase for security purposes.
- Print the path of the generated private key file and the passphrase used for encryption to the console for reference.
- Create a JUnit test class `JWTHelperTest` to test the functionality of the `JWTHelper` class.