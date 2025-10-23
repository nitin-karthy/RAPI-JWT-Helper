package com.smartbear;

import io.jsonwebtoken.Jwts;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;

/**
 * JWT Helper class to generate JWT tokens signed with a private key.
 * This class is designed to be used from ReadyAPI Groovy scripts.
 */
public class JWTHelper {

    static {
        // Register Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generates a JWT token signed with the provided private key.
     *
     * @param jwtFormat A map of key-value pairs representing the JWT claims to be included in the token.
     * @param privateKeyPath The path to the private key file used for signing the JWT.
     * @param privateKeyPassphrase The passphrase for the private key file (can be null or empty for unencrypted keys).
     * @return The generated JWT token as a string.
     * @throws RuntimeException if there's an error reading the key or generating the token.
     */
    public static String make(Map<String, Object> jwtFormat, String privateKeyPath, String privateKeyPassphrase) {
        try {
            // Validate the private key path
            if (privateKeyPath == null || privateKeyPath.isEmpty()) {
                throw new IllegalArgumentException("Private key path cannot be null or empty");
            }

            // Wrap the passphrase in Optional (may be null or empty for unencrypted keys)
            Optional<String> passphrase = Optional.ofNullable(privateKeyPassphrase)
                    .filter(p -> !p.isEmpty());

            // Read the private key from file
            PrivateKey privateKey = loadPrivateKey(privateKeyPath, passphrase);

            // Build the JWT token
            String jwt = Jwts.builder()
                    .claims(jwtFormat)
                    .issuedAt(new Date())
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();

            return jwt;

        } catch (Exception e) {
            throw new RuntimeException("Error generating JWT token: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a SHA-256 fingerprint of a public key file.
     * The fingerprint is prefixed with "SHA256:" and formatted as a hex string.
     * This is commonly used for key verification in APIs (GitHub, AWS, etc.).
     *
     * @param publicKeyPath The path to the public key file (.p8 or .pem format).
     * @return The fingerprint in the format "SHA256:hexstring"
     * @throws RuntimeException if there's an error reading the key or generating the fingerprint.
     */
    public static String generateFingerprint(String publicKeyPath) {
        try {
            // Validate the public key path
            if (publicKeyPath == null || publicKeyPath.isEmpty()) {
                throw new IllegalArgumentException("Public key path cannot be null or empty");
            }

            File keyFile = new File(publicKeyPath);
            if (!keyFile.exists()) {
                throw new IllegalArgumentException("Public key file not found at: " + publicKeyPath);
            }

            // Read the key file content
            String keyContent = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

            // Remove PEM headers/footers and whitespace to get the raw Base64 content
            String cleanedContent = keyContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // Decode the Base64 to get raw key bytes
            byte[] keyBytes = Base64.getDecoder().decode(cleanedContent);

            // Calculate SHA-256 hash of the key bytes
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(keyBytes);

            // Convert hash to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            // Return with SHA256: prefix
            return "SHA256:" + hexString.toString();

        } catch (Exception e) {
            throw new RuntimeException("Error generating fingerprint: " + e.getMessage(), e);
        }
    }

    /**
     * Loads a private key from a file.
     * Supports both PKCS#8 format (encrypted and unencrypted) and traditional PEM format.
     *
     * @param privateKeyPath The path to the private key file.
     * @param passphrase The passphrase for decrypting the key (if encrypted).
     * @return The loaded PrivateKey object.
     * @throws Exception if there's an error loading the key.
     */
    private static PrivateKey loadPrivateKey(String privateKeyPath, Optional<String> passphrase) throws Exception {
        File keyFile = new File(privateKeyPath);
        if (!keyFile.exists()) {
            throw new IllegalArgumentException("Private key file not found at: " + privateKeyPath);
        }

        // Read the key file content
        String keyContent = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);

        // Try to parse with Bouncy Castle PEM parser (handles both encrypted and unencrypted keys)
        if (passphrase.isPresent() && !passphrase.get().isEmpty()) {
            return loadEncryptedPrivateKey(keyContent, passphrase.get());
        }

        // For unencrypted keys, try PEM parser first, then fall back to manual parsing
        try {
            return loadUnencryptedPrivateKeyWithPEMParser(keyContent);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to load private key: " + e.getMessage(), e);
        }
    }

    /**
     * Loads an encrypted private key using Bouncy Castle PEM parser.
     *
     * @param keyContent The PEM-encoded key content.
     * @param passphrase The passphrase for decryption.
     * @return The decrypted PrivateKey object.
     * @throws Exception if there's an error decrypting or parsing the key.
     */
    private static PrivateKey loadEncryptedPrivateKey(String keyContent, String passphrase) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(keyContent))) {
            Object object = pemParser.readObject();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                // Handle encrypted key pair (traditional RSA format with passphrase)
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder()
                        .build(passphrase.toCharArray());
                PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(decryptorProvider);
                
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            } else if (object instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
                // Handle PKCS#8 encrypted format
                org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder decryptorBuilder = 
                    new org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder();
                org.bouncycastle.operator.InputDecryptorProvider decryptorProvider = 
                    decryptorBuilder.build(passphrase.toCharArray());
                PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
                
                return converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PrivateKeyInfo privateKeyInfo) {
                // Handle PKCS#8 unencrypted format
                return converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PEMKeyPair keyPair) {
                // Handle unencrypted key pair
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            } else {
                throw new IllegalArgumentException("Unsupported key format: " + 
                        (object != null ? object.getClass().getName() : "null"));
            }
        }
    }

    /**
     * Loads an unencrypted private key using Bouncy Castle PEM parser.
     *
     * @param keyContent The PEM-encoded key content.
     * @return The PrivateKey object.
     * @throws Exception if there's an error parsing the key.
     */
    private static PrivateKey loadUnencryptedPrivateKeyWithPEMParser(String keyContent) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(keyContent))) {
            Object object = pemParser.readObject();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PrivateKeyInfo privateKeyInfo) {
                return converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PEMKeyPair keyPair) {
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            } else {
                throw new IllegalArgumentException("Unsupported key format");
            }
        }
    }
}

