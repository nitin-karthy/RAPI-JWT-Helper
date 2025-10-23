package com.smartbear;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for JWTHelper.
 * Tests JWT generation with P8 format private keys (encrypted and unencrypted).
 */
class JWTHelperTest {

    private static String projectRoot;
    private static String encryptedKeyPath;
    private static String encryptedKeyPassphrase;
    private static String unencryptedKeyPath;
    private static String unencryptedKeyPassphrase;

    @BeforeAll
    static void setUpEnvironment() {
        projectRoot = System.getProperty("user.dir");

        // Set up paths and passphrases for test keys
        encryptedKeyPath = projectRoot + "/src/test/resources/test_private_key_encrypted.p8";
        encryptedKeyPassphrase = "testPassphrase123";

        unencryptedKeyPath = projectRoot + "/src/test/resources/test_private_key_unencrypted.p8";
        unencryptedKeyPassphrase = ""; // Empty for unencrypted keys
    }

    @Test
    void testMakeJWTWithEncryptedP8Key() throws Exception {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "testUser");
        claims.put("role", "admin");
        claims.put("customClaim", "customValue");

        // Act
        String jwt = JWTHelper.make(claims, encryptedKeyPath, encryptedKeyPassphrase);

        // Assert
        assertNotNull(jwt, "JWT token should not be null");
        assertFalse(jwt.isEmpty(), "JWT token should not be empty");
        assertEquals(3, jwt.split("\\.").length, "JWT should have 3 parts (header.payload.signature)");

        // Verify JWT can be parsed and verified with public key
        PublicKey publicKey = loadPublicKey("test_public_key.p8");
        Claims parsedClaims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

        assertEquals("testUser", parsedClaims.get("sub"), "Subject claim should match");
        assertEquals("admin", parsedClaims.get("role"), "Role claim should match");
        assertEquals("customValue", parsedClaims.get("customClaim"), "Custom claim should match");
        assertNotNull(parsedClaims.getIssuedAt(), "Issued at timestamp should be present");

        System.out.println("✅ Generated JWT with encrypted .p8 key: " + jwt.substring(0, 50) + "...");
    }

    @Test
    void testMakeJWTWithUnencryptedP8Key() throws Exception {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "unencryptedUser");
        claims.put("service", "testService");

        // Act
        String jwt = JWTHelper.make(claims, unencryptedKeyPath, unencryptedKeyPassphrase);

        // Assert
        assertNotNull(jwt, "JWT token should not be null");
        assertFalse(jwt.isEmpty(), "JWT token should not be empty");

        // Verify JWT structure
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts");

        // Verify with public key
        PublicKey publicKey = loadPublicKey("test_public_key_unencrypted.p8");
        Claims parsedClaims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

        assertEquals("unencryptedUser", parsedClaims.get("sub"));
        assertEquals("testService", parsedClaims.get("service"));

        System.out.println("✅ Generated JWT with unencrypted .p8 key: " + jwt.substring(0, 50) + "...");
    }

    @Test
    void testMakeJWTWithEmptyClaims() throws Exception {
        // Arrange
        Map<String, Object> claims = new HashMap<>();

        // Act
        String jwt = JWTHelper.make(claims, encryptedKeyPath, encryptedKeyPassphrase);

        // Assert
        assertNotNull(jwt);

        // Verify JWT can still be parsed
        PublicKey publicKey = loadPublicKey("test_public_key.p8");
        Claims parsedClaims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

        assertNotNull(parsedClaims.getIssuedAt(), "Even with empty claims, issuedAt should be present");

        System.out.println("✅ Generated JWT with empty claims");
    }

    @Test
    void testJWTSignatureVerification() throws Exception {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "verifyUser");
        claims.put("aud", "testAudience");
        claims.put("exp", System.currentTimeMillis() / 1000 + 3600); // 1 hour expiry

        // Act
        String jwt = JWTHelper.make(claims, encryptedKeyPath, encryptedKeyPassphrase);

        // Assert - Verify signature is valid
        PublicKey publicKey = loadPublicKey("test_public_key.p8");
        Claims parsedClaims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();

        assertEquals("verifyUser", parsedClaims.get("sub"));
        // JWT library wraps single audience value in a list
        Object aud = parsedClaims.get("aud");
        assertTrue(aud.toString().contains("testAudience"), "Audience claim should contain testAudience");

        System.out.println("✅ JWT signature verification successful");
    }

    @Test
    void testJWTContainsRS256Algorithm() {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "algorithmTest");

        // Act
        String jwt = JWTHelper.make(claims, encryptedKeyPath, encryptedKeyPassphrase);

        // Assert - Decode header to check algorithm
        String[] parts = jwt.split("\\.");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));

        assertTrue(headerJson.contains("RS256"), "JWT should use RS256 algorithm");

        System.out.println("✅ JWT uses RS256 algorithm");
    }

    @Test
    void testMultipleJWTsWithDifferentClaims() throws Exception {
        // Test creating multiple JWTs to ensure the helper is reusable
        Map<String, Object> claims1 = new HashMap<>();
        claims1.put("sub", "user1");
        claims1.put("role", "developer");

        Map<String, Object> claims2 = new HashMap<>();
        claims2.put("sub", "user2");
        claims2.put("role", "admin");

        // Act
        String jwt1 = JWTHelper.make(claims1, encryptedKeyPath, encryptedKeyPassphrase);
        String jwt2 = JWTHelper.make(claims2, encryptedKeyPath, encryptedKeyPassphrase);

        // Assert
        assertNotEquals(jwt1, jwt2, "Different claims should produce different JWTs");

        PublicKey publicKey = loadPublicKey("test_public_key.p8");

        Claims parsedClaims1 = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt1)
                .getPayload();
        assertEquals("user1", parsedClaims1.get("sub"));
        assertEquals("developer", parsedClaims1.get("role"));

        Claims parsedClaims2 = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt2)
                .getPayload();
        assertEquals("user2", parsedClaims2.get("sub"));
        assertEquals("admin", parsedClaims2.get("role"));

        System.out.println("✅ Multiple JWTs with different claims verified successfully");
    }

    @Test
    void testNullPrivateKeyPath() {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "testUser");

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> JWTHelper.make(claims, null, encryptedKeyPassphrase));

        assertTrue(exception.getMessage().contains("Private key path cannot be null or empty"));

        System.out.println("✅ Null private key path validation works correctly");
    }

    @Test
    void testInvalidPrivateKeyPath() {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "testUser");
        String invalidPath = "/non/existent/path/key.p8";

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> JWTHelper.make(claims, invalidPath, encryptedKeyPassphrase));

        assertTrue(exception.getMessage().contains("not found") || exception.getMessage().contains("Error generating"));

        System.out.println("✅ Invalid private key path validation works correctly");
    }

    // ============ Fingerprint Generation Tests ============

    @Test
    void testGenerateFingerprintForEncryptedPublicKey() {
        // Act
        String fingerprint = JWTHelper.generateFingerprint(projectRoot + "/src/test/resources/test_public_key.p8");

        // Assert
        assertNotNull(fingerprint, "Fingerprint should not be null");
        assertTrue(fingerprint.startsWith("SHA256:"), "Fingerprint should start with SHA256:");
        assertEquals(71, fingerprint.length(), "SHA256 fingerprint should be 71 characters (SHA256: + 64 hex chars)");

        // Verify it's a valid hex string after the prefix
        String hexPart = fingerprint.substring(7); // Remove "SHA256:" prefix
        assertTrue(hexPart.matches("[0-9a-f]{64}"), "Fingerprint should contain 64 lowercase hex characters");

        System.out.println("✅ Generated fingerprint for encrypted public key:");
        System.out.println("   " + fingerprint);
    }

    @Test
    void testGenerateFingerprintForUnencryptedPublicKey() {
        // Act
        String fingerprint = JWTHelper.generateFingerprint(projectRoot + "/src/test/resources/test_public_key_unencrypted.p8");

        // Assert
        assertNotNull(fingerprint, "Fingerprint should not be null");
        assertTrue(fingerprint.startsWith("SHA256:"), "Fingerprint should start with SHA256:");
        assertEquals(71, fingerprint.length(), "SHA256 fingerprint should be 71 characters (SHA256: + 64 hex chars)");

        System.out.println("✅ Generated fingerprint for unencrypted public key:");
        System.out.println("   " + fingerprint);
    }

    @Test
    void testFingerprintIsDeterministic() {
        // Arrange
        String publicKeyPath = projectRoot + "/src/test/resources/test_public_key.p8";

        // Act - Generate fingerprint multiple times
        String fingerprint1 = JWTHelper.generateFingerprint(publicKeyPath);
        String fingerprint2 = JWTHelper.generateFingerprint(publicKeyPath);
        String fingerprint3 = JWTHelper.generateFingerprint(publicKeyPath);

        // Assert - All fingerprints should be identical
        assertEquals(fingerprint1, fingerprint2, "Fingerprint should be deterministic");
        assertEquals(fingerprint2, fingerprint3, "Fingerprint should be deterministic");

        System.out.println("✅ Fingerprint generation is deterministic");
        System.out.println("   Fingerprint: " + fingerprint1);
    }

    @Test
    void testDifferentKeysHaveDifferentFingerprints() {
        // Act
        String fingerprint1 = JWTHelper.generateFingerprint(projectRoot + "/src/test/resources/test_public_key.p8");
        String fingerprint2 = JWTHelper.generateFingerprint(projectRoot + "/src/test/resources/test_public_key_unencrypted.p8");

        // Assert
        assertNotEquals(fingerprint1, fingerprint2, "Different public keys should have different fingerprints");

        System.out.println("✅ Different keys have different fingerprints:");
        System.out.println("   Key 1: " + fingerprint1);
        System.out.println("   Key 2: " + fingerprint2);
    }

    @Test
    void testFingerprintWithNullPath() {
        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> JWTHelper.generateFingerprint(null));

        assertTrue(exception.getMessage().contains("Public key path cannot be null or empty"));
        System.out.println("✅ Null public key path validation works correctly");
    }

    @Test
    void testFingerprintWithInvalidPath() {
        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> JWTHelper.generateFingerprint("/non/existent/public_key.p8"));

        assertTrue(exception.getMessage().contains("not found") || exception.getMessage().contains("Error generating"));
        System.out.println("✅ Invalid public key path validation works correctly");
    }

    /**
     * Load the public key for JWT verification from a specific file.
     */
    private PublicKey loadPublicKey(String filename) throws Exception {
        String publicKeyPath = projectRoot + "/src/test/resources/" + filename;

        String keyContent = Files.readString(Paths.get(publicKeyPath));
        keyContent = keyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
