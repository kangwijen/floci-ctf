package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AccountResolverTest {

    private static final String DEFAULT_ACCOUNT = "000000000000";
    private final AccountResolver resolver = new AccountResolver(DEFAULT_ACCOUNT);

    // --- resolve(String authorizationHeader) tests ---

    @Test
    void resolvesFrom12DigitAkidInAuthHeader() {
        String auth = "AWS4-HMAC-SHA256 Credential=000000000001/20260617/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        assertEquals("000000000001", resolver.resolve(auth));
    }

    @Test
    void fallsBackToDefaultForNon12DigitAkidInAuthHeader() {
        String auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260617/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        assertEquals(DEFAULT_ACCOUNT, resolver.resolve(auth));
    }

    @Test
    void fallsBackToDefaultWhenNullAuthHeader() {
        assertEquals(DEFAULT_ACCOUNT, resolver.resolve(null));
    }

    @Test
    void fallsBackToDefaultWhenEmptyAuthHeader() {
        assertEquals(DEFAULT_ACCOUNT, resolver.resolve(""));
    }

    // --- resolveFromPresignedCredential(String credentialValue) tests ---

    @Test
    void resolvesFromPresigned12DigitAkid() {
        assertEquals("000000000001",
                resolver.resolveFromPresignedCredential("000000000001/20260617/us-east-1/s3/aws4_request"));
    }

    @Test
    void fallsBackToDefaultForPresignedNon12DigitAkid() {
        assertEquals(DEFAULT_ACCOUNT,
                resolver.resolveFromPresignedCredential("AKIAIOSFODNN7EXAMPLE/20260617/us-east-1/s3/aws4_request"));
    }

    @Test
    void fallsBackToDefaultWhenPresignedCredentialNull() {
        assertEquals(DEFAULT_ACCOUNT, resolver.resolveFromPresignedCredential(null));
    }

    @Test
    void fallsBackToDefaultWhenPresignedCredentialEmpty() {
        assertEquals(DEFAULT_ACCOUNT, resolver.resolveFromPresignedCredential(""));
    }

    // --- extractPresignedAccessKeyId(String credentialValue) tests ---

    @Test
    void extractsAccessKeyIdFromPresignedCredential() {
        assertEquals("ASIAEXAMPLE",
                resolver.extractPresignedAccessKeyId("ASIAEXAMPLE/20260617/us-east-1/s3/aws4_request"));
    }

    @Test
    void extractPresignedAccessKeyIdReturnsNullWhenAbsent() {
        assertNull(resolver.extractPresignedAccessKeyId(null));
        assertNull(resolver.extractPresignedAccessKeyId(""));
    }

    // --- extractAccessKeyId(String authorizationHeader) tests ---

    @Test
    void extractAccessKeyIdReturnsAkidFromValidAuthHeader() {
        String auth = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260617/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc";
        assertEquals("AKIAIOSFODNN7EXAMPLE", resolver.extractAccessKeyId(auth));
    }

    @Test
    void extractAccessKeyIdReturnsNullForMalformedAuthorization() {
        assertNull(resolver.extractAccessKeyId("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"));
        assertNull(resolver.extractAccessKeyId("AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc"));
        assertNull(resolver.extractAccessKeyId("AWS4-HMAC-SHA256 Credential=/20260617/us-east-1/s3/aws4_request"));
        assertNull(resolver.extractAccessKeyId("AWS4-HMAC-SHA256 Credential=, SignedHeaders=host"));
    }

    // --- extractAccessKeyIdFromCredential(String credential) tests ---

    @Test
    void extractAccessKeyIdFromCredentialParsesSlashDelimitedValue() {
        assertEquals("AKIAIOSFODNN7EXAMPLE",
                resolver.extractAccessKeyIdFromCredential("AKIAIOSFODNN7EXAMPLE/20260617/us-east-1/s3/aws4_request"));
        assertEquals("000000000001",
                resolver.extractAccessKeyIdFromCredential("000000000001/20260617/us-east-1/s3/aws4_request"));
    }

    @Test
    void extractAccessKeyIdFromCredentialReturnsWholeValueWhenNoSlash() {
        assertEquals("AKIAONLY", resolver.extractAccessKeyIdFromCredential("AKIAONLY"));
    }

    @Test
    void extractAccessKeyIdFromCredentialReturnsNullWhenAbsent() {
        assertNull(resolver.extractAccessKeyIdFromCredential(null));
        assertNull(resolver.extractAccessKeyIdFromCredential(""));
        assertNull(resolver.extractAccessKeyIdFromCredential("   "));
    }

    // --- defaultAccountId() tests ---

    @Test
    void defaultAccountIdReturnsConfiguredValue() {
        assertEquals(DEFAULT_ACCOUNT, resolver.defaultAccountId());
    }
}
