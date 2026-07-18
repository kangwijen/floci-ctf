package io.github.hectorvent.floci.services.elasticache.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.testutil.IamServiceTestHelper;
import io.github.hectorvent.floci.testutil.SigV4TokenTestHelper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SigV4ValidatorTest {

    private static SigV4Validator validator(IamService iamService) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        return new SigV4Validator(iamService, config);
    }

    @Test
    @Tag("security-regression")
    void validateAcceptsTokenForMatchingReplicationGroup() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "cache-cluster-01", "default"));
        assertTrue(validator.validate(token, "CACHE-CLUSTER-01", "default"));
    }

    @Test
    void validateRejectsTokenForDifferentReplicationGroup() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "other-cluster", "default"));
    }

    @Test
    void validateRejectsTamperedSignature() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String tamperedToken = validToken.replace("User=default", "User=other");

        assertFalse(validator.validate(tamperedToken, "cache-cluster-01", "default"));
    }

    @Test
    void validateAcceptsTokenWhenExpectedGroupIsNull() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, null, "default"));
    }

    @Test
    void validateRejectsExpiredToken() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(1200),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenWithUnknownAccessKey() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDUNKNOWN",
                "wrong-secret",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenForWrongUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "attacker"),
                "Token signed for 'default' must be rejected when client authenticates as 'attacker'");
    }

    @Test
    void validateAcceptsTokenWhenExpectedUsernameIsNull() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "cache-cluster-01", null),
                "Null expectedUsername should skip the user identity check");
    }

    @Test
    void validateAcceptsTokenWithUrlEncodedUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        // Username with characters that require URL encoding exercises the
        // encoding path independently of the validator's decode logic
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "user+name@domain.com",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "cache-cluster-01", "user+name@domain.com"));
    }

    @Test
    void validateRejectsTokenMissingActionParameter() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutAction = validToken.replaceFirst("Action=connect&", "");

        assertFalse(validator.validate(withoutAction, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenMissingSignatureParameter() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutSignature = validToken.replaceFirst("&X-Amz-Signature=[0-9a-f]+", "");

        assertFalse(validator.validate(withoutSignature, "cache-cluster-01", "default"));
    }
}
