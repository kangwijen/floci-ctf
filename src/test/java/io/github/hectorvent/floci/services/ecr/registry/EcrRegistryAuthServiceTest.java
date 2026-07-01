package io.github.hectorvent.floci.services.ecr.registry;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EcrRegistryAuthServiceTest {

    private EcrRegistryAuthTokenStore tokenStore;
    private EcrRegistryAuthService authService;

    @BeforeEach
    void setUp() {
        tokenStore = new EcrRegistryAuthTokenStore();
        authService = new EcrRegistryAuthService(tokenStore);
    }

    @Test
    void parseBasicPassword_extractsTokenAfterAwsPrefix() {
        String password = "secret-token-value";
        String header = basicHeader(password);
        assertEquals(password, authService.parseBasicPassword(header).orElseThrow());
    }

    @Test
    void authenticate_validTokenReturnsSession() {
        EcrRegistryAuthSession session = new EcrRegistryAuthSession(
                "arn:aws:iam::000000000000:user/player",
                "AKIAPLAYER01",
                "000000000000",
                "us-east-1",
                Instant.now().plusSeconds(3600));
        String password = tokenStore.issue(session);
        var authenticated = authService.authenticate(basicHeader(password));
        assertTrue(authenticated.isPresent());
        assertEquals("AKIAPLAYER01", authenticated.get().accessKeyId());
    }

    @Test
    void authenticate_expiredTokenRejected() {
        EcrRegistryAuthSession session = new EcrRegistryAuthSession(
                "arn:aws:iam::000000000000:user/player",
                "AKIAPLAYER01",
                "000000000000",
                "us-east-1",
                Instant.now().minusSeconds(60));
        String password = tokenStore.issue(session);
        assertFalse(authService.authenticate(basicHeader(password)).isPresent());
    }

    @Test
    void authenticate_unknownTokenRejected() {
        assertFalse(authService.authenticate(basicHeader("not-issued")).isPresent());
    }

    private static String basicHeader(String password) {
        String raw = "AWS:" + password;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
}
