package io.github.hectorvent.floci.services.neptune.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("security-regression")
class NeptuneHandshakeAuthenticatorTest {

    @Test
    void whenAuthRequiredRejectsMissingAuthorization() {
        NeptuneHandshakeAuthenticator auth = authenticator(true, Optional.empty());
        assertFalse(auth.accept("GET /gremlin HTTP/1.1\r\nHost: localhost\r\n\r\n", "c1"));
    }

    @Test
    void whenAuthRequiredAcceptsKnownAws4Credential() {
        IamService iam = mock(IamService.class);
        when(iam.findSecretKey("AKIATESTKEY12345")).thenReturn(Optional.of("secret"));
        NeptuneHandshakeAuthenticator auth = new NeptuneHandshakeAuthenticator(iam, mockConfig(), true);

        String headers = "GET /gremlin HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Authorization: AWS4-HMAC-SHA256 Credential=AKIATESTKEY12345/20260101/us-east-1/neptune-db/aws4_request, "
                + "SignedHeaders=host, Signature=abc\r\n\r\n";
        assertTrue(auth.accept(headers, "c1"));
    }

    @Test
    void whenAuthNotRequiredAllowsEmptyHandshake() {
        NeptuneHandshakeAuthenticator auth = authenticator(false, Optional.empty());
        assertTrue(auth.accept("", "c1"));
    }

    private static NeptuneHandshakeAuthenticator authenticator(boolean required, Optional<String> secret) {
        IamService iam = mock(IamService.class);
        when(iam.findSecretKey(org.mockito.ArgumentMatchers.anyString())).thenReturn(secret);
        return new NeptuneHandshakeAuthenticator(iam, mockConfig(), required);
    }

    private static EmulatorConfig mockConfig() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        when(config.auth()).thenReturn(auth);
        when(auth.rootAccessKeyId()).thenReturn(Optional.empty());
        when(auth.resolveRootSecretAccessKey()).thenReturn(Optional.empty());
        return config;
    }
}
