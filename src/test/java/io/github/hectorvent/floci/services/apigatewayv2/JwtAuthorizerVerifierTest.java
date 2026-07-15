package io.github.hectorvent.floci.services.apigatewayv2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthorizerVerifierTest {

    private static final String SECRET = "jwt-authorizer-test-secret";

    @Test
    void verifiesHs256Token() throws Exception {
        JwtAuthorizerVerifier verifier = verifier();

        assertTrue(verifier.verify(hs256Jwt("{\"sub\":\"user\"}"), null));
    }

    @Test
    void rejectsUnsignedToken() {
        JwtAuthorizerVerifier verifier = verifier();
        String token = base64Url("{\"alg\":\"HS256\"}") + "." + base64Url("{\"sub\":\"user\"}") + ".";

        assertFalse(verifier.verify(token, null));
    }

    @Test
    void rejectsNoneAlgorithm() {
        JwtAuthorizerVerifier verifier = verifier();
        String token = base64Url("{\"alg\":\"none\"}") + "." + base64Url("{\"sub\":\"user\"}") + ".ignored";

        assertFalse(verifier.verify(token, null));
    }

    private static JwtAuthorizerVerifier verifier() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.apiGatewayJwtHmacSecret()).thenReturn(Optional.of(SECRET));
        return new JwtAuthorizerVerifier(config, new ObjectMapper(), HttpClient.newHttpClient());
    }

    private static String hs256Jwt(String payload) throws Exception {
        String signingInput = base64Url("{\"alg\":\"HS256\"}") + "." + base64Url(payload);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
