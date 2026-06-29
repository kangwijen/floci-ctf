package io.github.hectorvent.floci.services.eks;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EksTokenWebhookControllerTest {

    private final EmulatorConfig config = mock(EmulatorConfig.class);
    private final EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
    private final EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
    private final EksTokenWebhookController controller = new EksTokenWebhookController(config);

    EksTokenWebhookControllerTest() {
        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> status(Response response) {
        Map<String, Object> body = (Map<String, Object>) response.getEntity();
        return (Map<String, Object>) body.get("status");
    }

    private Map<String, Object> tokenReview(String token) {
        return Map.of(
                "apiVersion", "authentication.k8s.io/v1",
                "kind", "TokenReview",
                "spec", Map.of("token", token));
    }

    @Test
    @SuppressWarnings("unchecked")
    void awsIamTokenAuthenticatesAsClusterAdminWhenEnforcementOff() {
        when(iam.enforcementEnabled()).thenReturn(false);
        Response response = controller.review(tokenReview("k8s-aws-v1.aHR0cHM6Ly9zdHM..."));

        Map<String, Object> status = status(response);
        assertEquals(Boolean.TRUE, status.get("authenticated"));

        Map<String, Object> user = (Map<String, Object>) status.get("user");
        assertEquals(List.of("system:masters"), user.get("groups"));
    }

    @Test
    void fakeTokenRejectedWhenEnforcementOn() {
        when(iam.enforcementEnabled()).thenReturn(true);
        Response response = controller.review(tokenReview("k8s-aws-v1.aHR0cHM6Ly9zdHM..."));
        assertEquals(Boolean.FALSE, status(response).get("authenticated"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void plausiblePresignedStsTokenAuthenticatesWhenEnforcementOn() {
        when(iam.enforcementEnabled()).thenReturn(true);
        String stsUrl = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
                + "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260629%2Fus-east-1%2Fsts%2Faws4_request"
                + "&X-Amz-Date=20260629T120000Z"
                + "&X-Amz-Expires=60"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String token = EksTokenAuthenticator.EKS_TOKEN_PREFIX
                + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(stsUrl.getBytes(StandardCharsets.UTF_8));

        Response response = controller.review(tokenReview(token));
        Map<String, Object> status = status(response);
        assertEquals(Boolean.TRUE, status.get("authenticated"));

        Map<String, Object> user = (Map<String, Object>) status.get("user");
        assertEquals(List.of("system:masters"), user.get("groups"));
    }

    @Test
    void unrecognisedTokenIsRejected() {
        when(iam.enforcementEnabled()).thenReturn(false);
        Response response = controller.review(tokenReview("some-random-bearer-token"));
        assertEquals(Boolean.FALSE, status(response).get("authenticated"));
    }

    @Test
    void emptyOrMalformedReviewIsRejected() {
        when(iam.enforcementEnabled()).thenReturn(false);
        assertFalse((Boolean) status(controller.review(Map.of())).get("authenticated"));
        assertFalse((Boolean) status(controller.review(
                Map.of("spec", Map.of()))).get("authenticated"));
    }

    @Test
    void responseIsAlwaysAWellFormedTokenReview() {
        when(iam.enforcementEnabled()).thenReturn(false);
        Response response = controller.review(tokenReview("k8s-aws-v1.abc"));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertEquals("authentication.k8s.io/v1", body.get("apiVersion"));
        assertEquals("TokenReview", body.get("kind"));
        assertTrue(body.containsKey("status"));
    }

    @Test
    void responseEchoesRequestApiVersion() {
        when(iam.enforcementEnabled()).thenReturn(false);
        Map<String, Object> v1beta1Review = Map.of(
                "apiVersion", "authentication.k8s.io/v1beta1",
                "kind", "TokenReview",
                "spec", Map.of("token", "k8s-aws-v1.abc"));

        Response response = controller.review(v1beta1Review);
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertEquals("authentication.k8s.io/v1beta1", body.get("apiVersion"));
        assertEquals(Boolean.TRUE, status(response).get("authenticated"));
    }
}
