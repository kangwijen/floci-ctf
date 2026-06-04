package io.github.hectorvent.floci.services.eks;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EksTokenAuthenticatorTest {

    @Test
    void permissiveWhenIamEnforcementOff() {
        assertTrue(EksTokenAuthenticator.accepts("k8s-aws-v1.anything", false));
    }

    @Test
    void strictModeRejectsBarePrefix() {
        assertFalse(EksTokenAuthenticator.accepts("k8s-aws-v1.not-a-real-presign", true));
    }

    @Test
    void strictModeAcceptsPlausiblePresignedStsUrl() {
        String stsUrl = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
                + "&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc123";
        String token = EksTokenAuthenticator.EKS_TOKEN_PREFIX
                + Base64.getUrlEncoder().withoutPadding().encodeToString(stsUrl.getBytes(StandardCharsets.UTF_8));
        assertTrue(EksTokenAuthenticator.accepts(token, true));
    }
}
