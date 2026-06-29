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
    void strictModeAcceptsPlausiblePresignedStsGetCallerIdentityUrl() {
        String stsUrl = "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
                + "&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260629%2Fus-east-1%2Fsts%2Faws4_request"
                + "&X-Amz-Date=20260629T120000Z"
                + "&X-Amz-Expires=60"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String token = k8sAwsV1Token(stsUrl);
        assertTrue(EksTokenAuthenticator.accepts(token, true));
    }

    static String k8sAwsV1Token(String presignedStsUrl) {
        return EksTokenAuthenticator.EKS_TOKEN_PREFIX
                + Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(presignedStsUrl.getBytes(StandardCharsets.UTF_8));
    }
}
