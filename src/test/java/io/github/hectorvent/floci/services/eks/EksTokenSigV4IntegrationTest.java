package io.github.hectorvent.floci.services.eks;

import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.services.s3.PreSignedUrlGenerator;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
class EksTokenSigV4IntegrationTest {

    private static final DateTimeFormatter AMZ_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
            .withZone(ZoneOffset.UTC);

    @Inject
    EksTokenValidator tokenValidator;

    @Test
    void acceptsValidPresignedGetCallerIdentityToken() throws Exception {
        String token = k8sToken(signedStsUrl(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET, 900));
        assertTrue(tokenValidator.accepts(token));
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        String url = signedStsUrl(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET, 900);
        String tampered = url.replaceAll("X-Amz-Signature=[0-9a-f]+", "X-Amz-Signature=deadbeef");
        assertFalse(tokenValidator.accepts(EksTokenValidatorTest.k8sAwsV1Token(tampered)));
    }

    @Test
    void rejectsExpiredPresignedUrl() throws Exception {
        String amzDate = AMZ_DATE.format(Instant.now().minusSeconds(7200));
        String url = signedStsUrlWithDate(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET, 60, amzDate);
        assertFalse(tokenValidator.accepts(EksTokenValidatorTest.k8sAwsV1Token(url)));
    }

    @Test
    void rejectsUnknownAccessKey() throws Exception {
        String url = signedStsUrl("AKIAUNKNOWN00001", "not-a-real-secret-key-32-chars!!!", 900);
        assertFalse(tokenValidator.accepts(EksTokenValidatorTest.k8sAwsV1Token(url)));
    }

    @Test
    void rejectsBarePrefixWithoutPresignedUrl() {
        assertFalse(tokenValidator.accepts("k8s-aws-v1.not-a-real-presign"));
    }

    private static String k8sToken(String presignedStsUrl) {
        return EksTokenValidatorTest.k8sAwsV1Token(presignedStsUrl);
    }

    private static String signedStsUrl(String accessKeyId, String secretKey, int expiresSeconds)
            throws Exception {
        return signedStsUrlWithDate(accessKeyId, secretKey, expiresSeconds,
                AMZ_DATE.format(Instant.now()));
    }

    private static String signedStsUrlWithDate(String accessKeyId,
                                               String secretKey,
                                               int expiresSeconds,
                                               String amzDate) throws Exception {
        int port = io.restassured.RestAssured.port;
        String host = "localhost:" + port;
        String dateStamp = amzDate.substring(0, 8);
        String region = "us-east-1";
        String service = "sts";
        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("Action", "GetCallerIdentity");
        extra.put("Version", "2011-06-15");
        String rawQueryWithoutSignature = PreSignedUrlGenerator.buildPresignQueryWithoutSignature(
                credentialValue, amzDate, expiresSeconds, "host", extra);
        String signature = SigV4RequestValidator.computePresignedSignature(
                "GET",
                "/",
                rawQueryWithoutSignature,
                host,
                secretKey,
                amzDate,
                "host",
                region,
                service,
                dateStamp,
                credentialScope);
        return "http://" + host + "/?" + rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
    }
}
