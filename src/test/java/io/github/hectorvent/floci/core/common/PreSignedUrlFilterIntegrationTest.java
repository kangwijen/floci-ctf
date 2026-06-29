package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;

/**
 * End-to-end {@code PreSignedUrlFilter} behavior under the Compose CTF profile.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PreSignedUrlFilterIntegrationTest {

    private static final String BUCKET = "presign-filter-bucket";
    private static final String KEY = "object.txt";
    private static final String REGION = "us-east-1";
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;

    @BeforeAll
    void bind() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
    }

    @Test
    void presignedGetWithUnknownAkiaReturns403() {
        Instant now = Instant.now();
        String amzDate = AMZ_DATE.format(now);
        String dateStamp = amzDate.substring(0, 8);
        String credential = "AKIAUNKNOWN00001/" + dateStamp + "/" + REGION + "/s3/aws4_request";
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=" + urlEncode(credential)
                + "&X-Amz-Date=" + amzDate
                + "&X-Amz-Expires=3600"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=deadbeef";

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .when()
                .get("/" + BUCKET + "/" + KEY + "?" + query)
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("Unknown credentials"),
                        containsString("AccessDenied")));
    }

    @Test
    void expiredPresignedGetReturnsRequestExpiredOr403() {
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=" + urlEncode("AKIAUNKNOWN00001/20200101/" + REGION + "/s3/aws4_request")
                + "&X-Amz-Date=20200101T000000Z"
                + "&X-Amz-Expires=1"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=deadbeef";

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .when()
                .get("/" + BUCKET + "/" + KEY + "?" + query)
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("Request has expired"),
                        containsString("RequestExpired"),
                        containsString("AccessDenied")));
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
