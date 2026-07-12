package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Container credential server surface on CodeBuild/Lambda/ECS ports (9170/9171/9172).
 *
 * <p>Expanded beyond {@link NonHttpCampaignTest#containerCredentialPortsRequirePathOrDeny()}:
 * also probes IMDS-style {@code /latest/meta-data/iam/security-credentials/}.
 * MQTT CONNECT anonymous broker smoke remains in {@link NonHttpCampaignTest}.
 *
 * <p>Skipped unless {@code -Pfuzz-operator} and {@code AWS_ENDPOINT_URL} are set
 * (endpoint presence gates the suite even though probes hit local credential ports).
 */
class ContainerCredentialsCampaignTest {

    private static final int[] CRED_PORTS = {9170, 9171, 9172};
    private static final String[] CRED_PATHS = {
            "/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials"
    };

    @BeforeEach
    void setUp() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        Assumptions.assumeTrue(
                DifferentialHttpOracle.fromEnv().isPresent(),
                "Set AWS_ENDPOINT_URL for container credential campaigns");
    }

    @Test
    void openCredentialPortsMustNotMintKeysWithoutRelativeUri() throws Exception {
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        for (int port : CRED_PORTS) {
            if (!portOpen("127.0.0.1", port)) {
                continue;
            }
            for (String path : CRED_PATHS) {
                HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .timeout(Duration.ofSeconds(3))
                        .GET()
                        .build();
                HttpResponse<String> response = client.send(req, HttpResponse.BodyHandlers.ofString());
                String body = response.body() == null ? "" : response.body();
                if (containsCredentialMaterial(body)) {
                    SecurityOracle.failSecurity(
                            "ContainerCreds.port",
                            "port=" + port + " path=" + path,
                            "container credentials server returned keys without relative URI",
                            Map.of(
                                    "status", String.valueOf(response.statusCode()),
                                    "body", body.substring(0, Math.min(200, body.length()))));
                }
            }
        }
    }

    private static boolean containsCredentialMaterial(String body) {
        return body.contains("AccessKeyId") || body.contains("SecretAccessKey");
    }

    private static boolean portOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 500);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
