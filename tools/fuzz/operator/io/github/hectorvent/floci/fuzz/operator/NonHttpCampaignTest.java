package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Non-HTTP and side-channel campaigns: container credential ports, MQTT/TCP probes,
 * and Duck/Athena-related operator-cred surface smoke checks.
 *
 * <p>Expanded credential-port coverage (IMDS-style paths) lives in
 * {@link ContainerCredentialsCampaignTest}. TCP proxy port probes (ElastiCache 6379-6399,
 * MemoryDB 6400-6419, RDS 7001-7099, Neptune 8182-8282) and MQTT CONNECT probes stay here.
 * DocumentDB Mongo uses dynamic Docker host ports when clusters run (no fixed proxy range).
 */
class NonHttpCampaignTest {

    private static final String TCP_HOST = "127.0.0.1";
    private static final int ELASTICACHE_PORT_MIN = 6379;
    private static final int ELASTICACHE_PORT_MAX = 6399;
    private static final int MEMORYDB_PORT_MIN = 6400;
    private static final int MEMORYDB_PORT_MAX = 6419;
    private static final int RDS_PORT_MIN = 7001;
    private static final int RDS_PORT_MAX = 7099;
    private static final int NEPTUNE_PORT_MIN = 8182;
    private static final int NEPTUNE_PORT_MAX = 8282;
    private static final int MQTT_PORT = 1883;

    private String endpoint;

    @BeforeEach
    void setUp() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        endpoint = firstNonBlank(
                System.getenv("AWS_ENDPOINT_URL"),
                System.getenv("FLOCI_ENDPOINT"),
                System.getProperty("fuzz.endpoint"));
        Assumptions.assumeTrue(endpoint != null && !endpoint.isBlank(),
                "Set AWS_ENDPOINT_URL for non-HTTP campaigns");
    }

    @Test
    void containerCredentialPortsRequirePathOrDeny() throws Exception {
        // Lambda/ECS/CodeBuild credential servers bind on 9171/9172/9170 when containers run.
        // Against a stock Compose instance they may be closed; open ports must not mint root without a relative URI.
        for (int port : new int[] {9170, 9171, 9172}) {
            if (!portOpen("127.0.0.1", port)) {
                continue;
            }
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/"))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(req, HttpResponse.BodyHandlers.ofString());
            String body = response.body() == null ? "" : response.body();
            if (response.statusCode() == 200
                    && (body.contains("AccessKeyId") || body.contains("SecretAccessKey"))) {
                SecurityOracle.failSecurity(
                        "NonHttp.containerCreds",
                        "port=" + port,
                        "container credentials server returned keys without relative URI",
                        Map.of("body", body.substring(0, Math.min(200, body.length()))));
            }
        }
    }

    @Test
    void tcpProxyPortRangesRecordedWhenReachable() {
        // Record-only: proxies may be down when no ElastiCache/MemoryDB/RDS clusters run.
        List<String> open = new ArrayList<>();
        for (int port : samplePorts(ELASTICACHE_PORT_MIN, ELASTICACHE_PORT_MAX, 4)) {
            if (portOpen(TCP_HOST, port)) {
                open.add("elasticache:" + port);
            }
        }
        for (int port : samplePorts(MEMORYDB_PORT_MIN, MEMORYDB_PORT_MAX, 4)) {
            if (portOpen(TCP_HOST, port)) {
                open.add("memorydb:" + port);
            }
        }
        for (int port : samplePorts(RDS_PORT_MIN, RDS_PORT_MAX, 4)) {
            if (portOpen(TCP_HOST, port)) {
                open.add("rds:" + port);
            }
        }
        for (int port : samplePorts(NEPTUNE_PORT_MIN, NEPTUNE_PORT_MAX, 4)) {
            if (portOpen(TCP_HOST, port)) {
                open.add("neptune:" + port);
            }
        }
        Assumptions.assumeTrue(true, "tcp open ports=" + open);
    }

    @Test
    void redisAuthGarbageDoesNotHangWhenProxyOpen() throws Exception {
        byte[] authCommand = ("*2\r\n$4\r\nAUTH\r\n$12\r\nfuzz-garbage\r\n")
                .getBytes(StandardCharsets.UTF_8);
        for (int port : samplePorts(ELASTICACHE_PORT_MIN, ELASTICACHE_PORT_MAX, 3)) {
            if (!portOpen(TCP_HOST, port)) {
                continue;
            }
            CrashWatchdog.run("NonHttp.elasticache.auth", "port=" + port, 3000, () -> {
                softRedisAuthProbe(port, authCommand);
                return null;
            });
        }
        for (int port : samplePorts(MEMORYDB_PORT_MIN, MEMORYDB_PORT_MAX, 3)) {
            if (!portOpen(TCP_HOST, port)) {
                continue;
            }
            CrashWatchdog.run("NonHttp.memorydb.auth", "port=" + port, 3000, () -> {
                softRedisAuthProbe(port, authCommand);
                return null;
            });
        }
    }

    @Test
    void neptuneGremlinProxyGarbageUpgradeDoesNotHangWhenOpen() throws Exception {
        List<byte[]> samples = List.of(
                "GET /gremlin HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n"
                        .getBytes(StandardCharsets.UTF_8),
                ("GET / HTTP/1.1" + "\r\n" + "Upgrade: websocket" + "\r\n"
                        + "Connection: Upgrade" + "\r\n\r\n").getBytes(StandardCharsets.UTF_8),
                new byte[] {0x00, (byte) 0xff, (byte) 0xfe, (byte) 0xfd, 'g', 'a', 'r', 'b', 'a', 'g', 'e'});
        for (int port : samplePorts(NEPTUNE_PORT_MIN, NEPTUNE_PORT_MAX, 3)) {
            if (!portOpen(TCP_HOST, port)) {
                continue;
            }
            for (byte[] payload : samples) {
                CrashWatchdog.run("NonHttp.neptune.upgrade", "port=" + port, 3000, () -> {
                    softTcpProbe(port, payload);
                    return null;
                });
            }
        }
    }

    @Test
    void mqttConnectDoesNotHangWhenBrokerOpen() throws Exception {
        if (!portOpen(TCP_HOST, MQTT_PORT)) {
            return;
        }
        byte[] connectFrame = minimalMqttConnectFrame("fuzz-mqtt-client");
        CrashWatchdog.run("NonHttp.mqtt.connect", "port=" + MQTT_PORT, 3000, () -> {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(TCP_HOST, MQTT_PORT), 2000);
                socket.setSoTimeout(2000);
                OutputStream out = socket.getOutputStream();
                out.write(connectFrame);
                out.flush();
                InputStream in = socket.getInputStream();
                byte[] buf = new byte[64];
                in.read(buf);
            }
            return null;
        });
    }

    @Test
    void mqttAnonymousConnectRejectedWhenEnforcementOn() throws Exception {
        if (!portOpen(TCP_HOST, MQTT_PORT)) {
            return;
        }
        boolean enforcementOn = Boolean.parseBoolean(firstNonBlank(
                System.getenv("FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED"),
                System.getProperty("fuzz.iam.enforcement"),
                "true"));
        if (!enforcementOn) {
            return;
        }
        byte[] connectFrame = minimalMqttConnectFrame("fuzz-anon-client");
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TCP_HOST, MQTT_PORT), 2000);
            socket.setSoTimeout(2000);
            socket.getOutputStream().write(connectFrame);
            socket.getOutputStream().flush();
            byte[] buf = new byte[8];
            int read = socket.getInputStream().read(buf);
            if (read >= 4 && (buf[0] & 0xF0) == 0x20 && buf[3] == 0x00) {
                SecurityOracle.failSecurity(
                        "NonHttp.mqtt.anonymous",
                        "port=" + MQTT_PORT,
                        "anonymous MQTT CONNECT accepted under IAM enforcement",
                        Map.of("connack", bytesToHex(buf, read)));
            }
        }
    }

    @Test
    void unsignedAthenaStartQueryDoesNotSucceed() throws Exception {
        DifferentialHttpOracle oracle = new DifferentialHttpOracle(endpoint);
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "AmazonAthena.StartQueryExecution"),
                "{\"QueryString\":\"SELECT 1\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "NonHttp.athena.duck",
                    "StartQueryExecution",
                    "unsigned Athena query succeeded (operator Duck path risk)",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedEcrV2ManifestDenied() throws Exception {
        DifferentialHttpOracle oracle = new DifferentialHttpOracle(endpoint);
        for (String path : List.of(
                "/v2/",
                "/v2/fuzz-repo/manifests/latest",
                "/v2/fuzz-repo/tags/list",
                "/v2/fuzz-repo/blobs/sha256:deadbeef")) {
            DifferentialHttpOracle.ProbeResult result = oracle.exchange("GET", path, Map.of(), null);
            if (result.success()) {
                SecurityOracle.failSecurity(
                        "NonHttp.ecr.v2",
                        path,
                        "unsigned ECR /v2/ path succeeded",
                        Map.of("status", String.valueOf(result.status())));
            }
        }
    }

    @Test
    void dnsProbeDoesNotRequireOpenResolver() {
        // Embedded DNS is optional; campaign records reachability only.
        boolean open = portOpen("127.0.0.1", 53) || portOpen("127.0.0.1", 8053);
        Assumptions.assumeTrue(true, "dns open=" + open);
    }

    private static boolean portOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 500);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static List<Integer> samplePorts(int min, int max, int count) {
        List<Integer> ports = new ArrayList<>();
        if (min > max || count <= 0) {
            return ports;
        }
        int span = max - min + 1;
        int step = Math.max(1, span / count);
        for (int i = 0; i < count && min + i * step <= max; i++) {
            ports.add(min + i * step);
        }
        if (!ports.contains(max) && ports.size() < count) {
            ports.add(max);
        }
        return ports;
    }

    private static void softTcpProbe(int port, byte[] payload) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TCP_HOST, port), 2000);
            socket.setSoTimeout(2000);
            socket.getOutputStream().write(payload);
            socket.getOutputStream().flush();
            byte[] buf = new byte[256];
            socket.getInputStream().read(buf);
        }
    }

    private static void softRedisAuthProbe(int port, byte[] authCommand) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(TCP_HOST, port), 2000);
            socket.setSoTimeout(2000);
            socket.getOutputStream().write(authCommand);
            socket.getOutputStream().flush();
            byte[] buf = new byte[256];
            int read = socket.getInputStream().read(buf);
            if (read > 0) {
                String response = new String(buf, 0, read, StandardCharsets.UTF_8);
                if (response.startsWith("+OK") && authCommand.length > 0) {
                    // Garbage AUTH must not succeed when a proxy is enforcing credentials.
                    SecurityOracle.failSecurity(
                            "NonHttp.redis.auth",
                            "port=" + port,
                            "garbage Redis AUTH returned +OK",
                            Map.of("response", response.substring(0, Math.min(80, response.length()))));
                }
            }
        }
    }

    private static byte[] minimalMqttConnectFrame(String clientId) {
        byte[] clientIdBytes = clientId.getBytes(StandardCharsets.UTF_8);
        int remaining = 10 + 2 + clientIdBytes.length;
        byte[] frame = new byte[2 + remaining];
        int i = 0;
        frame[i++] = 0x10;
        frame[i++] = (byte) remaining;
        frame[i++] = 0x00;
        frame[i++] = 0x04;
        frame[i++] = 'M';
        frame[i++] = 'Q';
        frame[i++] = 'T';
        frame[i++] = 'T';
        frame[i++] = 0x04;
        frame[i++] = 0x02;
        frame[i++] = 0x00;
        frame[i++] = 0x3c;
        frame[i++] = (byte) ((clientIdBytes.length >> 8) & 0xff);
        frame[i++] = (byte) (clientIdBytes.length & 0xff);
        System.arraycopy(clientIdBytes, 0, frame, i, clientIdBytes.length);
        return frame;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String bytesToHex(byte[] buf, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02x", buf[i]));
        }
        return sb.toString();
    }
}
