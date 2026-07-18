package io.github.hectorvent.floci.core.common.docker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Optional Compose socket-proxy path must allowlist create/start/stop/inspect
 * and must not leave Floci on a direct RW docker.sock mount.
 */
@Tag("security-regression")
class DockerSocketProxyComposeTest {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());
    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final Path DEFAULT_COMPOSE = ROOT.resolve("docker-compose.yml");
    private static final Path SOCKET_PROXY_COMPOSE = ROOT.resolve("docker-compose.socket-proxy.yml");

    @Test
    void socketProxyOverrideAllowlistsCreateStartStopInspectAndRemovesDirectSock() throws Exception {
        assertTrue(Files.isRegularFile(SOCKET_PROXY_COMPOSE),
                "expected optional override " + SOCKET_PROXY_COMPOSE);

        JsonNode root = YAML.readTree(SOCKET_PROXY_COMPOSE.toFile());
        JsonNode services = root.path("services");
        JsonNode proxy = services.path("docker-socket-proxy");
        JsonNode floci = services.path("floci");

        assertFalse(proxy.isMissingNode(), "docker-socket-proxy service required");
        assertFalse(floci.isMissingNode(), "floci override required");

        Map<String, String> proxyEnv = envMap(proxy.path("environment"));
        assertEquals("1", proxyEnv.get("CONTAINERS"), "inspect/create need CONTAINERS");
        assertEquals("1", proxyEnv.get("POST"), "create/start/stop need POST");
        assertEquals("1", proxyEnv.get("ALLOW_START"), "start allowlist");
        assertEquals("1", proxyEnv.get("ALLOW_STOP"), "stop allowlist");

        String image = proxy.path("image").asText("");
        assertTrue(image.contains("docker-socket-proxy"),
                "proxy image should be tecnativa/docker-socket-proxy, got: " + image);

        assertTrue(volumeMounts(proxy).stream().anyMatch(v -> v.contains("docker.sock")),
                "proxy must mount host docker.sock");
        assertFalse(proxy.has("ports") && proxy.path("ports").isArray() && proxy.path("ports").size() > 0,
                "proxy must not publish host ports (LAN exposure of API)");

        Map<String, String> flociEnv = envMap(floci.path("environment"));
        String dockerHost = flociEnv.getOrDefault("FLOCI_DOCKER_DOCKER_HOST", "");
        assertTrue(dockerHost.contains("docker-socket-proxy"),
                "floci must point FLOCI_DOCKER_DOCKER_HOST at the proxy, got: " + dockerHost);

        assertFalse(volumeMounts(floci).stream().anyMatch(v -> v.contains("docker.sock")),
                "floci override must not mount docker.sock directly");
    }

    @Test
    void defaultComposeStillMountsDockerSockForCompatibility() throws Exception {
        assertTrue(Files.isRegularFile(DEFAULT_COMPOSE));
        JsonNode root = YAML.readTree(DEFAULT_COMPOSE.toFile());
        JsonNode floci = root.path("services").path("floci");
        assertTrue(volumeMounts(floci).stream().anyMatch(v -> v.contains("docker.sock")),
                "default Compose keeps RW sock unless operators opt into socket-proxy override");
        String composeText = Files.readString(DEFAULT_COMPOSE);
        assertTrue(composeText.toLowerCase().contains("host-root"),
                "default Compose must document LAN/RW-sock host-root risk");
    }

    @Test
    void docsStateLanExposureWithRwSockIsHostRoot() throws Exception {
        Path doc = ROOT.resolve("docs/configuration/docker-compose.md");
        assertTrue(Files.isRegularFile(doc));
        String text = Files.readString(doc);
        assertTrue(text.contains("host root") || text.contains("host-root"),
                "docker-compose.md must document LAN exposure + RW sock = host root");
        assertTrue(text.contains("docker-compose.socket-proxy.yml"),
                "docker-compose.md must document optional socket-proxy override");
    }

    private static Map<String, String> envMap(JsonNode environment) {
        if (environment == null || environment.isMissingNode() || environment.isNull()) {
            return Map.of();
        }
        if (environment.isObject()) {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            Iterator<Map.Entry<String, JsonNode>> fields = environment.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> e = fields.next();
                out.put(e.getKey(), e.getValue().asText());
            }
            return out;
        }
        if (environment.isArray()) {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            for (JsonNode item : environment) {
                String text = item.asText("");
                int eq = text.indexOf('=');
                if (eq > 0) {
                    out.put(text.substring(0, eq), text.substring(eq + 1));
                }
            }
            return out;
        }
        return Map.of();
    }

    private static Set<String> volumeMounts(JsonNode service) {
        Set<String> mounts = new LinkedHashSet<>();
        JsonNode volumes = service.path("volumes");
        if (!volumes.isArray()) {
            return mounts;
        }
        for (JsonNode v : volumes) {
            mounts.add(v.asText(""));
        }
        return mounts;
    }
}
