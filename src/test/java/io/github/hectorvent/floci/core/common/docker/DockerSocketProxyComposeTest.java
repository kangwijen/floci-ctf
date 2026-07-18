package io.github.hectorvent.floci.core.common.docker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

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
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final Path DEFAULT_COMPOSE = ROOT.resolve("docker-compose.yml");
    private static final Path SOCKET_PROXY_COMPOSE = ROOT.resolve("docker-compose.socket-proxy.yml");

    @Test
    void socketProxyOverrideAllowlistsCreateStartStopInspectAndRemovesDirectSock() throws Exception {
        assertTrue(Files.isRegularFile(SOCKET_PROXY_COMPOSE),
                "expected optional override " + SOCKET_PROXY_COMPOSE);

        String overrideText = Files.readString(SOCKET_PROXY_COMPOSE);
        assertTrue(overrideText.contains("volumes: !override") || overrideText.contains("volumes: !reset"),
                "floci volumes must use Compose !override or !reset so merge drops base docker.sock");

        JsonNode root = YAML.readTree(stripComposeYamlTags(overrideText));
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
    void mergedSocketProxyComposeDoesNotMountDockerSockIntoFloci() throws Exception {
        Assumptions.assumeTrue(isDockerComposeAvailable(),
                "docker compose CLI required to resolve merged Compose model");

        Process process = new ProcessBuilder(
                "docker", "compose",
                "-f", DEFAULT_COMPOSE.toString(),
                "-f", SOCKET_PROXY_COMPOSE.toString(),
                "config", "--format", "json")
                .directory(ROOT.toFile())
                .redirectErrorStream(true)
                .start();
        String output = readFully(process.getInputStream());
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "docker compose config timed out");
        assertEquals(0, process.exitValue(), "docker compose config failed: " + output);

        int jsonStart = output.indexOf('{');
        assertTrue(jsonStart >= 0, "expected JSON object in compose config output");
        JsonNode root = JSON.readTree(output.substring(jsonStart));
        JsonNode floci = root.path("services").path("floci");
        assertFalse(floci.isMissingNode(), "merged model must include floci");

        Map<String, String> env = envMap(floci.path("environment"));
        String dockerHost = env.getOrDefault("FLOCI_DOCKER_DOCKER_HOST", "");
        assertTrue(dockerHost.contains("docker-socket-proxy"),
                "merged floci must use proxy DOCKER_HOST, got: " + dockerHost);

        for (JsonNode volume : floci.path("volumes")) {
            String source = volume.path("source").asText("");
            String target = volume.path("target").asText("");
            String shortForm = volume.asText("");
            boolean isSock = source.contains("docker.sock")
                    || target.contains("docker.sock")
                    || shortForm.contains("docker.sock");
            assertFalse(isSock,
                    "merged floci must not bind-mount host docker.sock when socket-proxy overlay is applied, got: "
                            + volume);
        }

        JsonNode proxy = root.path("services").path("docker-socket-proxy");
        assertFalse(proxy.isMissingNode(), "merged model must include docker-socket-proxy");
        boolean proxyHasSock = false;
        for (JsonNode volume : proxy.path("volumes")) {
            String source = volume.path("source").asText("");
            String target = volume.path("target").asText("");
            if (source.contains("docker.sock") || target.contains("docker.sock")) {
                proxyHasSock = true;
                break;
            }
        }
        assertTrue(proxyHasSock, "proxy service must still mount host docker.sock");
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

    /**
     * Jackson YAML cannot load Compose merge tags. Strip them for structural asserts.
     * Merged-model coverage uses {@code docker compose config}.
     */
    private static String stripComposeYamlTags(String yaml) {
        return yaml.replace("!override", "").replace("!reset", "");
    }

    private static boolean isDockerComposeAvailable() {
        try {
            Process process = new ProcessBuilder("docker", "compose", "version")
                    .redirectErrorStream(true)
                    .start();
            if (!process.waitFor(15, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return false;
            }
            return process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static String readFully(InputStream in) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        in.transferTo(buf);
        return buf.toString(StandardCharsets.UTF_8);
    }
}
