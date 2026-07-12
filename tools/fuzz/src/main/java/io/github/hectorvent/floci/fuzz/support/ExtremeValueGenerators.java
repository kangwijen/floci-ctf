package io.github.hectorvent.floci.fuzz.support;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Extreme-value generators for crash and hang oracles only.
 *
 * <p>Do not feed these into security-namespace oracles (ARN scoping, auth bypass,
 * policy Allow/Deny). Shaped request bodies for security tests belong in
 * {@link FuzzBodyGenerators} and its {@code sanitize} path.
 */
public final class ExtremeValueGenerators {

    public static final int DEFAULT_CRASH_MAX_STRING = 8192;
    public static final int LARGE_SAMPLE_ONCE = 65536;

    private ExtremeValueGenerators() {
    }

    /** Legacy combined extreme strings (ECR signed diff, env hardening). */
    public static Arbitrary<String> extremeStrings() {
        return Arbitraries.oneOf(
                emptyAndWhitespace(),
                unicodeAndControl(),
                oversizedString(4096),
                Arbitraries.of(
                        "\uFFFE",
                        "AWS:\u0000token",
                        "Basic " + "A".repeat(8192),
                        "Basic !!!not-base64!!!",
                        "\uFEFFBasic dGVzdA=="));
    }

    public static Arbitrary<String> extremeEnvKeyNames() {
        return Arbitraries.oneOf(
                emptyAndWhitespace(),
                Arbitraries.strings().ofMinLength(128).ofMaxLength(512),
                Arbitraries.of(
                        "AWS_SECRET_ACCESS_KEY",
                        "aws_secret_access_key",
                        "FLOCI_AUTH_ROOT_ACCESS_KEY_ID",
                        "PLAYER_\uD800KEY",
                        "KEY\u0000SUFFIX"));
    }

    public static Arbitrary<String> emptyAndWhitespace() {
        return Arbitraries.oneOf(
                Arbitraries.just(null),
                Arbitraries.of("", " ", "\t", "\n", "\r\n", "  \t\n\r", "\u00a0"));
    }

    public static Arbitrary<String> oversizedString(int max) {
        int cap = Math.max(0, max);
        return Arbitraries.strings().ofMinLength(0).ofMaxLength(cap);
    }

    public static Arbitrary<String> oversizedStringDefault() {
        return oversizedString(DEFAULT_CRASH_MAX_STRING);
    }

    /** One-shot very large string for dedicated crash properties (not jqwik-shrunk). */
    public static String oversizedSampleOnce() {
        return "X".repeat(LARGE_SAMPLE_ONCE);
    }

    public static Arbitrary<String> unicodeAndControl() {
        return Arbitraries.oneOf(
                Arbitraries.just("\u0000"),
                Arbitraries.just("\u0001"),
                Arbitraries.just("\uFEFF"),
                Arbitraries.just("\uD800\uDFFF"),
                Arbitraries.just("مرحبا\u202Ertl"),
                Arbitraries.strings().withChars('\uD800', '\uDFFF').ofMinLength(1).ofMaxLength(12),
                Arbitraries.strings().withCharRange('\u0000', '\u001f').ofMinLength(1).ofMaxLength(16),
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(24).map(s -> s + "🎉"));
    }

    public static List<String> pathTraversalSamplesList() {
        return List.of(
                "../",
                "..\\",
                "%2e%2e%2f",
                "%2e%2e/",
                "..%2f..%2fetc%2fpasswd",
                "/etc/passwd",
                "C:\\Windows\\System32",
                "\\\\server\\share",
                "../x\u0000/y",
                "....//....//etc/passwd",
                "/%2e%2e/%2e%2e/secret");
    }

    public static Arbitrary<String> pathTraversalSamples() {
        return Arbitraries.oneOf(
                Arbitraries.of(pathTraversalSamplesList()),
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20)
                        .map(leaf -> "../" + leaf + "/%2e%2e"));
    }

    public static Arbitrary<String> jsonBombs() {
        return Arbitraries.integers().between(1, 32).flatMap(depth ->
                Arbitraries.integers().between(1, 4).map(width -> buildNestedJson(depth, width)));
    }

    private static final int JSON_BOMB_MAX_CHARS = 65_536;

    public static Arbitrary<String> numericExtremes() {
        return Arbitraries.of(
                "0",
                "-1",
                "1",
                String.valueOf(Integer.MAX_VALUE),
                String.valueOf(Integer.MIN_VALUE),
                String.valueOf(Long.MAX_VALUE),
                String.valueOf(Long.MIN_VALUE),
                "NaN",
                "Infinity",
                "-Infinity",
                "1e308",
                "1e-308",
                "0.0",
                "-0.0",
                "9223372036854775808");
    }

    public static Arbitrary<String> binaryishBase64() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(256)
                .map(bytes -> Base64.getEncoder().encodeToString(bytes));
    }

    public static Arbitrary<String> longBase64() {
        return Arbitraries.strings()
                .withChars("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
                .ofMinLength(64).ofMaxLength(4096);
    }

    /**
     * MQTT CONNECT frames with extreme client identifiers (crash parsing only).
     */
    public static Arbitrary<byte[]> mqttConnectFrameVariants() {
        return Arbitraries.oneOf(
                emptyAndWhitespace().map(ExtremeValueGenerators::minimalMqttConnectFrame),
                unicodeAndControl().map(ExtremeValueGenerators::minimalMqttConnectFrame),
                oversizedString(512).map(ExtremeValueGenerators::minimalMqttConnectFrame),
                pathTraversalSamples().map(ExtremeValueGenerators::minimalMqttConnectFrame));
    }

    /** Combined extreme bodies for HTTP parser crash properties. */
    public static Arbitrary<String> extremeBodies() {
        return Arbitraries.oneOf(
                emptyAndWhitespace(),
                oversizedStringDefault(),
                unicodeAndControl(),
                jsonBombs(),
                numericExtremes().map(n -> "{\"value\":" + n + ",\"n\":\"" + n + "\"}"),
                binaryishBase64().map(b -> "{\"SecretBinary\":\"" + b + "\"}"),
                longBase64().map(b -> "{\"blob\":\"" + b + "\"}"),
                pathTraversalSamples().map(p -> "{\"Name\":\"" + escapeJson(p) + "\"}"));
    }

    public static Arbitrary<String> extremePaths() {
        return Arbitraries.oneOf(
                emptyAndWhitespace(),
                pathTraversalSamples(),
                unicodeAndControl(),
                oversizedString(512).map(s -> "/" + s));
    }

    public static byte[] minimalMqttConnectFrame(String clientId) {
        String id = clientId == null ? "" : clientId;
        if (id.length() > 512) {
            id = id.substring(0, 512);
        }
        byte[] clientIdBytes = id.getBytes(StandardCharsets.UTF_8);
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

    private static String buildNestedJson(int depth, int width) {
        int d = Math.min(Math.max(depth, 1), 32);
        int w = Math.min(Math.max(width, 1), 4);
        StringBuilder sb = new StringBuilder(Math.min(JSON_BOMB_MAX_CHARS, d * w * 32));
        appendNestedObject(sb, d, w, 0);
        if (sb.length() > JSON_BOMB_MAX_CHARS) {
            return sb.substring(0, JSON_BOMB_MAX_CHARS);
        }
        return sb.toString();
    }

    private static void appendNestedObject(StringBuilder sb, int depth, int width, int level) {
        if (sb.length() >= JSON_BOMB_MAX_CHARS) {
            sb.append("{}");
            return;
        }
        sb.append('{');
        for (int i = 0; i < width; i++) {
            if (sb.length() >= JSON_BOMB_MAX_CHARS) {
                break;
            }
            if (i > 0) {
                sb.append(',');
            }
            String key = "k" + level + "_" + i;
            sb.append('"').append(escapeJson(key)).append("\":");
            if (level + 1 >= depth) {
                sb.append(i % 2 == 0 ? "[]" : "0");
            } else if (i % 3 == 0) {
                sb.append('[');
                int arrayWidth = Math.min(width, 2);
                for (int j = 0; j < arrayWidth; j++) {
                    if (j > 0) {
                        sb.append(',');
                    }
                    if (sb.length() >= JSON_BOMB_MAX_CHARS) {
                        sb.append("{}");
                        break;
                    }
                    appendNestedObject(sb, depth, width, level + 1);
                }
                sb.append(']');
            } else {
                appendNestedObject(sb, depth, width, level + 1);
            }
        }
        sb.append('}');
    }

    private static String escapeJson(String raw) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
