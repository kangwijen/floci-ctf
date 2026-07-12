package io.github.hectorvent.floci.fuzz.operator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Differential Allow/Deny oracle for live {@code floci:local} campaigns.
 *
 * <p>Finding if a low-priv participant gets success where gold policy denies,
 * or an unsigned request succeeds without an intentional anonymous path.
 */
public final class DifferentialHttpOracle {

    public record ProbeResult(int status, String bodySnippet) {
        boolean success() {
            return status >= 200 && status < 300;
        }

        boolean accessDenied() {
            return status == 403
                    || status == 401
                    || (bodySnippet != null && (bodySnippet.contains("AccessDenied")
                    || bodySnippet.contains("UnauthorizedOperation")
                    || bodySnippet.contains("AuthorizationError")));
        }
    }

    private final HttpClient client;
    private final URI endpoint;

    public DifferentialHttpOracle(String endpointUrl) {
        this.endpoint = URI.create(endpointUrl.endsWith("/")
                ? endpointUrl.substring(0, endpointUrl.length() - 1)
                : endpointUrl);
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public static Optional<DifferentialHttpOracle> fromEnv() {
        if (Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true"))) {
            return Optional.empty();
        }
        String url = firstNonBlank(
                System.getenv("AWS_ENDPOINT_URL"),
                System.getenv("FLOCI_ENDPOINT"),
                System.getProperty("fuzz.endpoint"));
        if (url == null || url.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new DifferentialHttpOracle(url));
    }

    public URI endpoint() {
        return endpoint;
    }

    public static Optional<ParticipantCredentials> participantCredentials() {
        return ParticipantCredentials.fromEnv();
    }

    public ProbeResult exchange(String method, String path, Map<String, String> headers, String body)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(endpoint.resolve(path))
                .timeout(Duration.ofSeconds(15));
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);
        b.method(method, publisher);
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getValue() != null) {
                    b.header(e.getKey(), e.getValue());
                }
            }
        }
        HttpResponse<String> response = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        String snippet = response.body() == null ? ""
                : response.body().substring(0, Math.min(500, response.body().length()));
        return new ProbeResult(response.statusCode(), snippet);
    }

    /**
     * Fails when unsigned succeeds, or when a registered participant succeeds while unsigned is denied.
     *
     * <p>Participant leg is skipped (no-op) when participant env is unset.
     */
    public void assertParticipantDeniedWhenUnsignedAlsoDenied(
            String target,
            String method,
            String path,
            Map<String, String> baseHeaders,
            String body,
            String region,
            String service) throws Exception {
        Map<String, String> unsignedHeaders = baseHeaders == null ? Map.of() : baseHeaders;
        ProbeResult unsigned = exchange(method, path, unsignedHeaders, body);
        if (unsigned.success()) {
            io.github.hectorvent.floci.fuzz.oracle.SecurityOracle.failSecurity(
                    target,
                    body,
                    "unsigned request succeeded under CTF profile",
                    Map.of("status", String.valueOf(unsigned.status()), "path", path));
        }

        Optional<ParticipantCredentials> creds = participantCredentials();
        if (creds.isEmpty()) {
            return;
        }

        Map<String, String> signed = ParticipantSigV4Signer.sign(
                endpoint,
                method,
                path,
                body,
                creds.get(),
                region,
                service,
                toSignedHeaderMap(unsignedHeaders));
        ProbeResult participant = exchange(method, path, signed, body);
        if (participant.success() && unsigned.accessDenied()) {
            Map<String, String> details = new LinkedHashMap<>();
            details.put("status", String.valueOf(participant.status()));
            details.put("path", path);
            details.put("body", participant.bodySnippet());
            io.github.hectorvent.floci.fuzz.oracle.SecurityOracle.failSecurity(
                    target,
                    body,
                    "participant succeeded while unsigned was denied",
                    details);
        }
    }

    /**
     * Fails if unsigned or participant requests succeed when the caller expects deny for both.
     *
     * <p>Participant leg is skipped when participant env is unset.
     */
    public void assertUnsignedDeniedAndParticipantNeverSucceeds(
            String target,
            String method,
            String path,
            Map<String, String> baseHeaders,
            String body,
            String region,
            String service) throws Exception {
        Map<String, String> unsignedHeaders = baseHeaders == null ? Map.of() : baseHeaders;
        ProbeResult unsigned = exchange(method, path, unsignedHeaders, body);
        if (unsigned.success()) {
            io.github.hectorvent.floci.fuzz.oracle.SecurityOracle.failSecurity(
                    target,
                    body,
                    "unsigned request succeeded under CTF profile",
                    Map.of("status", String.valueOf(unsigned.status()), "path", path));
        }

        Optional<ParticipantCredentials> creds = participantCredentials();
        if (creds.isEmpty()) {
            return;
        }

        Map<String, String> signed = ParticipantSigV4Signer.sign(
                endpoint,
                method,
                path,
                body,
                creds.get(),
                region,
                service,
                toSignedHeaderMap(unsignedHeaders));
        ProbeResult participant = exchange(method, path, signed, body);
        if (participant.success()) {
            Map<String, String> details = new LinkedHashMap<>();
            details.put("status", String.valueOf(participant.status()));
            details.put("path", path);
            details.put("body", participant.bodySnippet());
            io.github.hectorvent.floci.fuzz.oracle.SecurityOracle.failSecurity(
                    target,
                    body,
                    "participant unexpectedly allowed",
                    details);
        }
    }

    public void assertNeverSucceedsAsParticipant(
            String target,
            String method,
            String path,
            Map<String, String> participantHeaders,
            String body) throws Exception {
        ProbeResult participant = exchange(method, path, participantHeaders, body);
        if (participant.success()) {
            Map<String, String> details = new LinkedHashMap<>();
            details.put("status", String.valueOf(participant.status()));
            details.put("path", path);
            details.put("body", participant.bodySnippet());
            io.github.hectorvent.floci.fuzz.oracle.SecurityOracle.failSecurity(
                    target, body, "participant unexpectedly allowed", details);
        }
    }

    private static Map<String, String> toSignedHeaderMap(Map<String, String> headers) {
        Map<String, String> signed = new LinkedHashMap<>();
        if (headers == null) {
            return signed;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            if ("Authorization".equalsIgnoreCase(entry.getKey())) {
                continue;
            }
            signed.put(entry.getKey().toLowerCase(java.util.Locale.ROOT), entry.getValue());
        }
        return signed;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
