package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Outbound HTTP SSRF guard: validate destinations and pin-connect (resolve once,
 * validate, connect to that IP with Host/SNI, {@link HttpClient.Redirect#NEVER}).
 */
@ApplicationScoped
public class OutboundUrlGuard {

    private static final List<String> BLOCKED_HOSTS = List.of(
            "localhost",
            "metadata",
            "metadata.google.internal");

    private static final Pattern TEMPLATE_VAR = Pattern.compile("\\{[^}/]+\\}");

    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host");

    private final boolean blockPrivateAddresses;
    private final List<String> hostAllowlist;
    private final boolean allowPrivateAddresses;
    private final HostResolver hostResolver;

    @Inject
    public OutboundUrlGuard(EmulatorConfig config) {
        this(
                AuthPosture.from(config).egressBlock(),
                config.ctf().outboundUrlHostAllowlist().orElse(List.of()),
                config.ctf().outboundAllowPrivateAddresses());
    }

    public OutboundUrlGuard(boolean blockPrivateAddresses, List<String> hostAllowlist,
                            boolean allowPrivateAddresses) {
        this(blockPrivateAddresses, hostAllowlist, allowPrivateAddresses, InetAddress::getAllByName);
    }

    public OutboundUrlGuard(boolean blockPrivateAddresses, List<String> hostAllowlist,
                            boolean allowPrivateAddresses, HostResolver hostResolver) {
        this.blockPrivateAddresses = blockPrivateAddresses;
        this.hostAllowlist = hostAllowlist == null ? List.of() : hostAllowlist.stream()
                .filter(host -> host != null && !host.isBlank())
                .map(host -> host.trim().toLowerCase(Locale.ROOT))
                .toList();
        this.allowPrivateAddresses = allowPrivateAddresses;
        this.hostResolver = hostResolver == null ? InetAddress::getAllByName : hostResolver;
    }

    /**
     * Create-time / subscribe-time check. Unresolved public hostnames are allowed when blocking
     * is on (delivery uses {@link #pinHttpUrl(String)} which resolves and pins).
     */
    public void validateHttpUrl(String url) {
        ParsedUrl parsed = parseHttpUrl(url);
        if (!blockPrivateAddresses) {
            return;
        }
        rejectBlockedHostname(parsed.normalizedHost());
        if (allowPrivateAddresses) {
            return;
        }

        if (isLiteralIpHost(parsed.normalizedHost())) {
            try {
                InetAddress address = InetAddress.getByName(parsed.normalizedHost());
                if (isBlockedAddress(address)) {
                    throw blocked("Outbound URL resolves to a non-public address.");
                }
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Outbound URL host cannot be resolved: " + parsed.host(), e);
            }
            return;
        }

        try {
            for (InetAddress address : hostResolver.resolve(parsed.host())) {
                if (isBlockedAddress(address)) {
                    throw blocked("Outbound URL resolves to a non-public address.");
                }
            }
        } catch (UnknownHostException ignored) {
            // Unresolved public hostnames are allowed at create time and fail later on pin/connect.
        }
    }

    /**
     * Resolve once, validate every address, return a pin for connect (IP URI + logical Host/SNI).
     */
    public PinnedEndpoint pinHttpUrl(String url) {
        ParsedUrl parsed = parseHttpUrl(url);
        if (blockPrivateAddresses) {
            rejectBlockedHostname(parsed.normalizedHost());
        }

        InetAddress[] addresses;
        try {
            addresses = hostResolver.resolve(parsed.host());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Outbound URL host cannot be resolved: " + parsed.host(), e);
        }
        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("Outbound URL host cannot be resolved: " + parsed.host());
        }

        if (blockPrivateAddresses && !allowPrivateAddresses) {
            for (InetAddress address : addresses) {
                if (isBlockedAddress(address)) {
                    throw blocked("Outbound URL resolves to a non-public address.");
                }
            }
        }

        InetAddress pinned = addresses[0];
        int port = parsed.uri().getPort();
        if (port < 0) {
            port = parsed.https() ? 443 : 80;
        }
        URI connectUri = buildConnectUri(parsed.uri(), pinned, port);
        return new PinnedEndpoint(parsed.uri(), connectUri, parsed.host(), pinned, port, parsed.https());
    }

    /**
     * Pin-connect: TCP to the validated IP, TLS SNI + Host header use the logical hostname.
     * Redirects are never followed (raw HTTP/1.1, single response).
     */
    public PinnedHttpResponse sendPinned(String url, String method, byte[] body,
                                         Map<String, String> headers, Duration connectTimeout,
                                         Duration requestTimeout) throws IOException {
        return sendPinned(pinHttpUrl(url), method, body, headers, null, connectTimeout, requestTimeout);
    }

    public PinnedHttpResponse sendPinned(PinnedEndpoint pinned, String method, byte[] body,
                                         Map<String, String> headers, String hostHeaderOverride,
                                         Duration connectTimeout, Duration requestTimeout)
            throws IOException {
        int connectMs = (int) Math.min(Integer.MAX_VALUE, Math.max(1, connectTimeout.toMillis()));
        int soTimeoutMs = (int) Math.min(Integer.MAX_VALUE, Math.max(1, requestTimeout.toMillis()));
        byte[] payload = body == null ? new byte[0] : body;
        String hostHeader = hostHeaderOverride == null || hostHeaderOverride.isBlank()
                ? pinned.hostHeader()
                : hostHeaderOverride;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(pinned.pinnedAddress(), pinned.port()), connectMs);
            socket.setSoTimeout(soTimeoutMs);

            Socket io = socket;
            if (pinned.https()) {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket ssl = (SSLSocket) factory.createSocket(
                        socket, pinned.hostname(), pinned.port(), true);
                SSLParameters params = ssl.getSSLParameters();
                params.setServerNames(List.of(new SNIHostName(pinned.hostname())));
                params.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(params);
                ssl.startHandshake();
                io = ssl;
            }

            String path = pinned.originalUri().getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (pinned.originalUri().getRawQuery() != null) {
                path = path + "?" + pinned.originalUri().getRawQuery();
            }

            StringBuilder request = new StringBuilder()
                    .append(method.toUpperCase(Locale.ROOT)).append(' ').append(path).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(hostHeader).append("\r\n")
                    .append("Connection: close\r\n");
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    String lower = header.getKey().toLowerCase(Locale.ROOT);
                    if (HOP_BY_HOP.contains(lower)) {
                        continue;
                    }
                    request.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            if (payload.length > 0) {
                request.append("Content-Length: ").append(payload.length).append("\r\n");
            }
            request.append("\r\n");

            OutputStream out = io.getOutputStream();
            out.write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(payload);
            out.flush();
            return readHttpResponse(io.getInputStream());
        }
    }

    /** Egress HttpClient: never follow redirects (defense in depth when not using {@link #sendPinned}). */
    public static HttpClient newEgressHttpClient(Duration connectTimeout) {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(connectTimeout)
                .build();
    }

    public boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (address instanceof Inet6Address) {
            return (bytes[0] & 0xfe) == 0xfc;
        }

        int first = Byte.toUnsignedInt(bytes[0]);
        int second = Byte.toUnsignedInt(bytes[1]);
        return (first == 100 && second == 100)
                || (first == 169 && second == 254 && Byte.toUnsignedInt(bytes[2]) == 169
                && Byte.toUnsignedInt(bytes[3]) == 254);
    }

    private void rejectBlockedHostname(String normalizedHost) {
        if (BLOCKED_HOSTS.contains(normalizedHost)) {
            throw blocked("Outbound URL host is not permitted.");
        }
        if (!hostAllowlist.isEmpty() && !hostMatchesAllowlist(normalizedHost)) {
            throw blocked("Outbound URL host is not in the configured allowlist.");
        }
    }

    private ParsedUrl parseHttpUrl(String url) {
        URI uri;
        try {
            String sanitized = TEMPLATE_VAR.matcher(url == null ? "" : url).replaceAll("x");
            uri = URI.create(sanitized);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Outbound URL is invalid: " + e.getMessage(), e);
        }

        String scheme = uri.getScheme();
        if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("Outbound URL must use http or https.");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Outbound URL must include a host.");
        }
        return new ParsedUrl(uri, host, host.toLowerCase(Locale.ROOT), "https".equalsIgnoreCase(scheme));
    }

    private static URI buildConnectUri(URI original, InetAddress pinned, int port) {
        String ipHost = formatIpHost(pinned);
        String path = original.getRawPath();
        if (path == null || path.isBlank()) {
            path = "";
        }
        String query = original.getRawQuery();
        StringBuilder sb = new StringBuilder();
        sb.append(original.getScheme()).append("://").append(ipHost).append(':').append(port).append(path);
        if (query != null) {
            sb.append('?').append(query);
        }
        return URI.create(sb.toString());
    }

    private static String formatIpHost(InetAddress address) {
        String hostAddress = address.getHostAddress();
        if (address instanceof Inet6Address) {
            int zone = hostAddress.indexOf('%');
            if (zone >= 0) {
                hostAddress = hostAddress.substring(0, zone);
            }
            return "[" + hostAddress + "]";
        }
        return hostAddress;
    }

    private static PinnedHttpResponse readHttpResponse(InputStream input) throws IOException {
        ByteArrayOutputStream headerBytes = new ByteArrayOutputStream();
        int previous3 = -1;
        int previous2 = -1;
        int previous1 = -1;
        int current;
        while ((current = input.read()) != -1) {
            headerBytes.write(current);
            if (previous3 == '\r' && previous2 == '\n' && previous1 == '\r' && current == '\n') {
                break;
            }
            previous3 = previous2;
            previous2 = previous1;
            previous1 = current;
        }

        String headersText = headerBytes.toString(StandardCharsets.ISO_8859_1);
        String[] lines = headersText.split("\r\n");
        if (lines.length == 0 || !lines[0].startsWith("HTTP/")) {
            throw new IOException("invalid HTTP response");
        }
        String[] status = lines[0].split(" ", 3);
        int statusCode = Integer.parseInt(status[1]);
        Map<String, String> headers = new LinkedHashMap<>();
        String transferEncoding = null;
        int contentLength = -1;
        for (int i = 1; i < lines.length; i++) {
            int separator = lines[i].indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = lines[i].substring(0, separator);
            String value = lines[i].substring(separator + 1).trim();
            if (name.equalsIgnoreCase("Transfer-Encoding")) {
                transferEncoding = value;
            }
            if (name.equalsIgnoreCase("Content-Length")) {
                contentLength = Integer.parseInt(value);
            }
            if (!HOP_BY_HOP.contains(name.toLowerCase(Locale.ROOT))) {
                headers.put(name, value);
            }
        }
        byte[] body = transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")
                ? readChunkedBody(input)
                : contentLength >= 0 ? input.readNBytes(contentLength) : input.readAllBytes();
        return new PinnedHttpResponse(statusCode, headers, body);
    }

    private static byte[] readChunkedBody(InputStream input) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readAsciiLine(input);
            if (sizeLine == null) {
                throw new IOException("unexpected end of chunked response");
            }
            int extension = sizeLine.indexOf(';');
            int size = Integer.parseInt((extension >= 0 ? sizeLine.substring(0, extension) : sizeLine).trim(), 16);
            if (size == 0) {
                while (true) {
                    String trailer = readAsciiLine(input);
                    if (trailer == null || trailer.isEmpty()) {
                        return body.toByteArray();
                    }
                }
            }
            body.write(input.readNBytes(size));
            expectCrlf(input);
        }
    }

    private static String readAsciiLine(InputStream input) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (true) {
            int b = input.read();
            if (b == -1) {
                return line.size() == 0 ? null : line.toString(StandardCharsets.ISO_8859_1);
            }
            if (b == '\n') {
                return line.toString(StandardCharsets.ISO_8859_1);
            }
            if (b == '\r') {
                int next = input.read();
                if (next == '\n') {
                    return line.toString(StandardCharsets.ISO_8859_1);
                }
                line.write(b);
                if (next != -1) {
                    line.write(next);
                }
                continue;
            }
            line.write(b);
        }
    }

    private static void expectCrlf(InputStream input) throws IOException {
        int cr = input.read();
        int lf = input.read();
        if (cr != '\r' || lf != '\n') {
            throw new IOException("invalid chunked response");
        }
    }

    private boolean hostMatchesAllowlist(String host) {
        return hostAllowlist.stream().anyMatch(allowed ->
                host.equals(allowed) || host.endsWith("." + allowed));
    }

    private static boolean isLiteralIpHost(String host) {
        if (host.startsWith("[") && host.endsWith("]")) {
            return true;
        }
        if (host.indexOf(':') >= 0) {
            return true;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static AwsException blocked(String message) {
        return new AwsException("InvalidParameter", message, 400);
    }

    private record ParsedUrl(URI uri, String host, String normalizedHost, boolean https) {
    }
}
