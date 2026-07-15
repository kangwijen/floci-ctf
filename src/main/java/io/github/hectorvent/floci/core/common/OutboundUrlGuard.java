package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@ApplicationScoped
public class OutboundUrlGuard {

    private static final List<String> BLOCKED_HOSTS = List.of(
            "localhost",
            "metadata",
            "metadata.google.internal");

    private static final Pattern TEMPLATE_VAR = Pattern.compile("\\{[^}/]+\\}");

    private final boolean blockPrivateAddresses;
    private final List<String> hostAllowlist;
    private final boolean allowPrivateAddresses;

    @Inject
    public OutboundUrlGuard(EmulatorConfig config) {
        this(
                config.ctf().blockPrivateOutboundUrls(),
                config.ctf().outboundUrlHostAllowlist().orElse(List.of()),
                config.ctf().outboundAllowPrivateAddresses());
    }

    public OutboundUrlGuard(boolean blockPrivateAddresses, List<String> hostAllowlist,
                            boolean allowPrivateAddresses) {
        this.blockPrivateAddresses = blockPrivateAddresses;
        this.hostAllowlist = hostAllowlist == null ? List.of() : hostAllowlist.stream()
                .filter(host -> host != null && !host.isBlank())
                .map(host -> host.trim().toLowerCase(Locale.ROOT))
                .toList();
        this.allowPrivateAddresses = allowPrivateAddresses;
    }

    public void validateHttpUrl(String url) {
        URI uri;
        try {
            // API Gateway HTTP integrations may store path/query template variables.
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

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (!blockPrivateAddresses) {
            return;
        }
        if (BLOCKED_HOSTS.contains(normalizedHost)) {
            throw blocked("Outbound URL host is not permitted.");
        }
        if (!hostAllowlist.isEmpty() && !hostMatchesAllowlist(normalizedHost)) {
            throw blocked("Outbound URL host is not in the configured allowlist.");
        }
        if (allowPrivateAddresses) {
            return;
        }

        if (isLiteralIpHost(normalizedHost)) {
            try {
                InetAddress address = InetAddress.getByName(normalizedHost);
                if (isBlockedAddress(address)) {
                    throw blocked("Outbound URL resolves to a non-public address.");
                }
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Outbound URL host cannot be resolved: " + host, e);
            }
            return;
        }

        try {
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(address)) {
                    throw blocked("Outbound URL resolves to a non-public address.");
                }
            }
        } catch (UnknownHostException ignored) {
            // Unresolved public hostnames are allowed at create time and fail later on connect.
        }
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
}
