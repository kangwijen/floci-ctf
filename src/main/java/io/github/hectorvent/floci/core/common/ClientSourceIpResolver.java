package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;

/**
 * Resolves the client IP used for CloudTrail {@code sourceIPAddress} and S3 server access log
 * Remote IP so both evidence surfaces stay aligned under the same header and socket rules.
 */
public final class ClientSourceIpResolver {

    private ClientSourceIpResolver() {
    }

    public static String resolve(EmulatorConfig config,
                                 String stampedSourceIpHeader,
                                 String forwardedForHeader,
                                 String socketPeerHost) {
        if (config.ctf().cloudTrailAllowSourceIpHeader()) {
            String stamped = stampedSourceIpHeader;
            if (stamped != null && !stamped.isBlank()) {
                return normalizeLoopback(stamped.trim());
            }
        }
        if (config.auth().trustForwardedHeaders()) {
            String forwarded = forwardedForHeader;
            if (forwarded != null && !forwarded.isBlank()) {
                String sourceIp = forwarded;
                int comma = sourceIp.indexOf(',');
                if (comma > 0) {
                    sourceIp = sourceIp.substring(0, comma).trim();
                }
                return normalizeLoopback(sourceIp);
            }
        }
        if (socketPeerHost != null && !socketPeerHost.isBlank()) {
            return normalizeLoopback(socketPeerHost);
        }
        return "127.0.0.1";
    }

    static String normalizeLoopback(String ip) {
        if ("::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "127.0.0.1";
        }
        return ip;
    }
}
