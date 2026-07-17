package io.github.hectorvent.floci.core.common;

import java.util.Map;

/** Minimal HTTP response from pin-connect egress ({@link OutboundUrlGuard#sendPinned}). */
public record PinnedHttpResponse(int statusCode, Map<String, String> headers, byte[] body) {
}
