package io.github.hectorvent.floci.services.apigatewayv2.proxy;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.OutboundUrlGuard;
import io.github.hectorvent.floci.core.common.PinnedEndpoint;
import io.github.hectorvent.floci.core.common.PinnedHttpResponse;
import io.github.hectorvent.floci.services.apigatewayv2.model.Integration;
import org.jboss.logging.Logger;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Invokes an HTTP_PROXY integration: builds the target URL from the integration's
 * IntegrationUri (with {placeholder} substitution from path params), seeds an
 * outgoing request with the inbound headers + query, applies RequestParameters
 * transformations, and forwards via pin-connect egress ({@link OutboundUrlGuard#sendPinned}).
 *
 * <p>Hop-by-hop headers (per RFC 7230 §6.1) are stripped from both the outgoing
 * request and the response.
 *
 * <p>If the backend is unreachable or times out, returns a 502 Bad Gateway
 * ProxyResult so the controller can relay a clean error to the original client.
 */
public class HttpProxyInvoker {
    private static final Logger LOG = Logger.getLogger(HttpProxyInvoker.class);

    /** RFC 7230 hop-by-hop headers that must not be forwarded across proxies. */
    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host");

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final RequestParameterMapper mapper = new RequestParameterMapper(new ContextValueResolver());
    private final OutboundUrlGuard outboundUrlGuard;

    public HttpProxyInvoker(OutboundUrlGuard outboundUrlGuard) {
        if (outboundUrlGuard == null) {
            throw new IllegalArgumentException("OutboundUrlGuard is required");
        }
        this.outboundUrlGuard = outboundUrlGuard;
    }

    public ProxyResult invoke(Integration integration, RequestContext ctx) {
        String resolvedUrl = PathTemplateResolver.resolve(integration.getIntegrationUri(), ctx.pathParams());

        String method = integration.getIntegrationMethod();
        if (method == null || method.isEmpty() || method.equalsIgnoreCase("ANY")) {
            method = ctx.httpMethod();
        }

        ProxyRequestBuilder builder = new ProxyRequestBuilder(resolvedUrl, method);
        if (ctx.requestHeaders() != null) {
            for (Map.Entry<String, String> e : ctx.requestHeaders().entrySet()) {
                if (!HOP_BY_HOP.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                    builder.overwriteHeader(e.getKey(), e.getValue());
                }
            }
        }
        if (ctx.queryParams() != null) {
            for (Map.Entry<String, String> e : ctx.queryParams().entrySet()) {
                builder.overwriteQuery(e.getKey(), e.getValue());
            }
        }
        builder.setBody(ctx.body());

        mapper.apply(integration.getRequestParameters(), builder, ctx);

        String finalUrl = buildFinalUrl(builder);
        PinnedEndpoint pinned;
        try {
            pinned = outboundUrlGuard.pinHttpUrl(finalUrl);
        } catch (IllegalArgumentException | AwsException e) {
            LOG.warnv("HTTP_PROXY target rejected: {0}", e.getMessage());
            return errorResult("Bad Gateway: " + e.getMessage());
        }

        Map<String, String> outboundHeaders = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : builder.headers().entrySet()) {
            String lower = e.getKey().toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(lower)) {
                continue;
            }
            if (!e.getValue().isEmpty()) {
                outboundHeaders.put(e.getKey(), e.getValue().get(0));
            }
        }

        try {
            PinnedHttpResponse resp = outboundUrlGuard.sendPinned(
                    pinned,
                    method,
                    builder.body(),
                    outboundHeaders,
                    firstHeader(builder, "Host"),
                    CONNECT_TIMEOUT,
                    REQUEST_TIMEOUT);
            Map<String, String> respHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : resp.headers().entrySet()) {
                if (HOP_BY_HOP.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                    continue;
                }
                respHeaders.put(e.getKey(), e.getValue());
            }
            return new ProxyResult(resp.statusCode(), respHeaders, resp.body());
        } catch (Exception e) {
            LOG.warnv("HTTP_PROXY backend call failed: {0}", e.getMessage());
            return errorResult("Bad Gateway: " + e.getMessage());
        }
    }

    private static String firstHeader(ProxyRequestBuilder builder, String headerName) {
        for (Map.Entry<String, List<String>> entry : builder.headers().entrySet()) {
            if (entry.getKey().equalsIgnoreCase(headerName) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    private static String buildFinalUrl(ProxyRequestBuilder builder) {
        if (builder.queryParams().isEmpty()) {
            return builder.url();
        }
        URI parsed = URI.create(builder.url());
        StringJoiner sj = new StringJoiner("&");
        if (parsed.getRawQuery() != null) {
            sj.add(parsed.getRawQuery());
        }
        for (Map.Entry<String, List<String>> e : builder.queryParams().entrySet()) {
            for (String v : e.getValue()) {
                sj.add(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(v, StandardCharsets.UTF_8));
            }
        }
        String base = builder.url().split("\\?")[0];
        return base + "?" + sj;
    }

    private static ProxyResult errorResult(String message) {
        String body = "{\"message\":\"" + message.replace("\"", "\\\"") + "\"}";
        return new ProxyResult(502,
                Map.of("Content-Type", "application/json"),
                body.getBytes(StandardCharsets.UTF_8));
    }
}
