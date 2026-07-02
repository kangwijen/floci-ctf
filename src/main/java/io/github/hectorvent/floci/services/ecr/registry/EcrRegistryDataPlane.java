package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.RequestOptions;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Host-facing ECR registry proxy that validates docker-login tokens and enforces IAM
 * before streaming requests to the internal {@code registry:2} container.
 */
@ApplicationScoped
public class EcrRegistryDataPlane {

    private static final Logger LOG = Logger.getLogger(EcrRegistryDataPlane.class);

    private static final List<String> HOP_BY_HOP_HEADERS = List.of(
            "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailers",
            "proxy-authorization", "proxy-authenticate");

    @Inject
    Vertx vertx;

    @Inject
    EcrRegistryAuthService authService;

    @Inject
    EcrRegistryRouteResolver routeResolver;

    @Inject
    EcrRegistryAuthorizer authorizer;

    @Inject
    EmulatorConfig config;

    private HttpClient proxyClient;
    private volatile HttpServer server;
    private volatile int listenPort;
    private volatile String backendBaseUrl;

    public synchronized void start(int port, String backendBaseUrl) {
        if (server != null) {
            if (this.listenPort == port && this.backendBaseUrl.equals(backendBaseUrl)) {
                return;
            }
            stop();
        }
        this.listenPort = port;
        this.backendBaseUrl = backendBaseUrl;
        if (proxyClient == null) {
            proxyClient = vertx.createHttpClient(new HttpClientOptions()
                    .setMaxPoolSize(100)
                    .setConnectTimeout(5000)
                    .setKeepAlive(true));
        }

        HttpServer httpServer = vertx.createHttpServer(new HttpServerOptions()
                .setHost("0.0.0.0")
                .setPort(port));
        httpServer.requestHandler(this::handleRequest);

        AtomicReference<Throwable> bindFailure = new AtomicReference<>();
        httpServer.listen()
                .onSuccess(s -> {
                    this.server = s;
                    LOG.infov("ECR registry auth proxy listening on port {0} -> {1}",
                            String.valueOf(port), backendBaseUrl);
                })
                .onFailure(err -> {
                    bindFailure.set(err);
                    LOG.warnv("ECR registry auth proxy failed on port {0}: {1}",
                            String.valueOf(port), err.getMessage());
                });
        long deadline = System.currentTimeMillis() + 15_000;
        while (this.server == null && bindFailure.get() == null && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("ECR registry auth proxy start interrupted", e);
            }
        }
        if (bindFailure.get() != null) {
            throw new IllegalStateException(
                    "ECR registry auth proxy failed on port " + port, bindFailure.get());
        }
        if (this.server == null) {
            throw new IllegalStateException("ECR registry auth proxy timed out binding port " + port);
        }
    }

    public synchronized void stop() {
        if (server != null) {
            server.close();
            server = null;
        }
    }

    @PreDestroy
    void shutdown() {
        stop();
        if (proxyClient != null) {
            proxyClient.close();
            proxyClient = null;
        }
    }

    public boolean isRunning() {
        return server != null;
    }

    private void handleRequest(HttpServerRequest req) {
        String path = req.path() != null ? req.path() : "/";
        Optional<EcrRegistryRouteResolver.ResolvedRoute> routeOpt = routeResolver.resolve(
                req.method().name(), path, req.host(), routeResolver.usesPathUriStyle());
        if (routeOpt.isEmpty()) {
            req.response().setStatusCode(404).end("Not Found");
            return;
        }

        EcrRegistryRouteResolver.ResolvedRoute route = routeOpt.get();
        Optional<EcrRegistryAuthSession> session = authService.authenticate(req.getHeader("Authorization"));

        if (config.services().iam().enforcementEnabled()) {
            if (session.isEmpty()) {
                writeUnauthorized(req);
                return;
            }
            if (route.iamAction() != null && route.repositoryArn() != null) {
                Optional<String> denyReason = authorizer.authorize(session.get(), route);
                if (denyReason.isPresent()) {
                    req.response().setStatusCode(403).end("Denied");
                    return;
                }
            }
        }

        forward(req, route);
    }

    private void writeUnauthorized(HttpServerRequest req) {
        req.response()
                .setStatusCode(401)
                .putHeader("WWW-Authenticate", "Basic realm=\"Floci ECR Registry\"")
                .end("Unauthorized");
    }

    private void forward(HttpServerRequest req, EcrRegistryRouteResolver.ResolvedRoute route) {
        URI backend;
        try {
            backend = URI.create(backendBaseUrl);
        } catch (IllegalArgumentException e) {
            req.response().setStatusCode(502).end("Bad gateway");
            return;
        }

        String query = req.query();
        String forwardPath = route.backendPath();
        String uri = query != null && !query.isBlank() ? forwardPath + "?" + query : forwardPath;

        int backendPort = backend.getPort() > 0 ? backend.getPort() : 80;
        RequestOptions opts = new RequestOptions()
                .setMethod(req.method())
                .setHost(backend.getHost())
                .setPort(backendPort)
                .setURI(uri);

        proxyClient.request(opts)
                .onSuccess(clientReq -> {
                    req.headers().forEach(entry -> {
                        if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase())) {
                            clientReq.putHeader(entry.getKey(), entry.getValue());
                        }
                    });
                    clientReq.putHeader("Host", backend.getHost() + ":" + backendPort);
                    if (hasRequestBody(req)) {
                        clientReq.send(req)
                                .onSuccess(resp -> pipeResponse(req, resp))
                                .onFailure(err -> req.response().setStatusCode(502).end("Bad gateway"));
                    } else {
                        clientReq.send()
                                .onSuccess(resp -> pipeResponse(req, resp))
                                .onFailure(err -> req.response().setStatusCode(502).end("Bad gateway"));
                    }
                })
                .onFailure(err -> req.response().setStatusCode(503).end("Service unavailable"));
    }

    private static boolean hasRequestBody(HttpServerRequest req) {
        HttpMethod method = req.method();
        return method == HttpMethod.POST || method == HttpMethod.PUT || method == HttpMethod.PATCH;
    }

    private void pipeResponse(HttpServerRequest req, io.vertx.core.http.HttpClientResponse resp) {
        req.response().setStatusCode(resp.statusCode());
        String clientAuthority = clientAuthority(req);
        resp.headers().forEach(entry -> {
            String key = entry.getKey();
            if (HOP_BY_HOP_HEADERS.contains(key.toLowerCase(Locale.ROOT))) {
                return;
            }
            String value = entry.getValue();
            if ("location".equalsIgnoreCase(key)) {
                value = rewriteRegistryLocation(value, clientAuthority);
            }
            req.response().putHeader(key, value);
        });
        resp.pipeTo(req.response())
                .onFailure(err -> {
                    if (!req.response().ended()) {
                        req.response().setStatusCode(502).end("Bad gateway");
                    }
                });
    }

    private String clientAuthority(HttpServerRequest req) {
        String host = req.host();
        if (host != null && !host.isBlank()) {
            return host;
        }
        return "localhost:" + listenPort;
    }

    /**
     * Rewrites {@code Location} headers from the internal registry container so host-side
     * {@code docker push} continues against the published auth-proxy port.
     */
    static String rewriteRegistryLocation(String location, String clientAuthority, String backendBaseUrl,
                                          boolean tlsEnabled) {
        if (location == null || location.isBlank()) {
            return location;
        }
        String scheme = tlsEnabled ? "https" : "http";
        try {
            URI backend = URI.create(backendBaseUrl);
            URI loc = location.startsWith("/")
                    ? URI.create(scheme + "://" + clientAuthority + location)
                    : URI.create(location);
            if (loc.getHost() != null && backend.getHost() != null
                    && loc.getHost().equalsIgnoreCase(backend.getHost())
                    && samePort(loc, backend)) {
                String path = loc.getRawPath() != null ? loc.getRawPath() : "/";
                String query = loc.getRawQuery();
                String rebuilt = scheme + "://" + clientAuthority + path;
                if (query != null && !query.isBlank()) {
                    rebuilt += "?" + query;
                }
                return rebuilt;
            }
            if (location.startsWith("/")) {
                return scheme + "://" + clientAuthority + location;
            }
        } catch (IllegalArgumentException ignored) {
        }
        return location;
    }

    private String rewriteRegistryLocation(String location, String clientAuthority) {
        return rewriteRegistryLocation(location, clientAuthority, backendBaseUrl,
                config.services().ecr().tlsEnabled());
    }

    private static boolean samePort(URI location, URI backend) {
        int backendPort = backend.getPort() > 0 ? backend.getPort() : ("https".equalsIgnoreCase(backend.getScheme()) ? 443 : 80);
        int locationPort = location.getPort() > 0 ? location.getPort() : backendPort;
        return locationPort == backendPort;
    }
}
