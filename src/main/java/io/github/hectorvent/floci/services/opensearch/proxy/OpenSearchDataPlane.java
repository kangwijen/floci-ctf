package io.github.hectorvent.floci.services.opensearch.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import io.github.hectorvent.floci.services.opensearch.model.AdvancedSecurityOptions;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.RequestOptions;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Host-facing OpenSearch domain HTTP AuthProxy. Validates SigV4 / FGAC before
 * forwarding to the internal OpenSearch container.
 */
@ApplicationScoped
public class OpenSearchDataPlane {

    private static final Logger LOG = Logger.getLogger(OpenSearchDataPlane.class);

    private static final List<String> HOP_BY_HOP_HEADERS = List.of(
            "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailers",
            "proxy-authorization", "proxy-authenticate");

    private final Vertx vertx;
    private final EmulatorConfig config;
    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final ResourcePolicyResolver resourcePolicyResolver;

    private HttpClient proxyClient;
    private final ConcurrentHashMap<String, DomainProxy> proxies = new ConcurrentHashMap<>();

    @Inject
    public OpenSearchDataPlane(Vertx vertx,
                               EmulatorConfig config,
                               IamService iamService,
                               IamPolicyEvaluator evaluator,
                               ResourcePolicyResolver resourcePolicyResolver) {
        this.vertx = vertx;
        this.config = config;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.resourcePolicyResolver = resourcePolicyResolver;
    }

    public synchronized void start(String domainName, int listenPort, String backendBaseUrl,
                                   String domainArn, AdvancedSecurityOptions advancedSecurity) {
        stop(domainName);
        if (proxyClient == null) {
            proxyClient = vertx.createHttpClient(new HttpClientOptions()
                    .setMaxPoolSize(100)
                    .setConnectTimeout(5000)
                    .setKeepAlive(true));
        }

        HttpServer httpServer = vertx.createHttpServer(new HttpServerOptions()
                .setHost("0.0.0.0")
                .setPort(listenPort));
        DomainProxy domainProxy = new DomainProxy(domainName, backendBaseUrl, domainArn, advancedSecurity);
        httpServer.requestHandler(req -> handleRequest(req, domainProxy));

        AtomicReference<Throwable> bindFailure = new AtomicReference<>();
        httpServer.listen()
                .onSuccess(s -> {
                    domainProxy.server = s;
                    proxies.put(domainName, domainProxy);
                    LOG.infov("OpenSearch AuthProxy listening on port {0} for domain {1} -> {2}",
                            String.valueOf(listenPort), domainName, backendBaseUrl);
                })
                .onFailure(err -> {
                    bindFailure.set(err);
                    LOG.warnv("OpenSearch AuthProxy failed on port {0}: {1}",
                            String.valueOf(listenPort), err.getMessage());
                });
        long deadline = System.currentTimeMillis() + 15_000;
        while (domainProxy.server == null && bindFailure.get() == null
                && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("OpenSearch AuthProxy start interrupted", e);
            }
        }
        if (bindFailure.get() != null) {
            throw new IllegalStateException(
                    "OpenSearch AuthProxy failed on port " + listenPort, bindFailure.get());
        }
        if (domainProxy.server == null) {
            throw new IllegalStateException("OpenSearch AuthProxy timed out binding port " + listenPort);
        }
    }

    public synchronized void stop(String domainName) {
        DomainProxy proxy = proxies.remove(domainName);
        if (proxy != null && proxy.server != null) {
            proxy.server.close();
        }
    }

    public synchronized void stopAll() {
        for (String name : List.copyOf(proxies.keySet())) {
            stop(name);
        }
        if (proxyClient != null) {
            proxyClient.close();
            proxyClient = null;
        }
    }

    @PreDestroy
    void shutdown() {
        stopAll();
    }

    private void handleRequest(HttpServerRequest req, DomainProxy domain) {
        boolean enforcement = config.services().iam().enforcementEnabled();
        boolean fgac = domain.advancedSecurity != null && domain.advancedSecurity.isEnabled();

        if (enforcement || fgac) {
            Optional<String> deny = authorize(req, domain, enforcement, fgac);
            if (deny.isPresent()) {
                int code = deny.get().startsWith("unauthorized") ? 401 : 403;
                req.response().setStatusCode(code).end(deny.get());
                return;
            }
        }

        forward(req, domain);
    }

    private Optional<String> authorize(HttpServerRequest req, DomainProxy domain,
                                       boolean enforcement, boolean fgac) {
        String authorization = req.getHeader("Authorization");
        if (authorization == null || authorization.isBlank()) {
            return Optional.of("unauthorized: missing Authorization");
        }

        if (authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            if (!fgac) {
                return Optional.of("unauthorized: Basic auth requires FGAC");
            }
            return authorizeFgacBasic(authorization, domain);
        }

        if (!authorization.regionMatches(true, 0, "AWS4-HMAC-SHA256 ", 0, 16)) {
            return Optional.of("unauthorized: SigV4 or FGAC Basic required");
        }

        if (!enforcement && !fgac) {
            return Optional.empty();
        }

        return authorizeSigV4(req, domain, authorization, enforcement);
    }

    private Optional<String> authorizeFgacBasic(String authorization, DomainProxy domain) {
        try {
            String decoded = new String(Base64.getDecoder().decode(
                    authorization.substring(6).trim()), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) {
                return Optional.of("unauthorized: malformed Basic auth");
            }
            String user = decoded.substring(0, colon);
            AdvancedSecurityOptions.MasterUserOptions master =
                    domain.advancedSecurity != null ? domain.advancedSecurity.getMasterUserOptions() : null;
            if (master == null || master.getMasterUserName() == null
                    || !master.getMasterUserName().equals(user)) {
                return Optional.of("forbidden: FGAC master user mismatch");
            }
            return Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.of("unauthorized: malformed Basic auth");
        }
    }

    private Optional<String> authorizeSigV4(HttpServerRequest req, DomainProxy domain,
                                            String authorization, boolean enforcement) {
        String accessKeyId = extractAccessKeyId(authorization);
        if (accessKeyId == null) {
            return Optional.of("unauthorized: malformed SigV4");
        }

        Optional<String> secretOpt = iamService.findSecretKey(accessKeyId);
        if (secretOpt.isEmpty()
                && config.auth().rootAccessKeyId().filter(accessKeyId::equals).isPresent()) {
            secretOpt = config.auth().resolveRootSecretAccessKey();
        }
        if (secretOpt.isEmpty()) {
            return Optional.of("unauthorized: unknown access key");
        }

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        req.headers().forEach(e -> headers.add(e.getKey(), e.getValue()));
        String path = req.path() != null ? req.path() : "/";
        String query = req.query();
        byte[] body = new byte[0];

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                req.method().name(), path, query != null ? query : "",
                headers, authorization, secretOpt.get(), body);
        if (result != SigV4RequestValidator.Result.VALID) {
            return Optional.of("unauthorized: invalid SigV4 (" + result + ")");
        }

        if (!enforcement) {
            return Optional.empty();
        }

        if (config.auth().rootAccessKeyId().filter(accessKeyId::equals).isPresent()) {
            return Optional.empty();
        }

        String action = httpMethodToEsAction(req.method());
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
            return Optional.empty();
        }

        CallerContext caller = iamService.resolveCallerContext(accessKeyId);
        if (caller == null) {
            return Optional.of("forbidden: unknown caller");
        }

        List<String> resourcePolicies = resourcePolicyResolver.resolve(
                "es", domain.domainArn, extractRegion(authorization));
        Map<String, String> conditionCtx = buildConditionContext(accessKeyId);

        Decision decision = evaluator.evaluate(
                caller, resourcePolicies, action, domain.domainArn, conditionCtx);
        if (decision == Decision.DENY) {
            LOG.infov("OpenSearch data-plane IAM DENY: akid={0} action={1} resource={2}",
                    accessKeyId, action, domain.domainArn);
            return Optional.of("forbidden: access denied");
        }
        return Optional.empty();
    }

    private void forward(HttpServerRequest req, DomainProxy domain) {
        URI backend;
        try {
            backend = URI.create(domain.backendBaseUrl);
        } catch (IllegalArgumentException e) {
            req.response().setStatusCode(502).end("Bad gateway");
            return;
        }

        String query = req.query();
        String forwardPath = req.path() != null ? req.path() : "/";
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
                        if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
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
                .onFailure(err -> req.response().setStatusCode(502).end("Bad gateway"));
    }

    private static void pipeResponse(HttpServerRequest req, io.vertx.core.http.HttpClientResponse resp) {
        req.response().setStatusCode(resp.statusCode());
        resp.headers().forEach(entry -> {
            if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
                req.response().putHeader(entry.getKey(), entry.getValue());
            }
        });
        resp.body()
                .onSuccess(buf -> req.response().end(buf))
                .onFailure(err -> req.response().setStatusCode(502).end("Bad gateway"));
    }

    private static boolean hasRequestBody(HttpServerRequest req) {
        HttpMethod m = req.method();
        return m == HttpMethod.POST || m == HttpMethod.PUT || m == HttpMethod.PATCH
                || m == HttpMethod.DELETE;
    }

    private static String httpMethodToEsAction(HttpMethod method) {
        if (method == HttpMethod.GET) {
            return "es:ESHttpGet";
        }
        if (method == HttpMethod.HEAD) {
            return "es:ESHttpHead";
        }
        if (method == HttpMethod.POST) {
            return "es:ESHttpPost";
        }
        if (method == HttpMethod.PUT) {
            return "es:ESHttpPut";
        }
        if (method == HttpMethod.DELETE) {
            return "es:ESHttpDelete";
        }
        return "es:ESHttpGet";
    }

    private static String extractAccessKeyId(String authorization) {
        int credIdx = authorization.indexOf("Credential=");
        if (credIdx < 0) {
            return null;
        }
        int start = credIdx + "Credential=".length();
        int end = authorization.indexOf('/', start);
        if (end < 0) {
            end = authorization.indexOf(',', start);
        }
        if (end < 0) {
            return null;
        }
        return authorization.substring(start, end).trim();
    }

    private static String extractRegion(String authorization) {
        int credIdx = authorization.indexOf("Credential=");
        if (credIdx < 0) {
            return "us-east-1";
        }
        String cred = authorization.substring(credIdx + "Credential=".length()).split(",")[0].trim();
        String[] full = cred.split("/");
        if (full.length >= 3) {
            return full[2];
        }
        return "us-east-1";
    }

    private Map<String, String> buildConditionContext(String accessKeyId) {
        Map<String, String> out = new HashMap<>();
        String accountId = "000000000000";
        Optional<CallerIdentity> identity = iamService.resolveCallerIdentity(
                accessKeyId, accountId, config.auth().rootAccessKeyId());
        String principalArn = identity.map(CallerIdentity::arn)
                .orElse("arn:aws:iam::" + accountId + ":root");
        String principalAccount = identity.map(CallerIdentity::account).orElse(accountId);
        out.put("aws:principalarn", principalArn);
        out.put("aws:principalaccount", principalAccount);
        out.put("aws:sourceaccount", principalAccount);
        out.put("aws:sourcearn", principalArn);
        identity.map(CallerIdentity::userId).ifPresent(id -> out.put("aws:userid", id));
        out.put("aws:sourceip", "127.0.0.1");
        return out;
    }

    private static final class DomainProxy {
        final String domainName;
        final String backendBaseUrl;
        final String domainArn;
        final AdvancedSecurityOptions advancedSecurity;
        volatile HttpServer server;

        DomainProxy(String domainName, String backendBaseUrl, String domainArn,
                    AdvancedSecurityOptions advancedSecurity) {
            this.domainName = domainName;
            this.backendBaseUrl = backendBaseUrl;
            this.domainArn = domainArn;
            this.advancedSecurity = advancedSecurity;
        }
    }
}
