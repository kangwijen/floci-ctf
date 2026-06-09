package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.IntSupplier;

/**
 * HTTP server exposing {@code /v2/credentials/{token}} for container workloads
 * (Lambda execution role, CodeBuild service role, ECS task role).
 */
public final class ContainerCredentialsHttpServer {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final String SESSION_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private final Logger log;
    private final Vertx vertx;
    private final EmulatorConfig config;
    private final IamService iamService;
    private final IntSupplier portSupplier;
    private final String label;

    private final Map<String, CredentialRegistration> tokenToRegistration = new ConcurrentHashMap<>();

    private volatile HttpServer httpServer;

    public ContainerCredentialsHttpServer(Vertx vertx, EmulatorConfig config, IamService iamService,
                                          IntSupplier portSupplier, String label) {
        this.vertx = vertx;
        this.config = config;
        this.iamService = iamService;
        this.portSupplier = portSupplier;
        this.label = label;
        this.log = Logger.getLogger(ContainerCredentialsHttpServer.class.getName() + "." + label);
    }

    /**
     * Registers a workload session and returns a credential token when {@code roleArn} is set.
     */
    public String register(String sessionName, String roleArn, String region) {
        if (roleArn == null || roleArn.isBlank()) {
            return null;
        }
        String token = UUID.randomUUID().toString();
        tokenToRegistration.put(token, new CredentialRegistration(sessionName, roleArn, region));
        log.debugv("{0} credentials: registered session {1} token {2}", label, sessionName, token);
        return token;
    }

    public void unregister(String sessionName, List<String> credentialTokens) {
        if (credentialTokens != null) {
            for (String token : credentialTokens) {
                if (token != null) {
                    tokenToRegistration.remove(token);
                }
            }
        }
        if (sessionName != null) {
            tokenToRegistration.entrySet().removeIf(e -> sessionName.equals(e.getValue().sessionName()));
        }
    }

    public String credentialsFullUri(String hostAddress, String credentialToken) {
        int port = portSupplier.getAsInt();
        return "http://" + hostAddress + ":" + port + "/v2/credentials/" + credentialToken;
    }

    public CompletableFuture<Void> start() {
        CompletableFuture<Void> future = new CompletableFuture<>();
        int port = portSupplier.getAsInt();

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.get("/v2/credentials/:token").handler(this::handleCredentials);

        httpServer = vertx.createHttpServer();
        httpServer.requestHandler(router).listen(port, result -> {
            if (result.succeeded()) {
                log.infof("%s container credentials server listening on port %d", label, port);
                future.complete(null);
            } else {
                log.warnf("%s container credentials server failed to start on port %d: %s",
                        label, port, result.cause().getMessage());
                future.completeExceptionally(result.cause());
            }
        });
        return future;
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.close();
            httpServer = null;
        }
        tokenToRegistration.clear();
    }

    private void handleCredentials(RoutingContext ctx) {
        String token = ctx.pathParam("token");
        CredentialRegistration registration = tokenToRegistration.get(token);
        if (registration == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }

        try {
            IamRole role = iamService.getRoleByArn(registration.roleArn());
            int durationSeconds = 3600;
            String accessKeyId = "ASIA" + randomId(16);
            String secretKey = randomSecret(40);
            String sessionToken = randomSecret(200);
            Instant expiration = Instant.now().plusSeconds(durationSeconds);
            String accountId = AwsArnUtils.accountOrDefault(role.getArn(), config.defaultAccountId());
            String sessionName = registration.sessionName() != null ? registration.sessionName() : label.toLowerCase();
            String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId,
                    "assumed-role/" + role.getRoleName() + "/" + sessionName).toString();
            String assumedRoleId = role.getRoleId() + ":" + sessionName;
            iamService.registerSession(accessKeyId, role.getArn(), expiration, null, secretKey,
                    assumedRoleId, assumedRoleArn, null, sessionToken);

            String body = "{\"AccessKeyId\":\"" + accessKeyId + "\","
                    + "\"SecretAccessKey\":\"" + secretKey + "\","
                    + "\"Token\":\"" + sessionToken + "\","
                    + "\"Expiration\":\"" + ISO.format(expiration) + "\","
                    + "\"RoleArn\":\"" + registration.roleArn() + "\"}";
            ctx.response().setStatusCode(200)
                    .putHeader("content-type", "application/json")
                    .end(body);
        } catch (Exception e) {
            log.warnv("{0} credentials: failed to issue credentials for session {1}: {2}",
                    label, registration.sessionName(), e.getMessage());
            ctx.response().setStatusCode(404).end();
        }
    }

    private static String randomId(int length) {
        StringBuilder sb = new StringBuilder(length);
        ThreadLocalRandom random = ThreadLocalRandom.current();
        for (int i = 0; i < length; i++) {
            sb.append(SESSION_CHARS.charAt(random.nextInt(SESSION_CHARS.length())));
        }
        return sb.toString();
    }

    private static String randomSecret(int length) {
        return randomId(length);
    }

    private record CredentialRegistration(String sessionName, String roleArn, String region) {
    }
}
