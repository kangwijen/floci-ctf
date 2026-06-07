package io.github.hectorvent.floci.services.ecs.container;

import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
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

/**
 * ECS container credentials and task metadata HTTP server bound to port 9170 on the Floci host.
 * Task containers receive {@code AWS_CONTAINER_CREDENTIALS_FULL_URI} and
 * {@code ECS_CONTAINER_METADATA_URI_V4} pointing here when the task definition has a task role.
 */
@ApplicationScoped
public class EcsContainerCredentialsServer {

    private static final Logger LOG = Logger.getLogger(EcsContainerCredentialsServer.class);
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final String SESSION_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private final Vertx vertx;
    private final EmulatorConfig config;
    private final IamService iamService;

    /** credential token -> registration */
    private final Map<String, CredentialRegistration> tokenToRegistration = new ConcurrentHashMap<>();
    /** ECS task id -> metadata registration */
    private final Map<String, TaskMetadataRegistration> taskIdToMetadata = new ConcurrentHashMap<>();

    private volatile HttpServer httpServer;

    @Inject
    public EcsContainerCredentialsServer(Vertx vertx, EmulatorConfig config, IamService iamService) {
        this.vertx = vertx;
        this.config = config;
        this.iamService = iamService;
    }

    /**
     * Registers a task for metadata and returns a credential token when {@code taskRoleArn} is set.
     */
    public String registerTask(String taskArn, String taskId, String taskRoleArn,
                               String family, String region) {
        if (taskRoleArn == null || taskRoleArn.isBlank()) {
            return null;
        }
        String token = UUID.randomUUID().toString();
        CredentialRegistration registration = new CredentialRegistration(taskArn, taskId, taskRoleArn, region);
        tokenToRegistration.put(token, registration);
        taskIdToMetadata.put(taskId, new TaskMetadataRegistration(
                taskArn, taskId, taskRoleArn, family, region, token));
        LOG.debugv("ECS credentials: registered task {0} token {1}", taskId, token);
        return token;
    }

    public void unregisterTask(String taskId, List<String> credentialTokens) {
        if (taskId != null) {
            TaskMetadataRegistration metadata = taskIdToMetadata.remove(taskId);
            if (metadata != null && metadata.credentialToken() != null) {
                tokenToRegistration.remove(metadata.credentialToken());
            }
        }
        if (credentialTokens != null) {
            for (String token : credentialTokens) {
                if (token != null) {
                    tokenToRegistration.remove(token);
                }
            }
        }
    }

    public String credentialsFullUri(String hostAddress, String credentialToken) {
        int port = config.services().ecs().containerCredentialsPort();
        return "http://" + hostAddress + ":" + port + "/v2/credentials/" + credentialToken;
    }

    public String metadataUriV4(String hostAddress, String taskId) {
        int port = config.services().ecs().containerCredentialsPort();
        return "http://" + hostAddress + ":" + port + "/v4/" + taskId;
    }

    public CompletableFuture<Void> start() {
        CompletableFuture<Void> future = new CompletableFuture<>();
        int port = config.services().ecs().containerCredentialsPort();

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.get("/v2/credentials/:token").handler(this::handleCredentials);
        router.get("/v4/:taskId").handler(this::handleTaskMetadata);
        router.get("/v4/:taskId/task").handler(this::handleTaskMetadata);

        httpServer = vertx.createHttpServer();
        httpServer.requestHandler(router).listen(port, result -> {
            if (result.succeeded()) {
                LOG.infof("ECS container credentials server listening on port %d", port);
                future.complete(null);
            } else {
                LOG.warnf("ECS container credentials server failed to start on port %d: %s",
                        port, result.cause().getMessage());
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
        taskIdToMetadata.clear();
    }

    private void handleCredentials(RoutingContext ctx) {
        String token = ctx.pathParam("token");
        CredentialRegistration registration = tokenToRegistration.get(token);
        if (registration == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }

        try {
            IamRole role = iamService.getRoleByArn(registration.taskRoleArn());
            int durationSeconds = 3600;
            String accessKeyId = "ASIA" + randomId(16);
            String secretKey = randomSecret(40);
            String sessionToken = randomSecret(200);
            Instant expiration = Instant.now().plusSeconds(durationSeconds);
            String accountId = AwsArnUtils.accountOrDefault(role.getArn(), config.defaultAccountId());
            String sessionName = registration.taskId() != null ? registration.taskId() : "ecs-task";
            String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId,
                    "assumed-role/" + role.getRoleName() + "/" + sessionName).toString();
            String assumedRoleId = role.getRoleId() + ":" + sessionName;
            iamService.registerSession(accessKeyId, role.getArn(), expiration, null, secretKey,
                    assumedRoleId, assumedRoleArn);

            String body = "{\"AccessKeyId\":\"" + accessKeyId + "\","
                    + "\"SecretAccessKey\":\"" + secretKey + "\","
                    + "\"Token\":\"" + sessionToken + "\","
                    + "\"Expiration\":\"" + ISO.format(expiration) + "\","
                    + "\"RoleArn\":\"" + registration.taskRoleArn() + "\"}";
            ctx.response().setStatusCode(200)
                    .putHeader("content-type", "application/json")
                    .end(body);
        } catch (Exception e) {
            LOG.warnv("ECS credentials: failed to issue credentials for task {0}: {1}",
                    registration.taskId(), e.getMessage());
            ctx.response().setStatusCode(404).end();
        }
    }

    private void handleTaskMetadata(RoutingContext ctx) {
        String taskId = ctx.pathParam("taskId");
        TaskMetadataRegistration metadata = taskIdToMetadata.get(taskId);
        if (metadata == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }
        String body = "{\"Cluster\":\"default\","
                + "\"TaskARN\":\"" + metadata.taskArn() + "\","
                + "\"Family\":\"" + escapeJson(metadata.family()) + "\","
                + "\"DesiredStatus\":\"RUNNING\","
                + "\"KnownStatus\":\"RUNNING\","
                + "\"LaunchType\":\"FARGATE\","
                + "\"TaskRoleArn\":\"" + metadata.taskRoleArn() + "\","
                + "\"Region\":\"" + metadata.region() + "\"}";
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(body);
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
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

    private record CredentialRegistration(String taskArn, String taskId, String taskRoleArn, String region) {
    }

    private record TaskMetadataRegistration(String taskArn, String taskId, String taskRoleArn,
                                            String family, String region, String credentialToken) {
    }
}
