package io.github.hectorvent.floci.services.iot;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iot.model.IotCertificate;
import io.github.hectorvent.floci.services.iot.model.IotPolicy;
import io.github.hectorvent.floci.services.iot.model.IotRetainedMessage;
import io.netty.handler.codec.mqtt.MqttConnectReturnCode;
import io.netty.handler.codec.mqtt.MqttQoS;
import io.vertx.mqtt.MqttAuth;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.net.SocketAddress;
import io.vertx.mqtt.MqttEndpoint;
import io.vertx.mqtt.MqttServer;
import io.vertx.mqtt.MqttServerOptions;
import io.vertx.mqtt.messages.MqttPublishMessage;
import io.vertx.mqtt.messages.MqttSubscribeMessage;
import io.vertx.mqtt.messages.MqttUnsubscribeMessage;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class IotMqttBrokerService {

    private static final Logger LOG = Logger.getLogger(IotMqttBrokerService.class);

    private final EmulatorConfig config;
    private final Vertx vertx;
    private final Instance<IotService> iotService;
    private final IamService iamService;
    private final IamPolicyEvaluator policyEvaluator;
    private final RegionResolver regionResolver;
    private final Map<String, ClientSession> sessionsByClient = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Subscription>> subscriptionsByClient = new ConcurrentHashMap<>();
    private MqttServer server;

    @Inject
    public IotMqttBrokerService(EmulatorConfig config, Vertx vertx, Instance<IotService> iotService,
                                IamService iamService, IamPolicyEvaluator policyEvaluator,
                                RegionResolver regionResolver) {
        this.config = config;
        this.vertx = vertx;
        this.iotService = iotService;
        this.iamService = iamService;
        this.policyEvaluator = policyEvaluator;
        this.regionResolver = regionResolver;
    }

    void onStart(@Observes StartupEvent ignored) {
        if (!config.services().iot().enabled() || !config.services().iot().mqtt().enabled()) {
            LOG.info("IoT MQTT broker disabled by configuration");
            return;
        }
        if (!config.services().iot().mqtt().autoStart()) {
            LOG.info("IoT MQTT broker auto-start disabled by configuration");
            return;
        }
        startIfEnabled();
    }

    void onStop(@Observes ShutdownEvent ignored) {
        stop();
    }

    synchronized void startIfEnabled() {
        if (!config.services().iot().enabled() || !config.services().iot().mqtt().enabled()) {
            return;
        }
        if (server != null) {
            return;
        }

        MqttServer mqttServer = MqttServer.create(vertx, new MqttServerOptions()
                .setHost(config.services().iot().mqtt().host())
                .setPort(config.services().iot().mqtt().port()));
        mqttServer.endpointHandler(this::handleEndpoint);
        mqttServer.exceptionHandler(error -> LOG.warnv("IoT MQTT broker error: {0}", error.getMessage()));

        try {
            mqttServer.listen().toCompletionStage().toCompletableFuture().join();
            server = mqttServer;
            LOG.infov("IoT MQTT broker started on {0}:{1}",
                    config.services().iot().mqtt().host(), config.services().iot().mqtt().port());
        } catch (Exception e) {
            mqttServer.close();
            throw new IllegalStateException("Failed to start IoT MQTT broker", e);
        }
    }

    synchronized void stop() {
        MqttServer mqttServer = server;
        if (mqttServer == null) {
            return;
        }
        server = null;
        sessionsByClient.values().forEach(session -> session.endpoint().close());
        sessionsByClient.clear();
        subscriptionsByClient.clear();
        mqttServer.close().toCompletionStage().toCompletableFuture().join();
        LOG.info("IoT MQTT broker stopped");
    }

    public synchronized boolean isRunning() {
        return server != null;
    }

    void publish(String topic, byte[] payload) {
        if (server == null) {
            return;
        }
        fanOut(topic, payload == null ? new byte[0] : payload, false);
    }

    boolean disconnectClient(String clientId, boolean cleanSession) {
        ClientSession session = sessionsByClient.remove(clientId);
        if (session == null) {
            return false;
        }
        if (cleanSession) {
            subscriptionsByClient.remove(clientId);
        }
        session.endpoint().close();
        return true;
    }

    Optional<ConnectionInfo> getConnection(String clientId) {
        if (server == null) {
            return Optional.empty();
        }
        ClientSession session = sessionsByClient.get(clientId);
        if (session == null || !session.endpoint().isConnected()) {
            return Optional.empty();
        }
        return Optional.of(new ConnectionInfo(session.clientId(), session.sourceIp(), session.sourcePort()));
    }

    List<String> listSubscriptions(String clientId) {
        return subscriptionsByClient.getOrDefault(clientId, Map.of()).keySet().stream()
                .sorted()
                .toList();
    }

    /**
     * Coarse CTF MQTT CONNECT gate. When IAM enforcement is on, CONNECT with a fully anonymous
     * (null/blank) username is rejected outright. This is only the first layer — {@link
     * #resolvePrincipal} performs the real credential check, since a merely non-blank username
     * used to be treated as authenticated.
     */
    public static boolean allowMqttConnect(boolean enforcementEnabled, String username) {
        if (!enforcementEnabled) {
            return true;
        }
        return username != null && !username.isBlank();
    }

    /**
     * Resolves the CONNECT principal from the username/password fields.
     *
     * <p>CTF-safe simplification: full per-packet SigV4 signature verification (as real AWS IoT
     * device SDKs perform over MQTT) is not implemented. Credential shapes accepted:
     * <ul>
     *   <li>the configured root access key with a password matching the root secret</li>
     *   <li>username = a known IAM access key ID with a password matching the stored secret
     *       access key, authorized against that identity's IAM policies</li>
     *   <li>username = a known, ACTIVE IoT certificate ID or ARN, authorized against the IoT
     *       policies attached to that certificate</li>
     * </ul>
     * AKID paths fail closed when the stored secret is missing or the password does not match.
     * Full MQTT SigV4 / {@code iot:Connect} parity remains out of scope.
     */
    ConnectPrincipal resolvePrincipal(String username, String password) {
        if (username == null || username.isBlank()) {
            return null;
        }
        if (config.auth().rootAccessKeyId().filter(username::equals).isPresent()) {
            Optional<String> rootSecret = config.auth().resolveRootSecretAccessKey();
            if (rootSecret.isEmpty() || !secretsMatch(password, rootSecret.get())) {
                return null;
            }
            return ConnectPrincipal.unrestricted("root:" + username);
        }
        if (password != null && !password.isBlank()) {
            CallerContext caller = iamService.resolveCallerContext(username);
            if (caller != null) {
                Optional<String> storedSecret = iamService.findSecretKey(username);
                if (storedSecret.isEmpty() || !secretsMatch(password, storedSecret.get())) {
                    return null;
                }
                return ConnectPrincipal.scoped("iam:" + username, caller.identityPolicies());
            }
        }
        return resolveCertificatePrincipal(username);
    }

    /** Constant-time compare of MQTT password to a stored secret access key. */
    static boolean secretsMatch(String provided, String stored) {
        if (provided == null || stored == null) {
            return false;
        }
        byte[] a = provided.getBytes(StandardCharsets.UTF_8);
        byte[] b = stored.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }

    private ConnectPrincipal resolveCertificatePrincipal(String certificateIdentifier) {
        String certificateId = certificateIdentifier.contains(":cert/")
                ? certificateIdentifier.substring(certificateIdentifier.indexOf(":cert/") + ":cert/".length())
                : certificateIdentifier;
        IotCertificate certificate;
        try {
            certificate = iotService.get().describeCertificate(certificateId, regionResolver.getDefaultRegion());
        } catch (RuntimeException e) {
            return null;
        }
        if (!"ACTIVE".equals(certificate.getStatus())) {
            return null;
        }
        List<String> policies = iotService.get()
                .listAttachedPolicies(certificate.getCertificateArn(), regionResolver.getDefaultRegion())
                .stream()
                .map(IotPolicy::getPolicyDocument)
                .filter(doc -> doc != null && !doc.isBlank())
                .toList();
        return ConnectPrincipal.scoped("cert:" + certificateId, policies);
    }

    private boolean isAuthorized(ClientSession session, String action, String resourceArn) {
        if (!config.services().iam().enforcementEnabled()) {
            return true;
        }
        ConnectPrincipal principal = session.principal();
        return principal != null && principal.isAuthorized(policyEvaluator, action, resourceArn);
    }

    private String topicArn(String resourceSuffix) {
        return regionResolver.buildArn("iot", regionResolver.getDefaultRegion(), resourceSuffix);
    }

    private void handleEndpoint(MqttEndpoint endpoint) {
        String clientId = endpoint.clientIdentifier();
        MqttAuth auth = endpoint.auth();
        String username = auth == null ? null : auth.getUsername();
        String password = auth == null ? null : auth.getPassword();
        boolean enforcementEnabled = config.services().iam().enforcementEnabled();
        if (!allowMqttConnect(enforcementEnabled, username)) {
            LOG.warnv("IoT MQTT CONNECT rejected: missing username under IAM enforcement (clientId={0})",
                    clientId);
            endpoint.reject(MqttConnectReturnCode.CONNECTION_REFUSED_NOT_AUTHORIZED);
            return;
        }

        ConnectPrincipal principal = null;
        if (enforcementEnabled) {
            principal = resolvePrincipal(username, password);
            if (principal == null) {
                LOG.warnv("IoT MQTT CONNECT rejected: username did not resolve to a known IAM "
                        + "credential or an active IoT certificate (clientId={0})", clientId);
                endpoint.reject(MqttConnectReturnCode.CONNECTION_REFUSED_BAD_USER_NAME_OR_PASSWORD);
                return;
            }
        }

        SocketAddress remoteAddress = endpoint.remoteAddress();
        ClientSession session = new ClientSession(
                clientId,
                endpoint,
                remoteAddress == null ? null : remoteAddress.host(),
                remoteAddress == null ? -1 : remoteAddress.port(),
                endpoint.isCleanSession(),
                principal);

        endpoint.subscriptionAutoAck(false);
        endpoint.publishAutoAck(false);
        endpoint.exceptionHandler(error -> LOG.warnv("IoT MQTT client {0} error: {1}", clientId, error.getMessage()));
        endpoint.subscribeHandler(message -> handleSubscribe(session, message));
        endpoint.unsubscribeHandler(message -> handleUnsubscribe(session, message));
        endpoint.publishHandler(message -> handlePublish(session, message));
        endpoint.disconnectHandler(ignored -> removeSession(session));
        endpoint.closeHandler(ignored -> removeSession(session));

        ClientSession previous = sessionsByClient.put(clientId, session);
        if (previous != null && previous.endpoint() != endpoint) {
            previous.endpoint().close();
        }

        endpoint.accept();
    }

    private void handleSubscribe(ClientSession session, MqttSubscribeMessage message) {
        Map<String, Subscription> clientSubscriptions = subscriptionsByClient.computeIfAbsent(
                session.clientId(), ignored -> new ConcurrentHashMap<>());
        List<MqttQoS> grantedQos = new ArrayList<>();
        List<Subscription> accepted = new ArrayList<>();

        for (io.vertx.mqtt.MqttTopicSubscription requested : message.topicSubscriptions()) {
            String topicFilter = requested.topicName();
            MqttQoS qos = requested.qualityOfService();
            if (!isValidTopicFilter(topicFilter) || qos == MqttQoS.EXACTLY_ONCE
                    || !isAuthorized(session, "iot:Subscribe", topicArn("topicfilter/" + topicFilter))) {
                grantedQos.add(MqttQoS.FAILURE);
                continue;
            }

            int granted = qos == MqttQoS.AT_LEAST_ONCE ? 1 : 0;
            Subscription subscription = new Subscription(topicFilter, granted);
            clientSubscriptions.put(topicFilter, subscription);
            accepted.add(subscription);
            grantedQos.add(granted == 1 ? MqttQoS.AT_LEAST_ONCE : MqttQoS.AT_MOST_ONCE);
        }

        session.endpoint().subscribeAcknowledge(message.messageId(), grantedQos);
        deliverRetained(session, accepted);
    }

    private void handleUnsubscribe(ClientSession session, MqttUnsubscribeMessage message) {
        Map<String, Subscription> clientSubscriptions = subscriptionsByClient.get(session.clientId());
        if (clientSubscriptions != null) {
            for (String topic : message.topics()) {
                clientSubscriptions.remove(topic);
            }
            if (clientSubscriptions.isEmpty()) {
                subscriptionsByClient.remove(session.clientId(), clientSubscriptions);
            }
        }
        session.endpoint().unsubscribeAcknowledge(message.messageId());
    }

    private void handlePublish(ClientSession session, MqttPublishMessage message) {
        byte[] payload = message.payload().getBytes();
        if (message.qosLevel() == MqttQoS.EXACTLY_ONCE) {
            session.endpoint().close();
            return;
        }
        if (message.qosLevel() == MqttQoS.AT_LEAST_ONCE) {
            session.endpoint().publishAcknowledge(message.messageId());
        }

        String topic = message.topicName();
        if (!isAuthorized(session, "iot:Publish", topicArn("topic/" + topic))) {
            LOG.warnv("IoT MQTT PUBLISH denied: clientId={0} topic={1}", session.clientId(), topic);
            return;
        }

        if (topic.startsWith("$aws/")) {
            iotService.get().handleReservedMqttPublish(topic, payload, this::publish);
            return;
        }

        iotService.get().publish(topic, payload, message.isRetain(), message.qosLevel().value());
        fanOut(topic, payload, false);
    }

    private void fanOut(String topic, byte[] payload, boolean retained) {
        byte[] safePayload = payload == null ? new byte[0] : payload.clone();
        for (ClientSession session : sessionsByClient.values()) {
            if (!session.endpoint().isConnected() || !hasMatchingSubscription(session.clientId(), topic)) {
                continue;
            }
            if (!isAuthorized(session, "iot:Receive", topicArn("topic/" + topic))) {
                LOG.warnv("IoT MQTT RECEIVE denied: clientId={0} topic={1}", session.clientId(), topic);
                continue;
            }
            session.endpoint().publish(topic, Buffer.buffer(safePayload), MqttQoS.AT_MOST_ONCE, false, retained);
        }
    }

    private boolean hasMatchingSubscription(String clientId, String topic) {
        Map<String, Subscription> subscriptions = subscriptionsByClient.get(clientId);
        if (subscriptions == null) {
            return false;
        }
        return subscriptions.values().stream().anyMatch(subscription -> topicMatches(subscription.topicFilter(), topic));
    }

    private void deliverRetained(ClientSession session, List<Subscription> subscriptions) {
        if (subscriptions.isEmpty()) {
            return;
        }
        Set<String> deliveredTopics = new HashSet<>();
        for (IotRetainedMessage retained : iotService.get().listRetainedMessages(null, null).items()) {
            if (!deliveredTopics.add(retained.getTopic())) {
                continue;
            }
            boolean matches = subscriptions.stream()
                    .anyMatch(subscription -> topicMatches(subscription.topicFilter(), retained.getTopic()));
            if (!matches) {
                continue;
            }
            byte[] payload = Base64.getDecoder().decode(retained.getPayload());
            session.endpoint().publish(retained.getTopic(), Buffer.buffer(payload), MqttQoS.AT_MOST_ONCE, false, true);
        }
    }

    private void removeSession(ClientSession session) {
        sessionsByClient.remove(session.clientId(), session);
        if (session.cleanSession()) {
            subscriptionsByClient.remove(session.clientId());
        }
    }

    private boolean isValidTopicFilter(String topicFilter) {
        if (topicFilter == null || topicFilter.isBlank()) {
            return false;
        }
        String[] levels = topicFilter.split("/", -1);
        for (int i = 0; i < levels.length; i++) {
            String level = levels[i];
            if (level.contains("#") && (!"#".equals(level) || i != levels.length - 1)) {
                return false;
            }
            if (level.contains("+") && !"+".equals(level)) {
                return false;
            }
        }
        return true;
    }

    private boolean topicMatches(String topicFilter, String topic) {
        if (topicFilter.equals(topic)) {
            return true;
        }
        String[] filterLevels = topicFilter.split("/", -1);
        String[] topicLevels = topic.split("/", -1);
        for (int i = 0; i < filterLevels.length; i++) {
            String filterLevel = filterLevels[i];
            if ("#".equals(filterLevel)) {
                return i == filterLevels.length - 1;
            }
            if (i >= topicLevels.length) {
                return false;
            }
            if (!"+".equals(filterLevel) && !filterLevel.equals(topicLevels[i])) {
                return false;
            }
        }
        return filterLevels.length == topicLevels.length;
    }

    private record ClientSession(
            String clientId,
            MqttEndpoint endpoint,
            String sourceIp,
            int sourcePort,
            boolean cleanSession,
            ConnectPrincipal principal) {
    }

    private record Subscription(String topicFilter, int qos) {
    }

    record ConnectionInfo(String clientId, String address, int port) {
    }

    /**
     * The resolved identity behind an MQTT CONNECT: either the unrestricted operator root, an
     * IAM identity's policies, or an IoT certificate's attached policies. {@code null} in a
     * {@link ClientSession} means IAM enforcement was off when the connection was accepted.
     */
    record ConnectPrincipal(String descriptor, List<String> policyDocuments, boolean unrestricted) {

        static ConnectPrincipal unrestricted(String descriptor) {
            return new ConnectPrincipal(descriptor, List.of(), true);
        }

        static ConnectPrincipal scoped(String descriptor, List<String> policyDocuments) {
            return new ConnectPrincipal(descriptor, policyDocuments == null ? List.of() : policyDocuments, false);
        }

        boolean isAuthorized(IamPolicyEvaluator evaluator, String action, String resourceArn) {
            return unrestricted
                    || evaluator.evaluate(policyDocuments, action, resourceArn) == IamPolicyEvaluator.Decision.ALLOW;
        }
    }
}
