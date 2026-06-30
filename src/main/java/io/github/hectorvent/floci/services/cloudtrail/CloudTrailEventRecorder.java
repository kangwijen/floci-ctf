package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.ClientSourceIpResolver;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MediaType;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ApplicationScoped
public class CloudTrailEventRecorder {

    private static final String EVENT_VERSION = "1.08";
    private static final Pattern SERVICE_PATTERN =
            Pattern.compile("Credential=\\S+/\\d{8}/[^/]+/([^/]+)/");
    private static final DateTimeFormatter EVENT_TIME =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter EVENT_TIME_PARSE = new DateTimeFormatterBuilder()
            .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
            .optionalStart()
            .appendFraction(ChronoField.NANO_OF_SECOND, 0, 9, true)
            .optionalEnd()
            .appendLiteral('Z')
            .toFormatter()
            .withZone(ZoneOffset.UTC);

    private static final Set<String> SQS_DATA_EVENT_NAMES = Set.of(
            "SendMessage", "ReceiveMessage", "DeleteMessage", "ChangeMessageVisibility");

    private final ObjectMapper mapper;
    private final AccountResolver accountResolver;
    private final IamService iamService;
    private final ResourceArnBuilder arnBuilder;
    private final EmulatorConfig config;
    private final Instance<RequestContext> requestContext;
    private final Instance<io.quarkus.vertx.http.runtime.CurrentVertxRequest> vertxRequest;

    @Inject
    public CloudTrailEventRecorder(ObjectMapper mapper,
                                   AccountResolver accountResolver,
                                   IamService iamService,
                                   ResourceArnBuilder arnBuilder,
                                   EmulatorConfig config,
                                   Instance<RequestContext> requestContext,
                                   Instance<io.quarkus.vertx.http.runtime.CurrentVertxRequest> vertxRequest) {
        this.mapper = mapper;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.arnBuilder = arnBuilder;
        this.config = config;
        this.requestContext = requestContext;
        this.vertxRequest = vertxRequest;
    }

    public Map<String, Object> buildEvent(ContainerRequestContext request,
                                          ContainerResponseContext response,
                                          String iamAction,
                                          String credentialScope) {
        Instant eventInstant = resolveEventTime(request);
        String eventId = UUID.randomUUID().toString();
        String region = resolveRegion(request);
        String accountId = resolveAccountId(request);
        String eventSource = toEventSource(credentialScope);
        String eventName = toEventName(iamAction, request, credentialScope);
        String requestId = firstHeader(response, "x-amz-request-id", "x-amzn-RequestId");
        String sourceIp = resolveSourceIp(request);
        String userAgent = request.getHeaderString("User-Agent");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventVersion", EVENT_VERSION);
        event.put("userIdentity", buildUserIdentity(request, accountId, eventInstant));
        event.put("eventTime", EVENT_TIME.format(eventInstant));
        event.put("eventSource", eventSource);
        event.put("eventName", eventName);
        event.put("awsRegion", region);
        event.put("sourceIPAddress", sourceIp);
        if (userAgent != null && !userAgent.isBlank()) {
            event.put("userAgent", userAgent);
        }
        Map<String, Object> additionalEventData = buildAdditionalEventData(request);
        if (additionalEventData != null && !additionalEventData.isEmpty()) {
            event.put("additionalEventData", additionalEventData);
        }
        Map<String, Object> tlsDetails = buildTlsDetails(request, eventSource, region);
        if (tlsDetails != null && !tlsDetails.isEmpty()) {
            event.put("tlsDetails", tlsDetails);
        }
        Map<String, Object> requestParameters = buildRequestParameters(request, credentialScope);
        enrichAuditParameters(requestParameters, credentialScope, eventName, request, response, region, accountId);
        event.put("requestParameters", requestParameters);
        event.put("responseElements", null);
        event.put("requestID", requestId);
        event.put("eventID", eventId);
        event.put("readOnly", isReadOnly(eventName));
        event.put("eventType", "AwsApiCall");
        boolean dataEvent = isDataEvent(eventSource, eventName, null);
        event.put("managementEvent", !dataEvent);
        event.put("eventCategory", dataEvent ? "Data" : "Management");
        event.put("recipientAccountId", accountId);
        List<Map<String, Object>> resources = buildResources(
                request, credentialScope, region, accountId, eventName);
        if (resources != null && !resources.isEmpty()) {
            event.put("resources", resources);
        }

        int status = response.getStatus();
        if (status >= 400) {
            ErrorDetails error = extractError(response, status);
            if (error.code() != null) {
                event.put("errorCode", error.code());
            }
            if (error.message() != null) {
                event.put("errorMessage", error.message());
            }
        } else if (status >= 200 && status < 300) {
            event.put("responseElements",
                    buildSuccessResponseElements(request, response, credentialScope, eventName));
        }

        return event;
    }

    public Map<String, Object> buildInProcessEvent(InProcessAuditContext ctx) {
        Instant now = Instant.now();
        String eventId = UUID.randomUUID().toString();
        String accountId = config.defaultAccountId();
        String eventSource = ctx.eventSource() != null && !ctx.eventSource().isBlank()
                ? ctx.eventSource()
                : toEventSource(ctx.credentialScope());
        String eventName = ctx.eventName() != null ? ctx.eventName() : "Unknown";
        boolean dataEvent = isDataEvent(eventSource, eventName, ctx.eventCategory());
        boolean managementEvent = ctx.managementEvent() != null ? ctx.managementEvent() : !dataEvent;
        String eventCategory = ctx.eventCategory() != null ? ctx.eventCategory()
                : (dataEvent ? "Data" : "Management");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventVersion", EVENT_VERSION);
        event.put("userIdentity", buildInProcessUserIdentity(ctx, accountId, now));
        event.put("eventTime", EVENT_TIME.format(now));
        event.put("eventSource", eventSource);
        event.put("eventName", eventName);
        event.put("awsRegion", ctx.region());
        if (ctx.invokedBy() != null && !ctx.invokedBy().isBlank()) {
            event.put("sourceIPAddress", ctx.invokedBy());
            event.put("userAgent", ctx.invokedBy());
        } else {
            event.put("sourceIPAddress", "127.0.0.1");
        }
        event.put("requestParameters", buildInProcessRequestParameters(ctx));
        event.put("responseElements", null);
        event.put("requestID", UUID.randomUUID().toString());
        event.put("eventID", eventId);
        event.put("readOnly", isReadOnly(eventName));
        event.put("eventType", "AwsApiCall");
        event.put("managementEvent", managementEvent);
        event.put("eventCategory", eventCategory);
        event.put("recipientAccountId", accountId);
        if (ctx.errorCode() != null && !ctx.errorCode().isBlank()) {
            event.put("errorCode", ctx.errorCode());
        }
        return event;
    }

    public String eventId(Map<String, Object> event) {
        Object id = event.get("eventID");
        return id != null ? id.toString() : UUID.randomUUID().toString();
    }

    public String eventName(Map<String, Object> event) {
        Object name = event.get("eventName");
        return name != null ? name.toString() : "Unknown";
    }

    public String eventSource(Map<String, Object> event) {
        Object source = event.get("eventSource");
        return source != null ? source.toString() : "unknown.amazonaws.com";
    }

    public Instant eventTime(Map<String, Object> event) {
        Object time = event.get("eventTime");
        if (time == null) {
            return Instant.now();
        }
        return Instant.from(EVENT_TIME_PARSE.parse(time.toString()));
    }

    public boolean readOnly(Map<String, Object> event) {
        Object value = event.get("readOnly");
        return value instanceof Boolean b && b;
    }

    public String accessKeyId(Map<String, Object> event) {
        Object identity = event.get("userIdentity");
        if (identity instanceof Map<?, ?> map) {
            Object akid = map.get("accessKeyId");
            if (akid != null) {
                return akid.toString();
            }
        }
        return null;
    }

    public String username(Map<String, Object> event) {
        Object identity = event.get("userIdentity");
        if (identity instanceof Map<?, ?> map) {
            Object userName = map.get("userName");
            if (userName != null) {
                return userName.toString();
            }
            Object arn = map.get("arn");
            if (arn != null) {
                String arnText = arn.toString();
                int slash = arnText.lastIndexOf('/');
                if (slash >= 0 && arnText.contains(":user/")) {
                    return arnText.substring(slash + 1);
                }
            }
        }
        return null;
    }

    public String toJson(Map<String, Object> event) {
        try {
            return mapper.writeValueAsString(event);
        } catch (Exception e) {
            return "{}";
        }
    }

    public static String toEventSource(String credentialScope) {
        if (credentialScope == null || credentialScope.isBlank()) {
            return "unknown.amazonaws.com";
        }
        return switch (credentialScope) {
            case "execute-api" -> "apigateway.amazonaws.com";
            case "logs" -> "logs.amazonaws.com";
            default -> credentialScope + ".amazonaws.com";
        };
    }

    static String toEventName(String iamAction, ContainerRequestContext request, String credentialScope) {
        if (iamAction != null && iamAction.contains(":")) {
            String action = iamAction.substring(iamAction.indexOf(':') + 1);
            if ("ListBucket".equals(action) && "s3".equals(credentialScope)
                    && "2".equals(request.getUriInfo().getQueryParameters().getFirst("list-type"))) {
                return "ListObjectsV2";
            }
            return action;
        }
        String target = request.getHeaderString("X-Amz-Target");
        if (target != null && target.contains(".")) {
            return target.substring(target.lastIndexOf('.') + 1);
        }
        String action = request.getUriInfo().getQueryParameters().getFirst("Action");
        if (action != null && !action.isBlank()) {
            return action;
        }
        if ("s3".equals(credentialScope)) {
            return request.getMethod().toUpperCase() + "Request";
        }
        return "Unknown";
    }

    static boolean isReadOnly(String eventName) {
        if (eventName == null || eventName.isBlank()) {
            return false;
        }
        if ("AssumeRole".equals(eventName) || "ReceiveMessage".equals(eventName)) {
            return true;
        }
        if ("Decrypt".equals(eventName) || "Verify".equals(eventName) || "GenerateDataKey".equals(eventName)) {
            return true;
        }
        return eventName.startsWith("Get")
                || eventName.startsWith("List")
                || eventName.startsWith("Describe")
                || eventName.startsWith("Head")
                || eventName.startsWith("Lookup");
    }

    private static final Set<String> S3_DATA_EVENT_NAMES = Set.of(
            "PutObject", "GetObject", "DeleteObject", "HeadObject",
            "GetObjectVersion", "DeleteObjectVersion", "RestoreObject",
            "PutObjectAcl", "GetObjectAcl");

    public static boolean isDataEvent(String eventSource, String eventName, String explicitCategory) {
        if ("Data".equals(explicitCategory)) {
            return true;
        }
        if ("Management".equals(explicitCategory)) {
            return false;
        }
        if (eventSource != null && eventSource.startsWith("s3.")) {
            return S3_DATA_EVENT_NAMES.contains(eventName);
        }
        if (eventSource != null && eventSource.startsWith("sqs.")) {
            return SQS_DATA_EVENT_NAMES.contains(eventName);
        }
        return false;
    }

    private Map<String, Object> buildInProcessRequestParameters(InProcessAuditContext ctx) {
        Map<String, Object> params = new LinkedHashMap<>();
        if (ctx.requestParameters() != null) {
            params.putAll(ctx.requestParameters());
        }
        if ("sqs".equals(ctx.credentialScope())) {
            normalizeSqsAuditParameters(params);
        }
        if ("dynamodb".equals(ctx.credentialScope())) {
            normalizeDynamoDbAuditParameters(params);
        }
        if ("sns".equals(ctx.credentialScope())) {
            normalizeSnsAuditParameters(params);
        }
        if ("kms".equals(ctx.credentialScope())) {
            normalizeKmsAuditParameters(params, null, ctx.region(), config.defaultAccountId(), ctx.eventName(), null);
        }
        if (ctx.inScopeSourceArn() != null && !ctx.inScopeSourceArn().isBlank()
                && !params.containsKey("inScopeOf")) {
            params.put("inScopeOf", ctx.inScopeSourceArn());
        }
        return params;
    }

    private static void normalizeSqsAuditParameters(Map<String, Object> params) {
        copyAuditParamIfAbsent(params, "QueueUrl", "queueUrl");
        copyAuditParamIfAbsent(params, "MessageBody", "messageBody");
        params.remove("QueueUrl");
        params.remove("MessageBody");
    }

    private static void copyAuditParamIfAbsent(Map<String, Object> params, String sourceKey, String targetKey) {
        if (params.containsKey(targetKey)) {
            return;
        }
        Object value = params.get(sourceKey);
        if (value != null && !value.toString().isBlank()) {
            params.put(targetKey, value);
        }
    }

    private Map<String, Object> buildInProcessUserIdentity(InProcessAuditContext ctx,
                                                           String defaultAccountId,
                                                           Instant now) {
        if (ctx.executionRoleArn() != null && !ctx.executionRoleArn().isBlank()) {
            return buildAssumedRoleIdentity(ctx, now);
        }
        if (ctx.invokedBy() != null && !ctx.invokedBy().isBlank()) {
            return buildAwsServiceIdentity(ctx);
        }
        Map<String, Object> userIdentity = new LinkedHashMap<>();
        userIdentity.put("type", "Root");
        userIdentity.put("principalId", defaultAccountId);
        userIdentity.put("arn", "arn:aws:iam::" + defaultAccountId + ":root");
        userIdentity.put("accountId", defaultAccountId);
        return userIdentity;
    }

    private Map<String, Object> buildAssumedRoleIdentity(InProcessAuditContext ctx, Instant now) {
        String roleArn = ctx.executionRoleArn();
        String roleAccount = accountIdFromArn(roleArn, config.defaultAccountId());
        String roleName = roleArn.substring(roleArn.lastIndexOf('/') + 1);
        String sessionName = sessionNameFromInvokedBy(ctx.invokedBy());
        String assumedRoleArn = "arn:aws:sts::" + roleAccount + ":assumed-role/" + roleName + "/" + sessionName;

        Map<String, Object> sessionIssuer = new LinkedHashMap<>();
        sessionIssuer.put("type", ctx.issuerType() != null ? ctx.issuerType() : "Role");
        sessionIssuer.put("principalId", "AROAEXAMPLE");
        sessionIssuer.put("arn", roleArn);
        sessionIssuer.put("accountId", roleAccount);
        sessionIssuer.put("userName", roleName);

        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("creationDate", EVENT_TIME.format(now));
        attributes.put("mfaAuthenticated", "false");

        Map<String, Object> sessionContext = new LinkedHashMap<>();
        sessionContext.put("sessionIssuer", sessionIssuer);
        sessionContext.put("attributes", attributes);

        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("type", "AssumedRole");
        identity.put("principalId", "AROAEXAMPLE:" + sessionName);
        identity.put("arn", assumedRoleArn);
        identity.put("accountId", roleAccount);
        identity.put("sessionContext", sessionContext);
        if (ctx.invokedBy() != null && !ctx.invokedBy().isBlank()) {
            identity.put("invokedBy", ctx.invokedBy());
        }
        return identity;
    }

    private static Map<String, Object> buildAwsServiceIdentity(InProcessAuditContext ctx) {
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("type", "AWSService");
        identity.put("invokedBy", ctx.invokedBy());
        String principal = ctx.servicePrincipal() != null ? ctx.servicePrincipal() : ctx.invokedBy();
        if (principal != null && !principal.isBlank()) {
            identity.put("servicePrincipal", principal);
        }
        return identity;
    }

    private static String accountIdFromArn(String arn, String fallback) {
        if (arn == null) {
            return fallback;
        }
        String[] parts = arn.split(":");
        if (parts.length >= 5 && !parts[4].isBlank()) {
            return parts[4];
        }
        return fallback;
    }

    private static String sessionNameFromInvokedBy(String invokedBy) {
        if (invokedBy == null || invokedBy.isBlank()) {
            return "session";
        }
        String name = invokedBy;
        if (name.endsWith(".amazonaws.com")) {
            name = name.substring(0, name.length() - ".amazonaws.com".length());
        }
        return name.replace('.', '-');
    }

    private Map<String, Object> buildUserIdentity(ContainerRequestContext request, String accountId, Instant now) {
        String auth = request.getHeaderString("Authorization");
        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            String credential = request.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
            akid = accountResolver.extractAccessKeyIdFromCredential(credential);
        }

        Optional<CallerIdentity> identity = iamService.resolveCallerIdentity(
                akid, accountId, config.auth().rootAccessKeyId());

        Map<String, Object> userIdentity = new LinkedHashMap<>();
        if (identity.isPresent()) {
            CallerIdentity caller = identity.get();
            if (caller.arn().endsWith(":root")) {
                userIdentity.put("type", "Root");
            } else if (caller.arn().contains(":user/")) {
                userIdentity.put("type", "IAMUser");
                userIdentity.put("userName", caller.arn().substring(caller.arn().lastIndexOf('/') + 1));
                userIdentity.put("sessionContext", buildIamUserSessionContext(now));
            } else if (caller.arn().contains(":assumed-role/")) {
                userIdentity.put("type", "AssumedRole");
                userIdentity.putAll(buildHttpAssumedRoleSessionContext(caller.arn(), caller.account(), now));
            } else {
                userIdentity.put("type", "IAMUser");
            }
            userIdentity.put("principalId", caller.userId());
            userIdentity.put("arn", caller.arn());
            userIdentity.put("accountId", caller.account());
            if (akid != null) {
                userIdentity.put("accessKeyId", akid);
            }
            return userIdentity;
        }

        userIdentity.put("type", "Root");
        userIdentity.put("principalId", accountId);
        userIdentity.put("arn", "arn:aws:iam::" + accountId + ":root");
        userIdentity.put("accountId", accountId);
        if (akid != null) {
            userIdentity.put("accessKeyId", akid);
        }
        return userIdentity;
    }

    private Map<String, Object> buildRequestParameters(ContainerRequestContext request, String credentialScope) {
        Map<String, Object> params = new LinkedHashMap<>();
        String path = request.getUriInfo().getPath();
        if (path != null && !path.isBlank()) {
            String normalized = path.startsWith("/") ? path.substring(1) : path;
            if ("s3".equals(credentialScope)) {
                int slash = normalized.indexOf('/');
                if (slash < 0) {
                    if (!normalized.isBlank()) {
                        params.put("bucketName", normalized);
                    }
                } else {
                    params.put("bucketName", normalized.substring(0, slash));
                    params.put("key", normalized.substring(slash + 1));
                }
            } else {
                params.put("path", "/" + normalized);
            }
        }

        var query = request.getUriInfo().getQueryParameters();
        for (var entry : query.entrySet()) {
            if (entry.getValue() == null || entry.getValue().isEmpty()) {
                continue;
            }
            String key = entry.getKey();
            if (key.startsWith("X-Amz-")) {
                continue;
            }
            params.put(key, entry.getValue().getFirst());
        }

        String target = request.getHeaderString("X-Amz-Target");
        Map<String, String> form = parseFormParams(request);
        addFormParam(params, form, "QueueUrl", "queueUrl");
        addFormParam(params, form, "QueueName", "queueName");
        addFormParam(params, form, "MessageBody", "messageBody");
        addFormParam(params, form, "RoleArn", "roleArn");
        addFormParam(params, form, "RoleSessionName", "roleSessionName");
        addFormParam(params, form, "SecretId", "secretId");
        addFormParam(params, form, "TableName", "tableName");
        addFormParam(params, form, "StackName", "stackName");
        addFormParam(params, form, "Name", "name");
        addFormParam(params, form, "UserName", "userName");
        addFormParam(params, form, "TopicArn", "topicArn");
        addFormParam(params, form, "Action", "action");
        if (!params.containsKey("secretId")) {
            String secretId = readJsonStringField(request, "SecretId");
            if (secretId != null && !secretId.isBlank()) {
                params.put("secretId", secretId);
            }
        }
        if (!params.containsKey("name")) {
            String name = readJsonStringField(request, "Name");
            if (name != null && !name.isBlank()) {
                params.put("name", name);
            }
        }
        if (target != null && target.contains("secretsmanager.ListSecrets")) {
            Integer maxResults = readJsonIntField(request, "MaxResults");
            if (maxResults != null) {
                params.put("maxResults", maxResults);
            }
        }
        if ("sqs".equals(credentialScope) && !params.containsKey("queueUrl")) {
            String queueUrl = readJsonStringField(request, "QueueUrl");
            if (queueUrl != null && !queueUrl.isBlank()) {
                params.put("queueUrl", queueUrl);
            }
        }
        if ("sqs".equals(credentialScope) && !params.containsKey("messageBody")) {
            String messageBody = readJsonStringField(request, "MessageBody");
            if (messageBody != null && !messageBody.isBlank()) {
                params.put("messageBody", messageBody);
            }
        }
        if (!params.containsKey("tableName")) {
            String tableName = readJsonStringField(request, "TableName");
            if (tableName != null && !tableName.isBlank()) {
                params.put("tableName", tableName);
            }
        }
        if (!params.containsKey("topicArn")) {
            String topicArn = readJsonStringField(request, "TopicArn");
            if (topicArn != null && !topicArn.isBlank()) {
                params.put("topicArn", topicArn);
            }
        }
        if (!params.containsKey("keyId")) {
            String keyId = readJsonStringField(request, "KeyId");
            if (keyId != null && !keyId.isBlank()) {
                params.put("keyId", keyId);
            }
        }
        return params.isEmpty() ? null : params;
    }

    private void enrichAuditParameters(Map<String, Object> params,
                                       String credentialScope,
                                       String eventName,
                                       ContainerRequestContext request,
                                       ContainerResponseContext response,
                                       String region,
                                       String accountId) {
        if (params == null) {
            return;
        }
        if ("dynamodb".equals(credentialScope)) {
            normalizeDynamoDbAuditParameters(params);
        }
        if ("sns".equals(credentialScope)) {
            normalizeSnsAuditParameters(params);
        }
        if ("kms".equals(credentialScope)) {
            normalizeKmsAuditParameters(params, request, region, accountId, eventName, response);
        }
    }

    private static void normalizeDynamoDbAuditParameters(Map<String, Object> params) {
        copyAuditParamIfAbsent(params, "TableName", "tableName");
        params.remove("TableName");
        params.remove("path");
    }

    private static void normalizeSnsAuditParameters(Map<String, Object> params) {
        copyAuditParamIfAbsent(params, "TopicArn", "topicArn");
        params.remove("TopicArn");
    }

    private void normalizeKmsAuditParameters(Map<String, Object> params,
                                             ContainerRequestContext request,
                                             String region,
                                             String accountId,
                                             String eventName,
                                             ContainerResponseContext response) {
        String ciphertextBlob = request != null
                ? readJsonStringField(request, "CiphertextBlob")
                : stringParam(params, "CiphertextBlob");
        if (ciphertextBlob == null) {
            ciphertextBlob = stringParam(params, "ciphertextBlob");
        }

        params.remove("CiphertextBlob");
        params.remove("ciphertextBlob");
        params.remove("Plaintext");
        params.remove("plaintext");
        params.remove("path");

        String keyId = stringParam(params, "keyId");
        if (keyId == null || keyId.isBlank()) {
            String embeddedKeyId = ResourceArnBuilder.keyIdFromCiphertextBlob(ciphertextBlob);
            if (embeddedKeyId != null && !embeddedKeyId.isBlank()) {
                keyId = formatKmsKeyArn(embeddedKeyId, region, accountId);
            }
        }
        if ((keyId == null || keyId.isBlank()) && "Decrypt".equals(eventName) && response != null
                && response.getStatus() >= 200 && response.getStatus() < 300) {
            keyId = readResponseJsonStringField(response, "KeyId");
        }
        if (keyId != null && !keyId.isBlank()) {
            params.put("keyId", formatKmsKeyArn(keyId, region, accountId));
        }

        if (!params.containsKey("encryptionContext") && request != null) {
            Map<String, Object> encryptionContext = readJsonStringMapField(request, "EncryptionContext");
            if (encryptionContext != null && !encryptionContext.isEmpty()) {
                params.put("encryptionContext", encryptionContext);
            }
        }
        Object encryptionContext = params.get("EncryptionContext");
        if (encryptionContext != null) {
            params.put("encryptionContext", encryptionContext);
            params.remove("EncryptionContext");
        }

        if ("Decrypt".equals(eventName) || "Encrypt".equals(eventName) || "ReEncrypt".equals(eventName)) {
            String algorithm = stringParam(params, "encryptionAlgorithm");
            if (algorithm == null || algorithm.isBlank()) {
                algorithm = stringParam(params, "EncryptionAlgorithm");
            }
            params.put("encryptionAlgorithm",
                    algorithm != null && !algorithm.isBlank() ? algorithm : "SYMMETRIC_DEFAULT");
            params.remove("EncryptionAlgorithm");
        }
    }

    private static String stringParam(Map<String, Object> params, String key) {
        Object value = params.get(key);
        return value == null ? null : value.toString();
    }

    private static String formatKmsKeyArn(String keyId, String region, String accountId) {
        if (keyId.startsWith("arn:aws:kms:")) {
            return keyId;
        }
        if (keyId.startsWith("alias/")) {
            return "arn:aws:kms:" + region + ":" + accountId + ":" + keyId;
        }
        return "arn:aws:kms:" + region + ":" + accountId + ":key/" + keyId;
    }

    private String readResponseJsonStringField(ContainerResponseContext response, String fieldName) {
        Object entity = response.getEntity();
        if (!(entity instanceof String body) || body.isBlank()) {
            return null;
        }
        try {
            JsonNode node = mapper.readTree(body);
            JsonNode field = node.get(fieldName);
            if (field != null && !field.isNull()) {
                return field.asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private List<Map<String, Object>> buildResources(ContainerRequestContext request,
                                                     String credentialScope,
                                                     String region,
                                                     String accountId,
                                                     String eventName) {
        if (credentialScope == null || credentialScope.isBlank()) {
            return null;
        }
        String arn;
        try {
            arn = arnBuilder.build(credentialScope, request, region, accountId);
        } catch (RuntimeException ignored) {
            return null;
        }
        if (arn == null || arn.isBlank() || "*".equals(arn)) {
            return null;
        }
        List<Map<String, Object>> resources = new ArrayList<>();
        String type = cloudTrailResourceType(credentialScope, eventName, arn);
        if (type != null) {
            resources.add(resourceEntry(arn, type, accountId));
        }
        if ("AWS::S3::Object".equals(type)) {
            String bucketArn = bucketArnFromObjectArn(arn);
            if (bucketArn != null) {
                resources.add(resourceEntry(bucketArn, "AWS::S3::Bucket", accountId));
            }
        }
        return resources.isEmpty() ? null : resources;
    }

    private static Map<String, Object> resourceEntry(String arn, String type, String accountId) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("ARN", arn);
        entry.put("type", type);
        entry.put("accountId", accountId);
        return entry;
    }

    private static String bucketArnFromObjectArn(String objectArn) {
        if (objectArn == null || !objectArn.startsWith("arn:aws:s3:::")) {
            return null;
        }
        String path = objectArn.substring("arn:aws:s3:::".length());
        int slash = path.indexOf('/');
        if (slash <= 0) {
            return null;
        }
        return "arn:aws:s3:::" + path.substring(0, slash);
    }

    static String cloudTrailResourceType(String credentialScope, String eventName, String arn) {
        if (arn == null || arn.isBlank() || "*".equals(arn)) {
            return null;
        }
        return switch (credentialScope) {
            case "s3" -> {
                String resource = arn.startsWith("arn:aws:s3:::")
                        ? arn.substring("arn:aws:s3:::".length()) : arn;
                yield resource.contains("/") ? "AWS::S3::Object" : "AWS::S3::Bucket";
            }
            case "sqs" -> "AWS::SQS::Queue";
            case "sns" -> "AWS::SNS::Topic";
            case "kms" -> "AWS::KMS::Key";
            case "dynamodb" -> "AWS::DynamoDB::Table";
            case "secretsmanager" -> "AWS::SecretsManager::Secret";
            case "cloudtrail" -> "AWS::CloudTrail::Trail";
            case "iam" -> iamResourceType(arn);
            case "sts" -> arn.contains(":role/") ? "AWS::IAM::Role" : iamResourceType(arn);
            default -> null;
        };
    }

    private static String iamResourceType(String arn) {
        if (arn.contains(":user/")) {
            return "AWS::IAM::User";
        }
        if (arn.contains(":role/")) {
            return "AWS::IAM::Role";
        }
        if (arn.contains(":policy/")) {
            return "AWS::IAM::Policy";
        }
        if (arn.contains(":group/")) {
            return "AWS::IAM::Group";
        }
        return null;
    }

    private static boolean isAwsJsonMediaType(MediaType mediaType) {
        if (mediaType == null) {
            return false;
        }
        String subtype = mediaType.getSubtype();
        return "x-amz-json-1.1".equals(subtype) || "x-amz-json-1.0".equals(subtype);
    }

    private Integer readJsonIntField(ContainerRequestContext request, String fieldName) {
        if (!isAwsJsonMediaType(request.getMediaType())) {
            return null;
        }
        byte[] body = RequestBodyBuffer.peek(request);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = mapper.readTree(body);
            JsonNode field = node.get(fieldName);
            if (field != null && field.isNumber()) {
                return field.asInt();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String readJsonStringField(ContainerRequestContext request, String fieldName) {
        if (!isAwsJsonMediaType(request.getMediaType())) {
            return null;
        }
        byte[] body = RequestBodyBuffer.peek(request);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = mapper.readTree(body);
            JsonNode field = node.get(fieldName);
            if (field != null && field.isTextual()) {
                return field.asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private Map<String, Object> readJsonStringMapField(ContainerRequestContext request, String fieldName) {
        if (!isAwsJsonMediaType(request.getMediaType())) {
            return null;
        }
        byte[] body = RequestBodyBuffer.peek(request);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = mapper.readTree(body);
            JsonNode field = node.get(fieldName);
            if (field == null || !field.isObject()) {
                return null;
            }
            Map<String, Object> map = new LinkedHashMap<>();
            field.fields().forEachRemaining(entry -> map.put(entry.getKey(), entry.getValue().asText()));
            return map;
        } catch (Exception ignored) {
        }
        return null;
    }

    private static void addFormParam(Map<String, Object> params, Map<String, String> form,
                                     String formKey, String trailKey) {
        if (form == null || form.isEmpty()) {
            return;
        }
        String value = form.get(formKey);
        if (value != null && !value.isBlank()) {
            params.put(trailKey, value);
        }
    }

    private static Map<String, String> parseFormParams(ContainerRequestContext request) {
        MediaType mediaType = request.getMediaType();
        if (mediaType == null || !MediaType.APPLICATION_FORM_URLENCODED_TYPE.isCompatible(mediaType)) {
            return Map.of();
        }
        byte[] body = RequestBodyBuffer.peek(request);
        if (body == null) {
            body = RequestBodyBuffer.buffer(request);
        }
        if (body == null || body.length == 0) {
            return Map.of();
        }
        Charset charset = resolveCharset(mediaType);
        String raw = new String(body, charset);
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? decodeForm(pair.substring(0, eq)) : decodeForm(pair);
            String value = eq >= 0 ? decodeForm(pair.substring(eq + 1)) : "";
            params.put(key, value);
        }
        return params;
    }

    private static String decodeForm(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static Charset resolveCharset(MediaType mediaType) {
        String name = mediaType.getParameters().get("charset");
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static Map<String, Object> buildIamUserSessionContext(Instant now) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("mfaAuthenticated", "false");
        attributes.put("creationDate", EVENT_TIME.format(now));
        return Map.of("attributes", attributes);
    }

    private static Map<String, Object> buildHttpAssumedRoleSessionContext(String arn, String accountId, Instant now) {
        String roleName = "role";
        String sessionName = "session";
        int marker = arn.indexOf(":assumed-role/");
        if (marker >= 0) {
            String tail = arn.substring(marker + ":assumed-role/".length());
            int slash = tail.indexOf('/');
            if (slash > 0) {
                roleName = tail.substring(0, slash);
                sessionName = tail.substring(slash + 1);
            } else if (!tail.isBlank()) {
                roleName = tail;
            }
        }
        String roleArn = "arn:aws:iam::" + accountId + ":role/" + roleName;
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("creationDate", EVENT_TIME.format(now));
        attributes.put("mfaAuthenticated", "false");
        Map<String, Object> sessionIssuer = new LinkedHashMap<>();
        sessionIssuer.put("type", "Role");
        sessionIssuer.put("principalId", "AROA" + accountId + roleName);
        sessionIssuer.put("arn", roleArn);
        sessionIssuer.put("accountId", accountId);
        sessionIssuer.put("userName", roleName);
        Map<String, Object> sessionContext = new LinkedHashMap<>();
        sessionContext.put("sessionIssuer", sessionIssuer);
        sessionContext.put("attributes", attributes);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sessionContext", sessionContext);
        return out;
    }

    private Map<String, Object> buildSuccessResponseElements(ContainerRequestContext request,
                                                             ContainerResponseContext response,
                                                             String credentialScope,
                                                             String eventName) {
        if ("s3".equals(credentialScope)) {
            return buildS3ResponseElements(request, response, eventName);
        }
        if ("sts".equals(credentialScope) && eventName != null && eventName.startsWith("AssumeRole")) {
            return parseStsAssumeRoleResponse(response);
        }
        if ("iam".equals(credentialScope) && "CreateAccessKey".equals(eventName)) {
            return parseIamCreateAccessKeyResponse(response);
        }
        if ("sqs".equals(credentialScope) && "SendMessage".equals(eventName)) {
            return parseSqsSendMessageResponse(response);
        }
        return null;
    }

    private Map<String, Object> buildS3ResponseElements(ContainerRequestContext request,
                                                        ContainerResponseContext response,
                                                        String eventName) {
        Map<String, Object> elements = new LinkedHashMap<>();
        Object versionId = response.getHeaders().getFirst("x-amz-version-id");
        if (versionId != null) {
            elements.put("x-amz-version-id", versionId.toString());
        }
        Object deleteMarker = response.getHeaders().getFirst("x-amz-delete-marker");
        if (deleteMarker != null) {
            elements.put("x-amz-delete-marker", deleteMarker.toString());
        }
        if ("CreateBucket".equals(eventName)) {
            String path = request.getUriInfo().getPath();
            if (path != null && !path.isBlank()) {
                String bucket = path.startsWith("/") ? path.substring(1) : path;
                int slash = bucket.indexOf('/');
                if (slash >= 0) {
                    bucket = bucket.substring(0, slash);
                }
                if (!bucket.isBlank()) {
                    elements.put("bucketName", bucket);
                }
            }
        }
        return elements.isEmpty() ? null : elements;
    }

    private static Map<String, Object> parseStsAssumeRoleResponse(ContainerResponseContext response) {
        String body = responseBody(response);
        if (body == null || body.isBlank()) {
            return null;
        }
        String accessKeyId = xmlTagValue(body, "AccessKeyId");
        String expiration = xmlTagValue(body, "Expiration");
        String assumedRoleArn = xmlTagValue(body, "Arn");
        String assumedRoleId = xmlTagValue(body, "AssumedRoleId");
        if (accessKeyId == null && assumedRoleArn == null) {
            return null;
        }
        Map<String, Object> elements = new LinkedHashMap<>();
        if (accessKeyId != null || expiration != null) {
            Map<String, Object> credentials = new LinkedHashMap<>();
            if (accessKeyId != null) {
                credentials.put("accessKeyId", accessKeyId);
            }
            if (expiration != null) {
                credentials.put("expiration", expiration);
            }
            elements.put("credentials", credentials);
        }
        if (assumedRoleArn != null || assumedRoleId != null) {
            Map<String, Object> assumedRoleUser = new LinkedHashMap<>();
            if (assumedRoleArn != null) {
                assumedRoleUser.put("arn", assumedRoleArn);
            }
            if (assumedRoleId != null) {
                assumedRoleUser.put("assumedRoleId", assumedRoleId);
            }
            elements.put("assumedRoleUser", assumedRoleUser);
        }
        return elements.isEmpty() ? null : elements;
    }

    private static Map<String, Object> parseIamCreateAccessKeyResponse(ContainerResponseContext response) {
        String body = responseBody(response);
        if (body == null || body.isBlank()) {
            return null;
        }
        String accessKeyId = xmlTagValue(body, "AccessKeyId");
        String userName = xmlTagValue(body, "UserName");
        String status = xmlTagValue(body, "Status");
        String createDate = xmlTagValue(body, "CreateDate");
        if (accessKeyId == null) {
            return null;
        }
        Map<String, Object> accessKey = new LinkedHashMap<>();
        accessKey.put("accessKeyId", accessKeyId);
        if (userName != null) {
            accessKey.put("userName", userName);
        }
        if (status != null) {
            accessKey.put("status", status);
        }
        if (createDate != null) {
            accessKey.put("createDate", createDate);
        }
        return Map.of("accessKey", accessKey);
    }

    private static Map<String, Object> parseSqsSendMessageResponse(ContainerResponseContext response) {
        String body = responseBody(response);
        if (body == null || body.isBlank()) {
            return null;
        }
        String messageId = xmlTagValue(body, "MessageId");
        String md5 = xmlTagValue(body, "MD5OfMessageBody");
        if (messageId == null && md5 == null) {
            return null;
        }
        Map<String, Object> elements = new LinkedHashMap<>();
        if (messageId != null) {
            elements.put("messageId", messageId);
        }
        if (md5 != null) {
            elements.put("mD5OfMessageBody", md5);
        }
        return elements;
    }

    private static String responseBody(ContainerResponseContext response) {
        Object entity = response.getEntity();
        return entity instanceof String text ? text : null;
    }

    private String resolveRegion(ContainerRequestContext request) {
        try {
            if (requestContext.isResolvable()) {
                String region = requestContext.get().getRegion();
                if (region != null && !region.isBlank()) {
                    return region;
                }
            }
        } catch (Exception ignored) {
        }
        String auth = request.getHeaderString("Authorization");
        if (auth != null) {
            Matcher matcher = Pattern.compile("Credential=\\S+/\\d{8}/([^/]+)/").matcher(auth);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        String credential = request.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        if (credential != null) {
            String[] parts = credential.split("/");
            if (parts.length >= 3 && !parts[2].isBlank()) {
                return parts[2];
            }
        }
        return config.defaultRegion();
    }

    private String resolveAccountId(ContainerRequestContext request) {
        try {
            if (requestContext.isResolvable()) {
                String accountId = requestContext.get().getAccountId();
                if (accountId != null && !accountId.isBlank()) {
                    return accountId;
                }
            }
        } catch (Exception ignored) {
        }
        return accountResolver.resolve(request.getHeaderString("Authorization"));
    }

    private String resolveSourceIp(ContainerRequestContext request) {
        String stamped = request.getHeaderString("X-Floci-CloudTrail-Source-Ip");
        String forwarded = request.getHeaderString("X-Forwarded-For");
        String socketPeer = resolveSocketPeerHost();
        return ClientSourceIpResolver.resolve(config, stamped, forwarded, socketPeer);
    }

    private String resolveSocketPeerHost() {
        try {
            if (vertxRequest.isResolvable()) {
                var current = vertxRequest.get().getCurrent();
                if (current != null && current.request().remoteAddress() != null) {
                    return current.request().remoteAddress().host();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String firstHeader(ContainerResponseContext response, String... names) {
        for (String name : names) {
            Object value = response.getHeaders().getFirst(name);
            if (value != null) {
                return value.toString();
            }
        }
        return UUID.randomUUID().toString();
    }

    private static ErrorDetails extractError(ContainerResponseContext response, int status) {
        Object entity = response.getEntity();
        if (entity instanceof String body && !body.isBlank()) {
            String code = xmlTagValue(body, "Code");
            String message = xmlTagValue(body, "Message");
            if (code == null && body.contains("__type")) {
                int typeStart = body.indexOf("\"__type\"");
                if (typeStart >= 0) {
                    int colon = body.indexOf(':', typeStart);
                    int quoteStart = body.indexOf('"', colon + 1);
                    int quoteEnd = body.indexOf('"', quoteStart + 1);
                    if (quoteStart >= 0 && quoteEnd > quoteStart) {
                        code = body.substring(quoteStart + 1, quoteEnd);
                    }
                }
            }
            if (message == null && body.contains("\"message\"")) {
                int msgStart = body.indexOf("\"message\"");
                if (msgStart >= 0) {
                    int colon = body.indexOf(':', msgStart);
                    int quoteStart = body.indexOf('"', colon + 1);
                    int quoteEnd = body.indexOf('"', quoteStart + 1);
                    if (quoteStart >= 0 && quoteEnd > quoteStart) {
                        message = body.substring(quoteStart + 1, quoteEnd);
                    }
                }
            }
            if (code != null || message != null) {
                return new ErrorDetails(code != null ? code : defaultErrorCode(status), message);
            }
        }
        return new ErrorDetails(defaultErrorCode(status), null);
    }

    private static String defaultErrorCode(int status) {
        return switch (status) {
            case 401, 403 -> "AccessDenied";
            case 404 -> "NotFound";
            case 409 -> "Conflict";
            default -> "InternalFailure";
        };
    }

    private static String xmlTagValue(String xml, String tag) {
        String open = "<" + tag + ">";
        String close = "</" + tag + ">";
        int start = xml.indexOf(open);
        if (start < 0) {
            return null;
        }
        int end = xml.indexOf(close, start);
        if (end < 0) {
            return null;
        }
        return xml.substring(start + open.length(), end);
    }

    public static String extractCredentialScope(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        Matcher matcher = SERVICE_PATTERN.matcher(authorizationHeader);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static String formatEventTime(Instant instant) {
        Instant value = instant == null ? Instant.now() : instant;
        return EVENT_TIME.format(value);
    }

    static Instant resolveEventTime(ContainerRequestContext request) {
        if (request == null) {
            return Instant.now();
        }
        Object value = request.getProperty(CloudTrailAuditTiming.REQUEST_TIME_PROPERTY);
        if (value instanceof Instant instant) {
            return instant;
        }
        return Instant.now();
    }

    private Map<String, Object> buildAdditionalEventData(ContainerRequestContext request) {
        Map<String, Object> data = new LinkedHashMap<>();
        String auth = request.getHeaderString("Authorization");
        if (auth != null && auth.startsWith("AWS4-HMAC-SHA256")) {
            data.put("SignatureVersion", "AWS4-HMAC-SHA256");
            data.put("AuthenticationMethod", "AuthHeader");
        } else {
            var query = request.getUriInfo().getQueryParameters();
            if (query.containsKey("X-Amz-Algorithm") || query.containsKey("x-amz-algorithm")) {
                data.put("SignatureVersion", "AWS4-HMAC-SHA256");
                data.put("AuthenticationMethod", "QueryString");
            }
        }
        return data.isEmpty() ? null : data;
    }

    private Map<String, Object> buildTlsDetails(ContainerRequestContext request,
                                                String eventSource,
                                                String region) {
        if (!config.auth().trustForwardedHeaders()) {
            return null;
        }
        String proto = request.getHeaderString("X-Forwarded-Proto");
        if (proto == null || !proto.equalsIgnoreCase("https")) {
            return null;
        }
        Map<String, Object> tls = new LinkedHashMap<>();
        tls.put("tlsVersion", "TLSv1.2");
        tls.put("cipherSuite", "ECDHE-RSA-AES128-GCM-SHA256");
        String host = request.getHeaderString("Host");
        if (host == null || host.isBlank()) {
            host = defaultServiceHost(eventSource, region);
        }
        tls.put("clientProvidedHostHeader", host);
        return tls;
    }

    private static String defaultServiceHost(String eventSource, String region) {
        if (eventSource == null || eventSource.isBlank()) {
            return region + ".amazonaws.com";
        }
        String prefix = eventSource.replace(".amazonaws.com", "");
        return prefix + "." + region + ".amazonaws.com";
    }

    private record ErrorDetails(String code, String message) {
    }
}
