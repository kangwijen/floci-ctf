package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
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
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private final ObjectMapper mapper;
    private final AccountResolver accountResolver;
    private final IamService iamService;
    private final EmulatorConfig config;
    private final Instance<RequestContext> requestContext;

    @Inject
    public CloudTrailEventRecorder(ObjectMapper mapper,
                                   AccountResolver accountResolver,
                                   IamService iamService,
                                   EmulatorConfig config,
                                   Instance<RequestContext> requestContext) {
        this.mapper = mapper;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.config = config;
        this.requestContext = requestContext;
    }

    public Map<String, Object> buildEvent(ContainerRequestContext request,
                                          ContainerResponseContext response,
                                          String iamAction,
                                          String credentialScope) {
        Instant now = Instant.now();
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
        event.put("userIdentity", buildUserIdentity(request, accountId));
        event.put("eventTime", EVENT_TIME.format(now));
        event.put("eventSource", eventSource);
        event.put("eventName", eventName);
        event.put("awsRegion", region);
        event.put("sourceIPAddress", sourceIp);
        if (userAgent != null && !userAgent.isBlank()) {
            event.put("userAgent", userAgent);
        }
        event.put("requestParameters", buildRequestParameters(request, credentialScope));
        event.put("responseElements", null);
        event.put("requestID", requestId);
        event.put("eventID", eventId);
        event.put("readOnly", isReadOnly(eventName));
        event.put("eventType", "AwsApiCall");
        event.put("managementEvent", true);
        event.put("recipientAccountId", accountId);

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
            event.put("responseElements", buildSuccessResponseElements(request, credentialScope, eventName));
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
        return Instant.from(EVENT_TIME.parse(time.toString()));
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
            return iamAction.substring(iamAction.indexOf(':') + 1);
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
        return eventName.startsWith("Get")
                || eventName.startsWith("List")
                || eventName.startsWith("Describe")
                || eventName.startsWith("Head");
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
        return false;
    }

    private Map<String, Object> buildInProcessRequestParameters(InProcessAuditContext ctx) {
        Map<String, Object> params = new LinkedHashMap<>();
        if (ctx.requestParameters() != null) {
            params.putAll(ctx.requestParameters());
        }
        if (ctx.inScopeSourceArn() != null && !ctx.inScopeSourceArn().isBlank()
                && !params.containsKey("inScopeOf")) {
            params.put("inScopeOf", ctx.inScopeSourceArn());
        }
        return params;
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

    private Map<String, Object> buildUserIdentity(ContainerRequestContext request, String accountId) {
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
            } else if (caller.arn().contains(":assumed-role/")) {
                userIdentity.put("type", "AssumedRole");
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
        if (target != null) {
            params.put("x-amz-target", target);
        }
        return params;
    }

    private Map<String, Object> buildSuccessResponseElements(ContainerRequestContext request,
                                                             String credentialScope,
                                                             String eventName) {
        if (!"s3".equals(credentialScope)) {
            return null;
        }
        if ("CreateBucket".equals(eventName)) {
            Map<String, Object> elements = new LinkedHashMap<>();
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
            return elements.isEmpty() ? null : elements;
        }
        return null;
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
        if (config.auth().trustForwardedHeaders()) {
            String forwarded = request.getHeaderString("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String sourceIp = forwarded;
                int comma = sourceIp.indexOf(',');
                if (comma > 0) {
                    sourceIp = sourceIp.substring(0, comma).trim();
                }
                return sourceIp;
            }
        }
        return "127.0.0.1";
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

    private record ErrorDetails(String code, String message) {
    }
}
