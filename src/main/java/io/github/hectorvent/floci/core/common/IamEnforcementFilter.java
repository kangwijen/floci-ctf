package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import io.github.hectorvent.floci.services.s3.PreSignedUrlFilter;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JAX-RS filter that enforces IAM policies on every incoming request when
 * {@code floci.services.iam.enforcement-enabled = true}.
 *
 * <p>Evaluates identity-based policies and resource-based policies (S3 bucket policy,
 * Lambda resource policy, SQS/SNS/KMS/Secrets Manager policies) via {@link ResourcePolicyResolver}.
 *
 * <p>Pre-signed S3 URLs: after {@link PreSignedUrlFilter} validates SigV4 query auth,
 * bucket and identity policies are evaluated for the credential access key.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 20)
public class IamEnforcementFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(IamEnforcementFilter.class);
    private static final ObjectMapper EMR_BODY_MAPPER = new ObjectMapper();

    private static final Pattern SERVICE_PATTERN =
            Pattern.compile("Credential=\\S+/\\d{8}/[^/]+/([^/]+)/");

    private final EmulatorConfig config;
    private final AccountResolver accountResolver;
    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final IamActionRegistry actionRegistry;
    private final ResourceArnBuilder arnBuilder;
    private final ResourcePolicyResolver resourcePolicyResolver;
    private final RegionResolver regionResolver;
    private final KmsService kmsService;

    @Inject
    public IamEnforcementFilter(EmulatorConfig config,
                                AccountResolver accountResolver,
                                IamService iamService,
                                IamPolicyEvaluator evaluator,
                                IamActionRegistry actionRegistry,
                                ResourceArnBuilder arnBuilder,
                                ResourcePolicyResolver resourcePolicyResolver,
                                RegionResolver regionResolver,
                                KmsService kmsService) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.actionRegistry = actionRegistry;
        this.arnBuilder = arnBuilder;
        this.resourcePolicyResolver = resourcePolicyResolver;
        this.regionResolver = regionResolver;
        this.kmsService = kmsService;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }

        boolean strict = config.services().iam().strictEnforcementEnabled();
        String path = ctx.getUriInfo().getPath();

        if (SecurityBypassPaths.isPresignedUrlRequest(ctx)) {
            if (Boolean.TRUE.equals(ctx.getProperty(PreSignedUrlFilter.PRESIGN_VERIFIED_PROPERTY))) {
                enforcePresignedS3(ctx, strict);
            } else if (!SecurityBypassPaths.isInternalHealthOrInfoPath(
                    path, config.ctf().hideInternalEndpointsMode())) {
                LOG.infov("IAM enforcement DENY: unverified pre-signed URL on {0}", path);
                ctx.abortWith(accessDeniedResponse("s3:GetObject", "s3", ctx.getMediaType()));
            }
            return;
        }

        if (SecurityBypassPaths.isPresignedPostRequest(ctx)) {
            return;
        }

        // Cognito OAuth uses client_id/secret Basic auth or Bearer JWT (RFC 6749), not SigV4.
        // Controllers validate registered app clients; IAM policy evaluation does not apply here.
        if (SecurityBypassPaths.isCognitoOAuthPath(path)) {
            if (strict && SecurityBypassPaths.isCognitoOAuthUserInfoPath(path)) {
                String oauthAuth = ctx.getHeaderString("Authorization");
                if (oauthAuth == null || !oauthAuth.regionMatches(true, 0, "Bearer ", 0, 7)) {
                    LOG.infov("IAM strict enforcement DENY: missing Bearer token on {0}", path);
                    ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
                }
            }
            return;
        }

        String auth = ctx.getHeaderString("Authorization");
        if (auth == null) {
            if (strict && !SecurityBypassPaths.isInternalHealthOrInfoPath(
                    path, config.ctf().hideInternalEndpointsMode())) {
                LOG.infov("IAM strict enforcement DENY: missing Authorization header on {0}", path);
                ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            }
            return;
        }

        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            LOG.infov("IAM enforcement DENY: non-SigV4 Authorization on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return;
        }

        String credentialScope = extractCredentialScope(auth);
        if (credentialScope == null) {
            LOG.infov("IAM enforcement DENY: unparsable credential scope on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }

        String region = regionResolver.resolveRegionFromAuth(auth);
        String accountId = accountResolver.resolve(auth);
        evaluateAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
    }

    private void enforcePresignedS3(ContainerRequestContext ctx, boolean strict) {
        String credential = ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        String akid = accountResolver.extractAccessKeyIdFromCredential(credential);
        if (akid != null && config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return;
        }

        String region = regionResolver.getDefaultRegion();
        if (credential != null) {
            String[] parts = credential.split("/");
            if (parts.length >= 2 && parts[1].length() == 8) {
                // region segment present in credential scope
            }
            if (parts.length >= 3 && !parts[2].isBlank()) {
                region = parts[2];
            }
        }

        String accountId = akid != null && akid.matches("\\d{12}") ? akid : accountResolver.defaultAccountId();

        String action = actionRegistry.resolve("s3", ctx);
        if (action == null) {
            if (strict) {
                ctx.abortWith(accessDeniedResponse("s3:*", "s3", ctx.getMediaType()));
            }
            return;
        }

        CallerContext caller = akid != null ? iamService.resolveCallerContext(akid) : null;
        if (caller == null) {
            caller = CallerContext.of(List.of());
        }

        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
            return;
        }

        String resource = arnBuilder.build("s3", ctx, region, accountId);
        List<String> resourcePolicies = resourcePolicyResolver.resolve("s3", resource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, "s3", ctx);

        if (evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx) == Decision.DENY) {
            LOG.infov("IAM presign DENY: akid={0} action={1} resource={2}", akid, action, resource);
            ctx.abortWith(accessDeniedResponse(action, "s3", ctx.getMediaType()));
        }
    }

    private void evaluateAndAbortIfDenied(ContainerRequestContext ctx,
                                          String credentialScope,
                                          String akid,
                                          String region,
                                          String accountId,
                                          boolean strict) {
        if (isDynamoDbBatchExecuteStatement(credentialScope, ctx)) {
            evaluateDynamoDbBatchAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isEmrMultiClusterRequest(credentialScope, ctx)) {
            evaluateEmrMultiClusterAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isTaggingMultiResourceRequest(credentialScope, ctx)) {
            evaluateTaggingMultiResourceAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }

        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            if (strict) {
                String unknownAction = credentialScope + ":*";
                LOG.infov("IAM strict enforcement DENY: unmapped action scope={0} path={1}",
                        credentialScope, ctx.getUriInfo().getPath());
                ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            return;
        }

        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
            return;
        }

        String resource = arnBuilder.build(credentialScope, ctx, region, accountId);
        List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, ctx);

        Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
        if (decision == Decision.DENY
                && "kms".equals(credentialScope)
                && kmsService.isGrantAuthorized(
                        conditionCtx.get("aws:principalarn"),
                        conditionCtx.get("aws:principalaccount"),
                        resource,
                        action,
                        region)) {
            return;
        }
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2}", akid, action, resource);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
        }
    }

    private static boolean isDynamoDbBatchExecuteStatement(String credentialScope, ContainerRequestContext ctx) {
        if (!"dynamodb".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        return target != null && target.endsWith(".BatchExecuteStatement");
    }

    private void evaluateDynamoDbBatchAndAbortIfDenied(ContainerRequestContext ctx,
                                                       String credentialScope,
                                                       String akid,
                                                       String region,
                                                       String accountId,
                                                       boolean strict) {
        List<String> actions = actionRegistry.resolveAllDynamoDbBatchActions(ctx);
        List<String> resources = arnBuilder.buildAllDynamoDbPartiQLResources(ctx, region, accountId);

        if (actions.isEmpty()) {
            if (strict) {
                String unknownAction = credentialScope + ":*";
                LOG.infov("IAM strict enforcement DENY: empty BatchExecuteStatement scope={0}", credentialScope);
                ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse("dynamodb:BatchExecuteStatement", credentialScope, ctx.getMediaType()));
            return;
        }

        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, ctx);
        int count = Math.min(actions.size(), resources.size());

        for (int i = 0; i < count; i++) {
            String action = actions.get(i);
            if (action == null) {
                if (strict) {
                    String unknownAction = credentialScope + ":*";
                    LOG.infov("IAM strict enforcement DENY: unmapped PartiQL statement index={0}", i);
                    ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
                }
                continue;
            }

            if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
                continue;
            }

            String resource = resources.get(i);
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
            if (decision == Decision.DENY
                    && "kms".equals(credentialScope)
                    && kmsService.isGrantAuthorized(
                            conditionCtx.get("aws:principalarn"),
                            conditionCtx.get("aws:principalaccount"),
                            resource,
                            action,
                            region)) {
                continue;
            }
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} batchIndex={3}",
                        akid, action, resource, i);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }

        if (actions.size() != resources.size() && strict) {
            String unknownAction = credentialScope + ":*";
            LOG.infov("IAM strict enforcement DENY: BatchExecuteStatement action/resource count mismatch");
            ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
        }
    }

    private static boolean isEmrMultiClusterRequest(String credentialScope, ContainerRequestContext ctx) {
        if (!"elasticmapreduce".equals(credentialScope)) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            var ids = node.get("JobFlowIds");
            return ids != null && ids.isArray() && ids.size() > 1;
        } catch (Exception e) {
            return false;
        }
    }

    private void evaluateEmrMultiClusterAndAbortIfDenied(ContainerRequestContext ctx,
                                                       String credentialScope,
                                                       String akid,
                                                       String region,
                                                       String accountId,
                                                       boolean strict) {
        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            if (strict) {
                String unknownAction = credentialScope + ":*";
                LOG.infov("IAM strict enforcement DENY: unmapped EMR multi-cluster scope={0}", credentialScope);
                ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            return;
        }

        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
            return;
        }

        List<String> resources = arnBuilder.buildAllEmrClusterResources(ctx, region, accountId);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, ctx);

        for (String resource : resources) {
            if ("*".equals(resource)) {
                continue;
            }
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} emrMultiCluster", akid, action, resource);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
    }

    private static boolean isTaggingMultiResourceRequest(String credentialScope, ContainerRequestContext ctx) {
        if (!"tagging".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null) {
            return false;
        }
        String operation = target.contains(".") ? target.substring(target.lastIndexOf('.') + 1) : target;
        if ("GetTagKeys".equals(operation) || "GetTagValues".equals(operation)) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            var arnList = node.get("ResourceARNList");
            return arnList != null && arnList.isArray() && arnList.size() > 1;
        } catch (Exception e) {
            return false;
        }
    }

    private void evaluateTaggingMultiResourceAndAbortIfDenied(ContainerRequestContext ctx,
                                                              String credentialScope,
                                                              String akid,
                                                              String region,
                                                              String accountId,
                                                              boolean strict) {
        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            if (strict) {
                String unknownAction = credentialScope + ":*";
                LOG.infov("IAM strict enforcement DENY: unmapped tagging scope={0}", credentialScope);
                ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            return;
        }

        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
            return;
        }

        List<String> resources = arnBuilder.buildAllTaggingResources(ctx);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, ctx);

        for (String resource : resources) {
            if ("*".equals(resource)) {
                continue;
            }
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} taggingMultiArn", akid, action, resource);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
    }

    private Map<String, String> buildConditionContext(String accessKeyId,
                                                      String accountId,
                                                      String credentialScope,
                                                      ContainerRequestContext ctx) {
        Map<String, String> out = new HashMap<>();
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
        String sourceIp = "127.0.0.1";
        if (config.auth().trustForwardedHeaders()) {
            String forwarded = ctx.getHeaderString("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                sourceIp = forwarded;
                int comma = sourceIp.indexOf(',');
                if (comma > 0) {
                    sourceIp = sourceIp.substring(0, comma).trim();
                }
            }
        }
        out.put("aws:sourceip", sourceIp);
        if ("s3".equals(credentialScope)) {
            enrichS3ConditionKeys(ctx, out);
        }
        return out;
    }

    private static void enrichS3ConditionKeys(ContainerRequestContext ctx, Map<String, String> out) {
        var query = ctx.getUriInfo().getQueryParameters();
        String prefix = query.getFirst("prefix");
        if (prefix != null && !prefix.isBlank()) {
            out.put("s3:prefix", prefix);
        }
        String delimiter = query.getFirst("delimiter");
        if (delimiter != null && !delimiter.isBlank()) {
            out.put("s3:delimiter", delimiter);
        }
        String cannedAcl = ctx.getHeaderString("x-amz-acl");
        if (cannedAcl != null && !cannedAcl.isBlank()) {
            out.put("s3:x-amz-acl", cannedAcl);
        }
    }

    private String extractCredentialScope(String auth) {
        Matcher m = SERVICE_PATTERN.matcher(auth);
        return m.find() ? m.group(1) : null;
    }

    static boolean isInternalHealthOrInfoPath(String path) {
        return SecurityBypassPaths.isInternalHealthOrInfoPath(path, CtfHideInternalEndpointsMode.OFF);
    }

    static Response accessDeniedResponse(String action, String credentialScope, MediaType requestMediaType) {
        String message = "User is not authorized to perform: " + action;
        if ("s3".equals(credentialScope)) {
            return s3XmlAccessDenied(message);
        }
        if (isFormEncoded(requestMediaType) || isQueryProtocolScope(credentialScope, requestMediaType)) {
            return queryXmlAccessDenied(message);
        }
        return jsonAccessDenied(message);
    }

    /**
     * Query-protocol services (SQS, SNS, IAM, STS, ...) respond with XML {@code ErrorResponse}
     * even when the client omits {@code Content-Type} on the form-encoded POST.
     */
    private static boolean isQueryProtocolScope(String credentialScope, MediaType requestMediaType) {
        if (credentialScope == null || isAwsJsonContentType(requestMediaType)) {
            return false;
        }
        return switch (credentialScope) {
            case "sqs", "sns", "iam", "sts", "ec2", "rds", "elasticache", "cloudformation",
                 "email", "ses", "monitoring", "autoscaling", "elasticloadbalancing", "neptune",
                 "docdb" -> true;
            default -> false;
        };
    }

    private static boolean isAwsJsonContentType(MediaType mt) {
        if (mt == null || !"application".equalsIgnoreCase(mt.getType())) {
            return false;
        }
        String subtype = mt.getSubtype();
        return subtype != null
                && (subtype.startsWith("x-amz-json-") || "json".equalsIgnoreCase(subtype));
    }

    private static boolean isFormEncoded(MediaType mt) {
        return mt != null
                && "application".equalsIgnoreCase(mt.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype());
    }

    private static Response queryXmlAccessDenied(String message) {
        String xml = new XmlBuilder()
                .start("ErrorResponse")
                  .start("Error")
                    .elem("Type", "Sender")
                    .elem("Code", "AccessDenied")
                    .elem("Message", message)
                  .end("Error")
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("ErrorResponse")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response s3XmlAccessDenied(String message) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", "AccessDenied")
                  .elem("Message", message)
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("Error")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response jsonAccessDenied(String message) {
        String body = "{\"__type\":\"AccessDeniedException\",\"message\":\"" + escapeJson(message) + "\"}";
        return Response.status(403).type(MediaType.APPLICATION_JSON).entity(body).build();
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
