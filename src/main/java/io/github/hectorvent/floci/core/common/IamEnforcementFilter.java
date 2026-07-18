package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.ResourceRef;
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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
    private final AnonymousAccessGate anonymousAccessGate;
    private final RequestContext requestContext;
    private final IamConditionContextResolver conditionContextResolver;

    @Inject
    public IamEnforcementFilter(EmulatorConfig config,
                                AccountResolver accountResolver,
                                IamService iamService,
                                IamPolicyEvaluator evaluator,
                                IamActionRegistry actionRegistry,
                                ResourceArnBuilder arnBuilder,
                                ResourcePolicyResolver resourcePolicyResolver,
                                RegionResolver regionResolver,
                                KmsService kmsService,
                                AnonymousAccessGate anonymousAccessGate,
                                RequestContext requestContext,
                                IamConditionContextResolver conditionContextResolver) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.actionRegistry = actionRegistry;
        this.arnBuilder = arnBuilder;
        this.resourcePolicyResolver = resourcePolicyResolver;
        this.regionResolver = regionResolver;
        this.kmsService = kmsService;
        this.anonymousAccessGate = anonymousAccessGate;
        this.requestContext = requestContext;
        this.conditionContextResolver = conditionContextResolver;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }

        // Same knob as AuthPosture.strict() (B.1). UNRESOLVED / bare-* gates use this CTF posture.
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

        if (strict && SecurityBypassPaths.isMultipartBucketPostRequest(ctx)) {
            LOG.infov("IAM strict enforcement DENY: unauthenticated bucket POST on {0}", path);
            ctx.abortWith(accessDeniedResponse("s3:PutObject", "s3", ctx.getMediaType()));
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

        // Federated STS uses WebIdentityToken / SAMLAssertion in the form body, not SigV4.
        if (SecurityBypassPaths.isFederatedStsAssumeRequest(ctx)) {
            return;
        }

        String auth = ctx.getHeaderString("Authorization");
        if (auth == null) {
            if (strict && !SecurityBypassPaths.isInternalHealthOrInfoPath(
                    path, config.ctf().hideInternalEndpointsMode())) {
                if (anonymousAccessGate.allowsUnsignedRequest(ctx)) {
                    return;
                }
                LOG.infov("IAM strict enforcement DENY: missing Authorization header on {0}", path);
                ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            }
            return;
        }

        if (config.auth().validateSignatures()
                && auth.contains("Credential=")
                && !auth.trim().startsWith("AWS4-HMAC-SHA256")) {
            LOG.infov("IAM enforcement DENY: malformed SigV4 Authorization on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }

        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            LOG.infov("IAM enforcement DENY: non-SigV4 Authorization on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            if (!config.auth().validateSignatures()
                    || Boolean.TRUE.equals(
                            ctx.getProperty(SigV4ValidationFilter.SIGV4_VERIFIED_PROPERTY))) {
                return;
            }
            LOG.infov("IAM enforcement DENY: unverified operator root on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }

        String credentialScope = extractCredentialScope(auth);
        if (credentialScope == null) {
            LOG.infov("IAM enforcement DENY: unparsable credential scope on {0}", path);
            ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            return;
        }

        String region = regionResolver.resolveRegionFromAuth(auth);
        String accountId = resolveEnforcementAccountId(akid, accountResolver.resolve(auth));
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

        String accountId = resolveEnforcementAccountId(
                akid, accountResolver.resolveFromPresignedCredential(credential));

        String action = actionRegistry.resolve("s3", ctx);
        if (action == null) {
            denyUnmappedAction(ctx, "s3", "presigned");
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
        if (denyUnresolvedResource(ctx, resource, action, "s3", akid, strict)) {
            return;
        }
        List<String> resourcePolicies = resourcePolicyResolver.resolve("s3", resource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, "s3", action, ctx, region);

        if (evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx) == Decision.DENY) {
            LOG.infov("IAM presign DENY: akid={0} action={1} resource={2}", akid, action, resource);
            ctx.abortWith(accessDeniedResponse(action, "s3", ctx.getMediaType()));
        }
    }

    /**
     * Resolves the account used for IAM resource ARNs the same way as
     * {@link AccountContextFilter}: prefer the request-scoped account already set by that
     * filter, then {@link SessionAccountLookup} for temporary ASIA keys, then the
     * {@link AccountResolver} fallback (12-digit AKID or default account).
     */
    private String resolveEnforcementAccountId(String akid, String resolverFallback) {
        String fromContext = requestContext.getAccountId();
        if (fromContext != null && !fromContext.isBlank()) {
            return fromContext;
        }
        if (akid != null && !akid.matches("\\d{12}")) {
            Optional<String> sessionAccount = iamService.resolveAccountId(akid);
            if (sessionAccount.isPresent()) {
                return sessionAccount.get();
            }
        }
        return resolverFallback;
    }

    private void evaluateAndAbortIfDenied(ContainerRequestContext ctx,
                                          String credentialScope,
                                          String akid,
                                          String region,
                                          String accountId,
                                          boolean strict) {
        String routeScope = actionRegistry.resolveRestRouteScope(ctx);
        if (routeScope != null && !routeScope.equals(credentialScope)) {
            String denyAction = actionRegistry.resolve(routeScope, ctx);
            if (denyAction == null) {
                denyAction = routeScope + ":*";
            }
            LOG.infov(
                    "IAM enforcement DENY: credential scope {0} mismatches REST route scope {1} path={2}",
                    credentialScope, routeScope, ctx.getUriInfo().getPath());
            ctx.abortWith(accessDeniedResponse(denyAction, routeScope, ctx.getMediaType()));
            return;
        }

        if (isDynamoDbBatchExecuteStatement(credentialScope, ctx)) {
            evaluateDynamoDbBatchAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isDynamoDbMultiTableExecuteStatement(credentialScope, ctx)) {
            evaluateDynamoDbMultiTableExecuteAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isDynamoDbMultiTableRequestItems(credentialScope, ctx)) {
            evaluateDynamoDbRequestItemsAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isDynamoDbTransactRequest(credentialScope, ctx)) {
            evaluateDynamoDbTransactAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isSecretsManagerMultiSecretBatch(credentialScope, ctx)) {
            evaluateSecretsManagerBatchAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isKmsReEncrypt(credentialScope, ctx)) {
            evaluateKmsReEncryptDualAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isEmrMultiClusterRequest(credentialScope, ctx)) {
            evaluateEmrMultiClusterAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isEventsMultiBusPutEvents(credentialScope, ctx)) {
            evaluateEventsMultiBusAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isLogsMultiGroupStartQuery(credentialScope, ctx)) {
            evaluateLogsMultiGroupAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }
        if (isTaggingMultiResourceRequest(credentialScope, ctx)) {
            evaluateTaggingMultiResourceAndAbortIfDenied(ctx, credentialScope, akid, region, accountId, strict);
            return;
        }

        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            denyUnmappedAction(ctx, credentialScope, "action path=" + ctx.getUriInfo().getPath());
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

        String serviceScope = routeScope != null ? routeScope : credentialScope;
        String resource = arnBuilder.build(serviceScope, ctx, region, accountId);
        if (denyUnresolvedResource(ctx, resource, action, credentialScope, akid, strict)) {
            return;
        }
        List<String> resourcePolicies = resourcePolicyResolver.resolve(serviceScope, resource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, serviceScope, action, ctx, region);

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
            return;
        }

        if ("s3".equals(credentialScope)) {
            evaluateS3CopySourceAndAbortIfDenied(ctx, akid, region, accountId, caller);
        }
    }

    /**
     * CopyObject and UploadPartCopy are both PUT requests carrying an {@code x-amz-copy-source}
     * header. The main evaluation above only checks {@code s3:PutObject} on the destination; AWS
     * separately requires {@code s3:GetObject} (or {@code s3:GetObjectVersion} when the copy
     * source pins a version) on the source object. Without this, a caller with only
     * {@code s3:PutObject} on their own bucket could exfiltrate any object they can name as a
     * copy source.
     */
    private void evaluateS3CopySourceAndAbortIfDenied(ContainerRequestContext ctx,
                                                       String akid,
                                                       String region,
                                                       String accountId,
                                                       CallerContext caller) {
        String copySource = ctx.getHeaderString("x-amz-copy-source");
        if (copySource == null || copySource.isBlank()) {
            return;
        }
        ParsedS3CopySource parsed = parseS3CopySource(copySource);
        if (parsed == null) {
            return;
        }

        String sourceAction = parsed.versionId() != null ? "s3:GetObjectVersion" : "s3:GetObject";
        String sourceResource = AwsArnUtils.Arn.of("s3", "", "", parsed.bucket() + "/" + parsed.key()).toString();
        List<String> resourcePolicies = resourcePolicyResolver.resolve("s3", sourceResource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, "s3", sourceAction, ctx, region);

        Decision decision = evaluator.evaluate(caller, resourcePolicies, sourceAction, sourceResource, conditionCtx);
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} copySource",
                    akid, sourceAction, sourceResource);
            ctx.abortWith(accessDeniedResponse(sourceAction, "s3", ctx.getMediaType()));
        }
    }

    private record ParsedS3CopySource(String bucket, String key, String versionId) {
    }

    /**
     * Mirrors {@code S3Controller}'s copy-source parsing: strip a leading {@code '/'}, URL-decode
     * the remainder, split on the first {@code '/'} into bucket and key, then pull an optional
     * {@code versionId} query parameter off the key.
     */
    private static ParsedS3CopySource parseS3CopySource(String copySource) {
        String source = copySource.startsWith("/") ? copySource.substring(1) : copySource;
        String decoded;
        try {
            decoded = URLDecoder.decode(source, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        int slashIndex = decoded.indexOf('/');
        if (slashIndex <= 0) {
            return null;
        }
        String bucket = decoded.substring(0, slashIndex);
        String pathAfterBucket = decoded.substring(slashIndex + 1);

        int queryStart = pathAfterBucket.indexOf('?');
        if (queryStart < 0) {
            return new ParsedS3CopySource(bucket, pathAfterBucket, null);
        }
        String key = pathAfterBucket.substring(0, queryStart);
        String query = pathAfterBucket.substring(queryStart + 1);
        String versionId = null;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            if ("versionId".equals(pair.substring(0, eq))) {
                versionId = pair.substring(eq + 1);
                break;
            }
        }
        return new ParsedS3CopySource(bucket, key, versionId);
    }

    private static boolean isDynamoDbBatchExecuteStatement(String credentialScope, ContainerRequestContext ctx) {
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.endsWith(".BatchExecuteStatement")) {
            return false;
        }
        return "dynamodb".equals(credentialScope);
    }

    private boolean isDynamoDbMultiTableExecuteStatement(String credentialScope, ContainerRequestContext ctx) {
        if (!"dynamodb".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.endsWith(".ExecuteStatement")) {
            return false;
        }
        return arnBuilder.isMultiTablePartiQLExecuteStatement(ctx);
    }

    private static boolean isDynamoDbMultiTableRequestItems(String credentialScope, ContainerRequestContext ctx) {
        if (!"dynamodb".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null
                || (!target.endsWith(".BatchWriteItem") && !target.endsWith(".BatchGetItem"))) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            var items = node.get("RequestItems");
            return items != null && items.isObject() && items.size() > 1;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isDynamoDbTransactRequest(String credentialScope, ContainerRequestContext ctx) {
        if (!"dynamodb".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        return target != null
                && (target.endsWith(".TransactWriteItems") || target.endsWith(".TransactGetItems"));
    }

    private static boolean isSecretsManagerMultiSecretBatch(String credentialScope, ContainerRequestContext ctx) {
        if (!"secretsmanager".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.endsWith(".BatchGetSecretValue")) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            var list = node.get("SecretIdList");
            if (list != null && list.isArray() && list.size() > 1) {
                return true;
            }
            // Filters path must not fall through to secret:* — authorize each matched secret.
            var filters = node.get("Filters");
            return filters != null && filters.isArray() && !filters.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isKmsReEncrypt(String credentialScope, ContainerRequestContext ctx) {
        if (!"kms".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        return target != null && target.endsWith(".ReEncrypt");
    }

    /**
     * AWS ReEncrypt requires {@code kms:ReEncryptFrom} on the source CMK (CiphertextBlob)
     * and {@code kms:ReEncryptTo} on {@code DestinationKeyId}.
     */
    private void evaluateKmsReEncryptDualAndAbortIfDenied(ContainerRequestContext ctx,
                                                          String credentialScope,
                                                          String akid,
                                                          String region,
                                                          String accountId,
                                                          boolean strict) {
        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse("kms:ReEncryptFrom", credentialScope, ctx.getMediaType()));
            return;
        }

        String sourceResource = arnBuilder.build("kms", ctx, region, accountId);
        if (denyUnresolvedResource(ctx, sourceResource, "kms:ReEncryptFrom", credentialScope, akid, strict)) {
            return;
        }
        String destResource = arnBuilder.buildKmsDestinationKeyArn(ctx, region, accountId);
        if (denyUnresolvedResource(ctx, destResource, "kms:ReEncryptTo", credentialScope, akid, strict)) {
            return;
        }

        if (!authorizeKmsAction(caller, "kms:ReEncryptFrom", sourceResource, akid, accountId, region, ctx)
                || !authorizeKmsAction(caller, "kms:ReEncryptTo", destResource, akid, accountId, region, ctx)) {
            return;
        }
    }

    private boolean authorizeKmsAction(CallerContext caller,
                                       String action,
                                       String resource,
                                       String akid,
                                       String accountId,
                                       String region,
                                       ContainerRequestContext ctx) {
        List<String> resourcePolicies = resourcePolicyResolver.resolve("kms", resource, region);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, "kms", action, ctx, region);
        Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
        if (decision == Decision.DENY
                && kmsService.isGrantAuthorized(
                        conditionCtx.get("aws:principalarn"),
                        conditionCtx.get("aws:principalaccount"),
                        resource,
                        action,
                        region)) {
            return true;
        }
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2}", akid, action, resource);
            ctx.abortWith(accessDeniedResponse(action, "kms", ctx.getMediaType()));
            return false;
        }
        return true;
    }

    private void evaluateDynamoDbRequestItemsAndAbortIfDenied(ContainerRequestContext ctx,
                                                              String credentialScope,
                                                              String akid,
                                                              String region,
                                                              String accountId,
                                                              boolean strict) {
        evaluateMultiResourceAndAbortIfDenied(
                ctx, credentialScope, akid, region, accountId, strict,
                arnBuilder.buildAllDynamoDbRequestItemsResources(ctx, region, accountId),
                "dynamodbRequestItems");
    }

    private void evaluateDynamoDbTransactAndAbortIfDenied(ContainerRequestContext ctx,
                                                          String credentialScope,
                                                          String akid,
                                                          String region,
                                                          String accountId,
                                                          boolean strict) {
        List<String> resources = arnBuilder.buildAllDynamoDbTransactResources(ctx, region, accountId);
        if (resources.isEmpty()) {
            // No extractable tables — deny rather than fall back to table/*.
            String action = actionRegistry.resolve(credentialScope, ctx);
            if (action == null) {
                action = credentialScope + ":*";
            }
            LOG.infov("IAM enforcement DENY: akid={0} action={1} empty TransactItems tables", akid, action);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            return;
        }
        evaluateMultiResourceAndAbortIfDenied(
                ctx, credentialScope, akid, region, accountId, strict, resources, "dynamodbTransact");
    }

    private void evaluateSecretsManagerBatchAndAbortIfDenied(ContainerRequestContext ctx,
                                                             String credentialScope,
                                                             String akid,
                                                             String region,
                                                             String accountId,
                                                             boolean strict) {
        evaluateMultiResourceAndAbortIfDenied(
                ctx, credentialScope, akid, region, accountId, strict,
                arnBuilder.buildAllSecretsManagerBatchResources(ctx, region, accountId),
                "secretsManagerBatch");
    }

    private void evaluateMultiResourceAndAbortIfDenied(ContainerRequestContext ctx,
                                                       String credentialScope,
                                                       String akid,
                                                       String region,
                                                       String accountId,
                                                       boolean strict,
                                                       List<String> resources,
                                                       String reason) {
        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            denyUnmappedAction(ctx, credentialScope, reason);
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

        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, action, ctx, region);
        for (String resource : resources) {
            MultiResourceGate gate = gateMultiResourceEntry(resource, strict);
            if (gate == MultiResourceGate.DENIED) {
                LOG.infov("IAM enforcement DENY: unresolved resource akid={0} action={1} {2}",
                        akid, action, reason);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
            if (gate == MultiResourceGate.SKIP) {
                continue;
            }
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} {3}",
                        akid, action, resource, reason);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
    }

    private void evaluateDynamoDbMultiTableExecuteAndAbortIfDenied(ContainerRequestContext ctx,
                                                                  String credentialScope,
                                                                  String akid,
                                                                  String region,
                                                                  String accountId,
                                                                  boolean strict) {
        String action = actionRegistry.resolve(credentialScope, ctx);
        if (action == null) {
            denyUnmappedAction(ctx, credentialScope, "ExecuteStatement");
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

        List<String> resources = arnBuilder.buildAllDynamoDbExecuteStatementPartiQLResources(ctx, region, accountId);
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, action, ctx, region);

        for (String resource : resources) {
            MultiResourceGate gate = gateMultiResourceEntry(resource, strict);
            if (gate == MultiResourceGate.DENIED) {
                LOG.infov("IAM enforcement DENY: unresolved resource akid={0} action={1} partiqlMultiTable",
                        akid, action);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
            if (gate == MultiResourceGate.SKIP) {
                continue;
            }
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
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2} partiqlMultiTable",
                        akid, action, resource);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
        }
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
            denyUnmappedAction(ctx, credentialScope, "empty BatchExecuteStatement");
            return;
        }

        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            LOG.infov("IAM enforcement DENY: unknown access key {0}", akid);
            ctx.abortWith(accessDeniedResponse("dynamodb:BatchExecuteStatement", credentialScope, ctx.getMediaType()));
            return;
        }

        int count = Math.min(actions.size(), resources.size());

        for (int i = 0; i < count; i++) {
            String action = actions.get(i);
            if (action == null) {
                denyUnmappedAction(ctx, credentialScope, "PartiQL statement index=" + i);
                return;
            }

            if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(action)) {
                continue;
            }

            String resource = resources.get(i);
            MultiResourceGate gate = gateMultiResourceEntry(resource, strict);
            if (gate == MultiResourceGate.DENIED) {
                LOG.infov("IAM enforcement DENY: unresolved resource akid={0} batchIndex={1}", akid, i);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
            if (gate == MultiResourceGate.SKIP) {
                continue;
            }
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
            Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, action, ctx, region);
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
            denyUnmappedAction(ctx, credentialScope, "EMR multi-cluster");
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
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, action, ctx, region);

        for (String resource : resources) {
            MultiResourceGate gate = gateMultiResourceEntry(resource, strict);
            if (gate == MultiResourceGate.DENIED) {
                LOG.infov("IAM enforcement DENY: unresolved resource akid={0} action={1} emrMultiCluster",
                        akid, action);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
            if (gate == MultiResourceGate.SKIP) {
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

    private static boolean isEventsMultiBusPutEvents(String credentialScope, ContainerRequestContext ctx) {
        if (!"events".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.endsWith(".PutEvents")) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            var entries = node.get("Entries");
            if (entries == null || !entries.isArray() || entries.size() <= 1) {
                return false;
            }
            java.util.Set<String> buses = new java.util.HashSet<>();
            for (var entry : entries) {
                String bus = entry.path("EventBusName").asText(null);
                buses.add((bus == null || bus.isBlank()) ? "default" : bus);
            }
            return buses.size() > 1;
        } catch (Exception e) {
            return false;
        }
    }

    private void evaluateEventsMultiBusAndAbortIfDenied(ContainerRequestContext ctx,
                                                        String credentialScope,
                                                        String akid,
                                                        String region,
                                                        String accountId,
                                                        boolean strict) {
        evaluateMultiResourceAndAbortIfDenied(
                ctx, credentialScope, akid, region, accountId, strict,
                arnBuilder.buildAllEventsPutEventsResources(ctx, region, accountId),
                "eventsPutEventsMultiBus");
    }

    private static boolean isLogsMultiGroupStartQuery(String credentialScope, ContainerRequestContext ctx) {
        if (!"logs".equals(credentialScope)) {
            return false;
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.endsWith(".StartQuery")) {
            return false;
        }
        byte[] body = RequestBodyBuffer.buffer(ctx);
        if (body.length == 0) {
            return false;
        }
        try {
            var node = EMR_BODY_MAPPER.readTree(body);
            int count = 0;
            count += logGroupArrayCount(node, "logGroupNames");
            count += logGroupArrayCount(node, "logGroupIdentifiers");
            return count > 1;
        } catch (Exception e) {
            return false;
        }
    }

    private static int logGroupArrayCount(JsonNode node, String fieldName) {
        var array = node.get(fieldName);
        return array != null && array.isArray() ? array.size() : 0;
    }

    private void evaluateLogsMultiGroupAndAbortIfDenied(ContainerRequestContext ctx,
                                                        String credentialScope,
                                                        String akid,
                                                        String region,
                                                        String accountId,
                                                        boolean strict) {
        evaluateMultiResourceAndAbortIfDenied(
                ctx, credentialScope, akid, region, accountId, strict,
                arnBuilder.buildAllLogsStartQueryResources(ctx, region, accountId),
                "logsStartQueryMultiGroup");
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
            denyUnmappedAction(ctx, credentialScope, "tagging");
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
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, credentialScope, action, ctx, region);

        if (resources.size() == 1 && ResourceRef.isUnresolvedToken(resources.getFirst())) {
            if (denyUnresolvedResource(ctx, resources.getFirst(), action, credentialScope, akid, strict)) {
                return;
            }
            // Non-strict lab: evaluate as intentional Resource:* (historical tagging fallback).
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, "*", region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, "*", conditionCtx);
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource=* taggingUnresolved", akid, action);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        if (resources.size() == 1 && "*".equals(resources.getFirst())) {
            // Intentional tagging wildcard (GetTagKeys/GetTagValues).
            List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, "*", region);
            Decision decision = evaluator.evaluate(caller, resourcePolicies, action, "*", conditionCtx);
            if (decision == Decision.DENY) {
                LOG.infov("IAM enforcement DENY: akid={0} action={1} resource=* taggingMultiArn", akid, action);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
            }
            return;
        }

        for (String resource : resources) {
            MultiResourceGate gate = gateMultiResourceEntry(resource, strict);
            if (gate == MultiResourceGate.DENIED) {
                LOG.infov("IAM enforcement DENY: unresolved resource akid={0} action={1} taggingMultiArn",
                        akid, action);
                ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
                return;
            }
            if (gate == MultiResourceGate.SKIP) {
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

    private void denyUnmappedAction(ContainerRequestContext ctx, String credentialScope, String reason) {
        String unknownAction = credentialScope + ":*";
        LOG.infov("IAM enforcement DENY: unmapped {0} scope={1}", reason, credentialScope);
        ctx.abortWith(accessDeniedResponse(unknownAction, credentialScope, ctx.getMediaType()));
    }

    private boolean denyUnresolvedResource(ContainerRequestContext ctx,
                                           String resource,
                                           String action,
                                           String credentialScope,
                                           String akid,
                                           boolean strict) {
        if (!ResourceRef.isUnresolvedToken(resource)) {
            return false;
        }
        if (!strict) {
            return false;
        }
        LOG.infov("IAM enforcement DENY: unresolved resource akid={0} action={1} resource={2}",
                akid, action, resource);
        ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
        return true;
    }

    /**
     * Under CTF/strict, UNRESOLVED denies and bare {@code *} is evaluated (not skipped).
     * Non-strict keeps the historical skip for bare {@code *} / unresolved tokens.
     */
    private static MultiResourceGate gateMultiResourceEntry(String resource, boolean strict) {
        if (ResourceRef.isUnresolvedToken(resource)) {
            return strict ? MultiResourceGate.DENIED : MultiResourceGate.SKIP;
        }
        if ("*".equals(resource) && !strict) {
            return MultiResourceGate.SKIP;
        }
        return MultiResourceGate.EVALUATE;
    }

    private enum MultiResourceGate {
        EVALUATE,
        SKIP,
        DENIED
    }

    private Map<String, String> buildConditionContext(String accessKeyId,
                                                      String accountId,
                                                      String credentialScope,
                                                      String action,
                                                      ContainerRequestContext ctx,
                                                      String region) {
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
        if (region != null && !region.isBlank()) {
            out.put("aws:requestedregion", region);
        }
        Instant now = Instant.now();
        out.put("aws:currenttime", now.toString());
        out.put("aws:epochtime", String.valueOf(now.getEpochSecond()));
        if ("s3".equals(credentialScope)) {
            enrichS3ConditionKeys(ctx, out);
        }
        Map<String, String> actionConditions = conditionContextResolver.resolve(credentialScope, action, ctx);
        if (actionConditions != null) {
            out.putAll(actionConditions);
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
