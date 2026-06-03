package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
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
 * {@code floci.iam.enforcement-enabled = true}.
 *
 * <p>Evaluates identity-based policies and resource-based policies (S3 bucket policy,
 * Lambda resource policy, SQS/SNS/KMS/Secrets Manager policies) via {@link ResourcePolicyResolver}.
 *
 * <p>Pre-signed S3 URLs: after {@link PreSignedUrlFilter} validates the Floci HMAC, bucket
 * and identity policies are evaluated (HMAC secret does not bypass IAM).
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 20)
public class IamEnforcementFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(IamEnforcementFilter.class);

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

    @Inject
    public IamEnforcementFilter(EmulatorConfig config,
                                AccountResolver accountResolver,
                                IamService iamService,
                                IamPolicyEvaluator evaluator,
                                IamActionRegistry actionRegistry,
                                ResourceArnBuilder arnBuilder,
                                ResourcePolicyResolver resourcePolicyResolver,
                                RegionResolver regionResolver) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.actionRegistry = actionRegistry;
        this.arnBuilder = arnBuilder;
        this.resourcePolicyResolver = resourcePolicyResolver;
        this.regionResolver = regionResolver;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }

        boolean strict = config.services().iam().strictEnforcementEnabled();

        if (SecurityBypassPaths.isPresignedUrlRequest(ctx)) {
            if (Boolean.TRUE.equals(ctx.getProperty(PreSignedUrlFilter.PRESIGN_VERIFIED_PROPERTY))) {
                enforcePresignedS3(ctx, strict);
            } else if (strict
                    && !SecurityBypassPaths.isInternalHealthOrInfoPath(
                            ctx.getUriInfo().getPath(), config.ctf().hideInternalEndpointsMode())
                    && config.auth().validateSignatures()) {
                LOG.infov("IAM strict enforcement DENY: unverified pre-signed URL on {0}",
                        ctx.getUriInfo().getPath());
                ctx.abortWith(accessDeniedResponse("s3:GetObject", "s3", ctx.getMediaType()));
            }
            return;
        }

        String auth = ctx.getHeaderString("Authorization");
        if (auth == null) {
            if (strict && !SecurityBypassPaths.isInternalHealthOrInfoPath(
                    ctx.getUriInfo().getPath(), config.ctf().hideInternalEndpointsMode())) {
                LOG.infov("IAM strict enforcement DENY: missing Authorization header on {0}",
                        ctx.getUriInfo().getPath());
                ctx.abortWith(accessDeniedResponse("MissingAuthentication", null, ctx.getMediaType()));
            }
            return;
        }

        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            return;
        }
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return;
        }

        String credentialScope = extractCredentialScope(auth);
        if (credentialScope == null) {
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
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, ctx);

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
        Map<String, String> conditionCtx = buildConditionContext(akid, accountId, ctx);

        Decision decision = evaluator.evaluate(caller, resourcePolicies, action, resource, conditionCtx);
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: akid={0} action={1} resource={2}", akid, action, resource);
            ctx.abortWith(accessDeniedResponse(action, credentialScope, ctx.getMediaType()));
        }
    }

    private Map<String, String> buildConditionContext(String accessKeyId,
                                                      String accountId,
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
        String sourceIp = ctx.getHeaderString("X-Forwarded-For");
        if (sourceIp == null || sourceIp.isBlank()) {
            sourceIp = "127.0.0.1";
        } else {
            int comma = sourceIp.indexOf(',');
            if (comma > 0) {
                sourceIp = sourceIp.substring(0, comma).trim();
            }
        }
        out.put("aws:sourceip", sourceIp);
        return out;
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
        if (isFormEncoded(requestMediaType)) {
            return queryXmlAccessDenied(message);
        }
        return jsonAccessDenied(message);
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
        String body = "{\"__type\":\"AccessDeniedException\",\"message\":\"" + message + "\"}";
        return Response.status(403).type(MediaType.APPLICATION_JSON).entity(body).build();
    }
}
