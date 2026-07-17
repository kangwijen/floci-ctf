package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Evaluates IAM policies for in-process service calls (Step Functions task integrations,
 * API Gateway AWS integrations) that bypass {@link io.github.hectorvent.floci.core.common.IamEnforcementFilter}.
 *
 * <p>When enforcement is enabled and a caller role ARN is supplied, identity and resource
 * policies are evaluated the same way as HTTP requests. Calls without an execution role
 * are always denied when enforcement is on.
 *
 * <p>Grant fallback mirrors {@link io.github.hectorvent.floci.core.common.IamEnforcementFilter}:
 * only KMS data-plane grants ({@link KmsService#isGrantAuthorized}) can authorize when identity
 * and resource policies deny. S3, Secrets Manager, and other services have no grant model in
 * this emulator.
 */
@ApplicationScoped
public class InProcessIamAuthorizer {

    private static final Logger LOG = Logger.getLogger(InProcessIamAuthorizer.class);

    private final EmulatorConfig config;
    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final ResourceArnBuilder arnBuilder;
    private final ResourcePolicyResolver resourcePolicyResolver;
    private final RegionResolver regionResolver;
    private final KmsService kmsService;

    @Inject
    public InProcessIamAuthorizer(EmulatorConfig config,
                                  IamService iamService,
                                  IamPolicyEvaluator evaluator,
                                  ResourceArnBuilder arnBuilder,
                                  ResourcePolicyResolver resourcePolicyResolver,
                                  RegionResolver regionResolver,
                                  KmsService kmsService) {
        this.config = config;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.arnBuilder = arnBuilder;
        this.resourcePolicyResolver = resourcePolicyResolver;
        this.regionResolver = regionResolver;
        this.kmsService = kmsService;
    }

    /**
     * Authorizes {@code iam:PassRole} for the caller of the current request against a role ARN
     * being attached to a service resource (Step Functions state machine, EventBridge Scheduler
     * schedule, EventBridge Pipes pipe, or a Lambda function's execution role).
     *
     * <p>AWS requires {@code iam:PassRole} on the caller's identity — separate from whatever
     * permission created the resource itself — with the {@code iam:PassedToService} condition key
     * set to the service principal that will assume the role. Without this, any caller who can
     * create the resource can silently reuse any role that exists in the account, regardless of
     * whether they are allowed to pass it.
     *
     * <p>Resolves the caller from {@link RegionResolver#getCallerAccessKeyId()} so this works both
     * for the direct HTTP creation path (JAX-RS request scope) and for CloudFormation-driven
     * creation, where {@link io.github.hectorvent.floci.services.cloudformation.CloudFormationService}
     * activates a synthetic request scope carrying the stack-creator's access key on the background
     * provisioning thread. When no caller can be resolved (root credentials, unauthenticated
     * internal callers, or no active request scope) the check is skipped rather than denied, matching
     * the "unknown key — bypass" behavior {@link IamService#resolveCallerContext} already uses
     * elsewhere in this class.
     *
     * @param roleArn         the role being attached; a blank value is a no-op (the caller's own
     *                        validation is responsible for rejecting a missing role)
     * @param servicePrincipal the AWS service principal that will assume the role
     *                        (e.g. {@code states.amazonaws.com})
     * @param region          AWS region, used for identity-based policy condition evaluation
     */
    public void authorizePassRole(String roleArn, String servicePrincipal, String region) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (roleArn == null || roleArn.isBlank()) {
            return;
        }
        String akid = regionResolver.getCallerAccessKeyId();
        if (akid == null || akid.isBlank()) {
            return;
        }
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return;
        }
        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            return;
        }

        String accountId = regionResolver.getAccountId();
        Optional<String> callerArn = iamService.resolveCallerArn(akid);
        Map<String, String> conditionCtx = buildConditionContext(
                callerArn.orElse("arn:aws:iam::" + accountId + ":root"), accountId);
        conditionCtx.put("iam:passedtoservice", servicePrincipal);
        if (region != null && !region.isBlank()) {
            conditionCtx.put("aws:requestedregion", region);
        }

        Decision decision = evaluator.evaluate(caller, List.of(), "iam:PassRole", roleArn, conditionCtx);
        if (decision == Decision.DENY) {
            LOG.infov("In-process IAM DENY (PassRole): akid={0} role={1} service={2}",
                    akid, roleArn, servicePrincipal);
            throw new AwsException("AccessDeniedException",
                    "User: " + callerArn.orElse(akid) + " is not authorized to perform: iam:PassRole on resource: "
                            + roleArn, 403);
        }
    }

    /**
     * Authorizes an IAM action for the caller of the current request against a specific resource
     * ARN, independent of any execution role. Used by privileged CloudFormation resource types
     * ({@code AWS::IAM::Role}, {@code AWS::IAM::User}, {@code AWS::IAM::AccessKey}, ...) whose
     * provisioning bypasses HTTP IAM enforcement entirely when run from the stack's background
     * executor thread.
     *
     * <p>Unlike {@link #authorizePassRole}, an unresolvable caller is denied rather than skipped:
     * this method gates the ability to mint new IAM principals, so failing open on an
     * unauthenticated or unknown caller would defeat the purpose of the check.
     *
     * @param iamAction   canonical action, e.g. {@code iam:CreateRole}
     * @param resourceArn target resource ARN (or {@code "*"} when the action has no path-scoped
     *                    resource, e.g. before the physical name is known)
     * @param region      AWS region
     */
    public void authorizeCallerAction(String iamAction, String resourceArn, String region) {
        authorizeCallerAction(iamAction, resourceArn, region, "iam");
    }

    /**
     * Same as {@link #authorizeCallerAction(String, String, String)}, but resolves resource-based
     * policies (bucket policies, key policies, ...) under the given SigV4 credential scope instead
     * of always assuming an IAM-domain resource. Used when the gated action targets a resource in a
     * different service, e.g. {@code s3:GetObject} on a CloudFormation {@code TemplateURL}.
     */
    public void authorizeCallerAction(String iamAction, String resourceArn, String region, String credentialScope) {
        authorizeExplicitCaller(regionResolver.getCallerAccessKeyId(), iamAction, resourceArn, region, credentialScope);
    }

    /**
     * Same as {@link #authorizeCallerAction(String, String, String, String)}, but takes the caller's
     * access key ID directly instead of resolving it from {@link RegionResolver#getCallerAccessKeyId()}.
     * Used by callers outside the JAX-RS request scope that already have SigV4 credentials in hand,
     * e.g. the WebSocket handler, which registers on the Vert.x router and never enters a JAX-RS
     * {@code ContainerRequestContext}.
     */
    public void authorizeExplicitCaller(String akid, String iamAction, String resourceArn, String region,
                                        String credentialScope) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (akid == null || akid.isBlank()) {
            denyCallerAction(iamAction, resourceArn, "unknown", "no caller identity");
            return;
        }
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return;
        }
        CallerContext caller = iamService.resolveCallerContext(akid);
        if (caller == null) {
            denyCallerAction(iamAction, resourceArn, akid, "unknown access key");
            return;
        }
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(iamAction)) {
            return;
        }

        String accountId = regionResolver.getAccountId();
        String resource = resourceArn != null && !resourceArn.isBlank() ? resourceArn : "*";
        List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
        Optional<String> callerArn = iamService.resolveCallerArn(akid);
        Map<String, String> conditionCtx = buildConditionContext(
                callerArn.orElse("arn:aws:iam::" + accountId + ":root"), accountId);

        Decision decision = evaluator.evaluate(caller, resourcePolicies, iamAction, resource, conditionCtx);
        if (decision == Decision.DENY) {
            denyCallerAction(iamAction, resourceArn, akid, "policy evaluation denied");
        }
    }

    private void denyCallerAction(String iamAction, String resourceArn, String akid, String reason) {
        LOG.infov("In-process IAM DENY ({0}): akid={1} action={2} resource={3}",
                reason, akid, iamAction, resourceArn);
        throw new AwsException("AccessDeniedException",
                "User: " + akid + " is not authorized to perform: " + iamAction, 403);
    }

    /**
     * Authorizes an in-process integration call using the supplied IAM role ARN.
     *
     * @param roleArn         execution role (SFN state machine role or APIGW integration credentials)
     * @param credentialScope SigV4 service scope (e.g. {@code secretsmanager}, {@code dynamodb})
     * @param action          API action name (e.g. {@code GetSecretValue}, {@code PutItem})
     * @param requestBody     JSON request body used for resource ARN extraction
     * @param region          AWS region
     */
    public void authorize(String roleArn,
                          String credentialScope,
                          String action,
                          JsonNode requestBody,
                          String region) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }

        if (roleArn == null || roleArn.isBlank()) {
            deny(credentialScope, action, roleArn, "missing execution role");
            return;
        }

        CallerContext caller = iamService.resolveCallerContextFromRoleArn(roleArn);
        if (caller == null) {
            deny(credentialScope, action, roleArn, "unknown execution role");
            return;
        }

        String iamAction = toIamAction(credentialScope, action);
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(iamAction)) {
            return;
        }

        String accountId = accountFromRoleArn(roleArn);
        String resource = arnBuilder.buildFromJsonBody(credentialScope, requestBody, region, accountId);
        evaluateRoleAccess(roleArn, caller, credentialScope, action, resource, region);
    }

    /**
     * Authorizes an in-process call when the target resource ARN is already known (pipes, scheduler, ESM).
     */
    public void authorizeWithResource(String roleArn,
                                      String credentialScope,
                                      String action,
                                      String resourceArn,
                                      String region) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (roleArn == null || roleArn.isBlank()) {
            deny(credentialScope, action, roleArn, "missing execution role");
            return;
        }
        CallerContext caller = iamService.resolveCallerContextFromRoleArn(roleArn);
        if (caller == null) {
            deny(credentialScope, action, roleArn, "unknown execution role");
            return;
        }
        evaluateRoleAccess(roleArn, caller, credentialScope, action, resourceArn, region);
    }

    /**
     * Authorizes query-protocol in-process integrations (API Gateway path-style URIs).
     */
    public void authorizeQuery(String roleArn,
                               String credentialScope,
                               String queryAction,
                               MultivaluedMap<String, String> params,
                               String region) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (roleArn == null || roleArn.isBlank()) {
            deny(credentialScope, queryAction, roleArn, "missing execution role");
            return;
        }
        CallerContext caller = iamService.resolveCallerContextFromRoleArn(roleArn);
        if (caller == null) {
            deny(credentialScope, queryAction, roleArn, "unknown execution role");
            return;
        }
        String iamAction = toIamAction(credentialScope, queryAction);
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(iamAction)) {
            return;
        }
        String accountId = accountFromRoleArn(roleArn);
        String resource = arnBuilder.buildFromQueryParams(credentialScope, params, region, accountId);
        evaluateRoleAccess(roleArn, caller, credentialScope, queryAction, resource, region);
    }

    /**
     * Authorizes service-to-service delivery using destination resource policies only.
     * Matches AWS EventBridge, SNS, CloudWatch Logs, and ELB Lambda invoke patterns.
     */
    public void authorizeServicePrincipal(String servicePrincipal,
                                          String credentialScope,
                                          String action,
                                          String resourceArn,
                                          String region) {
        authorizeServicePrincipal(servicePrincipal, credentialScope, action, resourceArn, region, null);
    }

    public void authorizeServicePrincipal(String servicePrincipal,
                                          String credentialScope,
                                          String action,
                                          String resourceArn,
                                          String region,
                                          String sourceArn) {
        authorizeServicePrincipal(servicePrincipal, credentialScope, action, resourceArn, region, sourceArn, null);
    }

    public void authorizeServicePrincipal(String servicePrincipal,
                                          String credentialScope,
                                          String action,
                                          String resourceArn,
                                          String region,
                                          String sourceArn,
                                          String sourceAccountId) {
        authorizeServicePrincipal(servicePrincipal, credentialScope, action, resourceArn, region,
                sourceArn, sourceAccountId, null);
    }

    public void authorizeServicePrincipal(String servicePrincipal,
                                          String credentialScope,
                                          String action,
                                          String resourceArn,
                                          String region,
                                          String sourceArn,
                                          String sourceAccountId,
                                          String cannedAcl) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        if (servicePrincipal == null || servicePrincipal.isBlank()) {
            deny(credentialScope, action, servicePrincipal, "missing service principal");
            return;
        }
        String iamAction = toIamAction(credentialScope, action);
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(iamAction)) {
            return;
        }
        String resource = resourceArn != null && !resourceArn.isBlank() ? resourceArn : "*";
        String accountId = AwsArnUtils.accountOrDefault(resource, "000000000000");
        List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
        Map<String, String> conditionCtx = buildConditionContext(servicePrincipal, accountId);
        if (sourceArn != null && !sourceArn.isBlank()) {
            conditionCtx.put("aws:sourcearn", sourceArn);
        }
        if (sourceAccountId != null && !sourceAccountId.isBlank()) {
            conditionCtx.put("aws:sourceaccount", sourceAccountId);
        }
        if (cannedAcl != null && !cannedAcl.isBlank()) {
            conditionCtx.put("s3:x-amz-acl", cannedAcl);
        }
        CallerContext emptyIdentity = CallerContext.of(List.of());
        Decision decision = evaluator.evaluate(emptyIdentity, resourcePolicies, iamAction, resource, conditionCtx);
        if (decision == Decision.DENY) {
            deny(credentialScope, action, servicePrincipal, "resource policy denied");
        }
    }

    private void evaluateRoleAccess(String roleArn,
                                    CallerContext caller,
                                    String credentialScope,
                                    String action,
                                    String resourceArn,
                                    String region) {
        String iamAction = toIamAction(credentialScope, action);
        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(iamAction)) {
            return;
        }
        String accountId = accountFromRoleArn(roleArn);
        String resource = resourceArn != null && !resourceArn.isBlank() ? resourceArn : "*";
        List<String> resourcePolicies = resourcePolicyResolver.resolve(credentialScope, resource, region);
        Map<String, String> conditionCtx = buildConditionContext(roleArn, accountId);
        Decision decision = evaluator.evaluate(caller, resourcePolicies, iamAction, resource, conditionCtx);
        if (decision == Decision.DENY
                && "kms".equals(credentialScope)
                && kmsService.isGrantAuthorized(
                        conditionCtx.get("aws:principalarn"),
                        conditionCtx.get("aws:principalaccount"),
                        resource,
                        iamAction,
                        region)) {
            return;
        }
        if (decision == Decision.DENY) {
            deny(credentialScope, action, roleArn, "policy evaluation denied");
        }
    }

    private void deny(String credentialScope, String action, String roleArn, String reason) {
        String iamAction = toIamAction(credentialScope, action);
        LOG.infov("In-process IAM DENY ({0}): role={1} action={2}", reason, roleArn, iamAction);
        throw new AwsException("AccessDeniedException",
                "User: " + (roleArn != null ? roleArn : "unknown")
                        + " is not authorized to perform: " + iamAction, 403);
    }

    static String toIamAction(String credentialScope, String action) {
        String normalized = normalizeAction(credentialScope, action);
        return IamUnrestrictedActions.canonicalAction(credentialScope + ":" + normalized);
    }

    private static String normalizeAction(String credentialScope, String action) {
        if (action == null || action.isBlank()) {
            return "*";
        }
        if ("dynamodb".equals(credentialScope)
                && action.length() > 0
                && Character.isLowerCase(action.charAt(0))) {
            return Character.toUpperCase(action.charAt(0)) + action.substring(1);
        }
        return action;
    }

    private static String accountFromRoleArn(String roleArn) {
        String account = AwsArnUtils.accountOrDefault(roleArn, null);
        return account != null && !account.isBlank() ? account : "000000000000";
    }

    private Map<String, String> buildConditionContext(String roleArn, String accountId) {
        Map<String, String> out = new HashMap<>();
        out.put("aws:principalarn", roleArn);
        out.put("aws:principalaccount", accountId);
        out.put("aws:sourceaccount", accountId);
        out.put("aws:sourcearn", roleArn);
        return out;
    }
}
