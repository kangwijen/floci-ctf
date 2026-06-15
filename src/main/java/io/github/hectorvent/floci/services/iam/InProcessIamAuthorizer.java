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
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
