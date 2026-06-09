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
