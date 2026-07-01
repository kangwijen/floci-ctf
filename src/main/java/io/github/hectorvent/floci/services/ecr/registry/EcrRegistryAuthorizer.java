package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Evaluates IAM identity and repository resource policies for ECR registry HTTP requests.
 */
@ApplicationScoped
public class EcrRegistryAuthorizer {

    private static final Logger LOG = Logger.getLogger(EcrRegistryAuthorizer.class);

    private final EmulatorConfig config;
    private final IamService iamService;
    private final IamPolicyEvaluator evaluator;
    private final ResourcePolicyResolver resourcePolicyResolver;

    @Inject
    public EcrRegistryAuthorizer(EmulatorConfig config,
                                 IamService iamService,
                                 IamPolicyEvaluator evaluator,
                                 ResourcePolicyResolver resourcePolicyResolver) {
        this.config = config;
        this.iamService = iamService;
        this.evaluator = evaluator;
        this.resourcePolicyResolver = resourcePolicyResolver;
    }

    /**
     * @return empty when allowed; otherwise a short denial reason for logging
     */
    public Optional<String> authorize(EcrRegistryAuthSession session, EcrRegistryRouteResolver.ResolvedRoute route) {
        if (!config.services().iam().enforcementEnabled()) {
            return Optional.empty();
        }
        if (route.iamAction() == null || route.repositoryArn() == null) {
            return Optional.empty();
        }

        String accessKeyId = session.accessKeyId();
        if (accessKeyId != null
                && config.auth().rootAccessKeyId().filter(accessKeyId::equals).isPresent()) {
            return Optional.empty();
        }

        CallerContext caller = iamService.resolveCallerContext(accessKeyId);
        if (caller == null) {
            return Optional.of("unknown access key");
        }

        if (IamUnrestrictedActions.isExemptFromPolicyEvaluation(route.iamAction())) {
            return Optional.empty();
        }

        String region = route.region() != null ? route.region() : session.region();
        List<String> resourcePolicies = resourcePolicyResolver.resolve("ecr", route.repositoryArn(), region);
        Map<String, String> conditionCtx = buildConditionContext(accessKeyId, session.accountId());

        Decision decision = evaluator.evaluate(
                caller, resourcePolicies, route.iamAction(), route.repositoryArn(), conditionCtx);
        if (decision == Decision.DENY) {
            LOG.infov("ECR registry IAM DENY: akid={0} action={1} resource={2}",
                    accessKeyId, route.iamAction(), route.repositoryArn());
            return Optional.of("access denied");
        }
        return Optional.empty();
    }

    private Map<String, String> buildConditionContext(String accessKeyId, String accountId) {
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
        out.put("aws:sourceip", "127.0.0.1");
        return out;
    }
}
