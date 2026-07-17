package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Thin PassRole helpers for compute create paths (ECS task/execution roles, EC2 instance
 * profiles, Lambda execution roles). Keeps god-class services from embedding profile-resolution
 * and service-principal constants.
 */
@ApplicationScoped
public class ComputePassRoleGate {

    public static final String ECS_TASKS_SERVICE = "ecs-tasks.amazonaws.com";
    public static final String EC2_SERVICE = "ec2.amazonaws.com";
    public static final String LAMBDA_SERVICE = "lambda.amazonaws.com";

    private final InProcessIamAuthorizer iamAuthorizer;
    private final IamService iamService;

    @Inject
    public ComputePassRoleGate(InProcessIamAuthorizer iamAuthorizer, IamService iamService) {
        this.iamAuthorizer = iamAuthorizer;
        this.iamService = iamService;
    }

    public void authorizeEcsTaskRoles(String taskRoleArn, String executionRoleArn, String region) {
        iamAuthorizer.authorizePassRole(taskRoleArn, ECS_TASKS_SERVICE, region);
        iamAuthorizer.authorizePassRole(executionRoleArn, ECS_TASKS_SERVICE, region);
    }

    public void authorizeLambdaExecutionRole(String roleArn, String region) {
        iamAuthorizer.authorizePassRole(roleArn, LAMBDA_SERVICE, region);
    }

    /**
     * Authorizes {@code iam:PassRole} for each role attached to the instance profile being
     * associated with an EC2 instance. Blank profile refs are a no-op.
     */
    public void authorizeEc2InstanceProfile(String instanceProfileArnOrName, String region) {
        if (instanceProfileArnOrName == null || instanceProfileArnOrName.isBlank()) {
            return;
        }
        String profileName = instanceProfileName(instanceProfileArnOrName);
        InstanceProfile profile;
        try {
            profile = iamService.getInstanceProfile(profileName);
        } catch (AwsException ex) {
            throw new AwsException("AccessDeniedException",
                    "User is not authorized to perform: iam:PassRole on instance profile: "
                            + instanceProfileArnOrName, 403);
        }
        for (String roleName : profile.getRoleNames()) {
            IamRole role = iamService.getRole(roleName);
            iamAuthorizer.authorizePassRole(role.getArn(), EC2_SERVICE, region);
        }
    }

    static String instanceProfileName(String arnOrName) {
        if (arnOrName == null) {
            return null;
        }
        String marker = "instance-profile/";
        int idx = arnOrName.indexOf(marker);
        if (idx >= 0) {
            return arnOrName.substring(idx + marker.length());
        }
        return arnOrName;
    }
}
