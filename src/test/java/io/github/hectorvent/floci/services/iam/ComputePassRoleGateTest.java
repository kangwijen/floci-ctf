package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("security-regression")
class ComputePassRoleGateTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/ec2-role";
    private static final String PROFILE_ARN =
            "arn:aws:iam::000000000000:instance-profile/my-profile";

    private InProcessIamAuthorizer iamAuthorizer;
    private IamService iamService;
    private ComputePassRoleGate gate;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        iamService = mock(IamService.class);
        gate = new ComputePassRoleGate(iamAuthorizer, iamService);
    }

    @Test
    void authorizeEcsTaskRolesPassesBothRoles() {
        gate.authorizeEcsTaskRoles("arn:aws:iam::000000000000:role/task",
                "arn:aws:iam::000000000000:role/exec", REGION);

        verify(iamAuthorizer).authorizePassRole(
                "arn:aws:iam::000000000000:role/task", ComputePassRoleGate.ECS_TASKS_SERVICE, REGION);
        verify(iamAuthorizer).authorizePassRole(
                "arn:aws:iam::000000000000:role/exec", ComputePassRoleGate.ECS_TASKS_SERVICE, REGION);
    }

    @Test
    void authorizeLambdaExecutionRolePassesLambdaPrincipal() {
        gate.authorizeLambdaExecutionRole(ROLE_ARN, REGION);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, ComputePassRoleGate.LAMBDA_SERVICE, REGION);
    }

    @Test
    void authorizeEc2InstanceProfilePassesAttachedRoles() {
        InstanceProfile profile = new InstanceProfile("AIPA", "my-profile", "/", PROFILE_ARN);
        profile.setRoleNames(List.of("ec2-role"));
        IamRole role = new IamRole("AROA", "ec2-role", "/", ROLE_ARN, "{}");
        when(iamService.getInstanceProfile("my-profile")).thenReturn(profile);
        when(iamService.getRole("ec2-role")).thenReturn(role);

        gate.authorizeEc2InstanceProfile(PROFILE_ARN, REGION);

        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, ComputePassRoleGate.EC2_SERVICE, REGION);
    }

    @Test
    void authorizeEc2InstanceProfileSkipsBlank() {
        gate.authorizeEc2InstanceProfile("  ", REGION);
        verify(iamService, never()).getInstanceProfile(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void authorizeEc2InstanceProfileDeniesUnknownProfile() {
        when(iamService.getInstanceProfile("missing"))
                .thenThrow(new AwsException("NoSuchEntity", "missing", 404));

        AwsException ex = assertThrows(AwsException.class,
                () -> gate.authorizeEc2InstanceProfile(
                        "arn:aws:iam::000000000000:instance-profile/missing", REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
        verify(iamAuthorizer, never()).authorizePassRole(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void authorizeEc2InstanceProfilePropagatesPassRoleDeny() {
        InstanceProfile profile = new InstanceProfile("AIPA", "my-profile", "/", PROFILE_ARN);
        profile.setRoleNames(List.of("ec2-role"));
        IamRole role = new IamRole("AROA", "ec2-role", "/", ROLE_ARN, "{}");
        when(iamService.getInstanceProfile("my-profile")).thenReturn(profile);
        when(iamService.getRole("ec2-role")).thenReturn(role);
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq(ComputePassRoleGate.EC2_SERVICE), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> gate.authorizeEc2InstanceProfile(PROFILE_ARN, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void instanceProfileNameExtractsFromArn() {
        assertEquals("my-profile", ComputePassRoleGate.instanceProfileName(PROFILE_ARN));
        assertEquals("bare-name", ComputePassRoleGate.instanceProfileName("bare-name"));
    }
}
