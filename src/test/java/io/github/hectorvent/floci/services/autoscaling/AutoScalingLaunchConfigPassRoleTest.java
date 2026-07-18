package io.github.hectorvent.floci.services.autoscaling;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.ComputePassRoleGate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * E-FO-02: CreateLaunchConfiguration with IamInstanceProfile must require iam:PassRole.
 */
@Tag("security-regression")
class AutoScalingLaunchConfigPassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String PROFILE_ARN =
            "arn:aws:iam::000000000000:instance-profile/asg-profile";

    private ComputePassRoleGate passRoleGate;
    private AutoScalingService service;

    @BeforeEach
    void setUp() {
        passRoleGate = mock(ComputePassRoleGate.class);
        service = new AutoScalingService();
        service.regionResolver = new RegionResolver(REGION, "000000000000");
        service.passRoleGate = passRoleGate;
    }

    @Test
    void createLaunchConfigurationRequiresPassRoleOnInstanceProfile() {
        service.createLaunchConfiguration(REGION, "passrole-lc", null,
                "ami-12345678", "t3.micro", null, List.of(), null, PROFILE_ARN, false);

        verify(passRoleGate).authorizeEc2InstanceProfile(PROFILE_ARN, REGION);
    }

    @Test
    void createLaunchConfigurationDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeEc2InstanceProfile(eq(PROFILE_ARN), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createLaunchConfiguration(REGION, "denied-lc", null,
                        "ami-12345678", "t3.micro", null, List.of(), null, PROFILE_ARN, false));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }
}
