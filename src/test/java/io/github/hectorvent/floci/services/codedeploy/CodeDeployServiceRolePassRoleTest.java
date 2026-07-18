package io.github.hectorvent.floci.services.codedeploy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.ssm.SsmCommandService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * E-FO-07: deployment-group serviceRoleArn create/update requires iam:PassRole.
 */
@Tag("security-regression")
class CodeDeployServiceRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/codedeploy-role";

    private InProcessIamAuthorizer iamAuthorizer;
    private CodeDeployService service;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        service = new CodeDeployService(
                mock(LambdaService.class), mock(EcsService.class), mock(ElbV2Service.class),
                mock(SsmCommandService.class), mock(Ec2Service.class), new ObjectMapper(),
                new RegionResolver(REGION, "000000000000"), null,
                null, iamAuthorizer);
        service.createApplication(REGION, "app", "Server", null);
    }

    @Test
    void createDeploymentGroupRequiresPassRole() {
        service.createDeploymentGroup(REGION, "app", "group", null, ROLE_ARN, Map.of());
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "codedeploy.amazonaws.com", REGION);
    }

    @Test
    void createDeploymentGroupDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("codedeploy.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createDeploymentGroup(REGION, "app", "denied", null, ROLE_ARN, Map.of()));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void updateDeploymentGroupRequiresPassRoleOnRoleChange() {
        service.createDeploymentGroup(REGION, "app", "upd", null, ROLE_ARN, Map.of());
        String newRole = "arn:aws:iam::000000000000:role/codedeploy-role-2";
        service.updateDeploymentGroup(REGION, "app", "upd", null, null, newRole, Map.of());
        verify(iamAuthorizer).authorizePassRole(newRole, "codedeploy.amazonaws.com", REGION);
    }
}
