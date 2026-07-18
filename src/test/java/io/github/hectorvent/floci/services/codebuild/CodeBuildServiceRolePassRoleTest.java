package io.github.hectorvent.floci.services.codebuild;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.codebuild.model.ProjectArtifacts;
import io.github.hectorvent.floci.services.codebuild.model.ProjectEnvironment;
import io.github.hectorvent.floci.services.codebuild.model.ProjectSource;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
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
 * E-FO-08: project serviceRole create/update requires iam:PassRole.
 */
@Tag("security-regression")
class CodeBuildServiceRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/codebuild-role";

    private InProcessIamAuthorizer iamAuthorizer;
    private CodeBuildService service;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        service = new CodeBuildService(mock(CodeBuildRunner.class), mock(EmulatorConfig.class),
                mock(StorageFactory.class), iamAuthorizer);
    }

    @Test
    void createProjectRequiresPassRole() {
        service.createProject(REGION, ACCOUNT, "passrole-proj", null,
                source(), null, null, artifacts(), null, environment(), ROLE_ARN,
                null, null, null, null, null, null, null);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "codebuild.amazonaws.com", REGION);
    }

    @Test
    void createProjectDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("codebuild.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createProject(REGION, ACCOUNT, "denied-proj", null,
                        source(), null, null, artifacts(), null, environment(), ROLE_ARN,
                        null, null, null, null, null, null, null));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void updateProjectRequiresPassRoleOnRoleChange() {
        service.createProject(REGION, ACCOUNT, "upd-proj", null,
                source(), null, null, artifacts(), null, environment(), ROLE_ARN,
                null, null, null, null, null, null, null);
        String newRole = "arn:aws:iam::000000000000:role/codebuild-role-2";
        service.updateProject(REGION, "upd-proj", null, null, null, null, null, null, null,
                newRole, null, null, null, null, null, null, null);
        verify(iamAuthorizer).authorizePassRole(newRole, "codebuild.amazonaws.com", REGION);
    }

    private static ProjectSource source() {
        ProjectSource source = new ProjectSource();
        source.setType("NO_SOURCE");
        return source;
    }

    private static ProjectArtifacts artifacts() {
        ProjectArtifacts artifacts = new ProjectArtifacts();
        artifacts.setType("NO_ARTIFACTS");
        return artifacts;
    }

    private static ProjectEnvironment environment() {
        ProjectEnvironment environment = new ProjectEnvironment();
        environment.setType("LINUX_CONTAINER");
        environment.setImage("aws/codebuild/standard:7.0");
        environment.setComputeType("BUILD_GENERAL1_SMALL");
        return environment;
    }
}
