package io.github.hectorvent.floci.services.emr;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.emr.model.EmrCluster;
import io.github.hectorvent.floci.services.emr.model.EmrStep;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-20: EMR step ExecutionRoleArn requires iam:PassRole.
 */
@Tag("security-regression")
class EmrExecutionRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/emr-exec";

    private InProcessIamAuthorizer iamAuthorizer;
    private EmrService service;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        doReturn(new InMemoryStorage<>()).when(storageFactory).create(anyString(), anyString(), any());
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().emr().defaultReleaseLabel()).thenReturn("emr-7.0.0");
        service = new EmrService(storageFactory, config,
                new RegionResolver(REGION, "000000000000"), iamAuthorizer);
    }

    @Test
    void runJobFlowRequiresPassRoleOnStepExecutionRole() {
        EmrCluster cluster = new EmrCluster();
        cluster.setName("passrole-cluster");
        EmrStep step = new EmrStep();
        step.setName("step1");
        step.setExecutionRoleArn(ROLE_ARN);
        cluster.setSteps(List.of(step));

        service.runJobFlow(cluster, REGION);

        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "elasticmapreduce.amazonaws.com", REGION);
    }

    @Test
    void runJobFlowDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("elasticmapreduce.amazonaws.com"), eq(REGION));

        EmrCluster cluster = new EmrCluster();
        cluster.setName("denied-cluster");
        EmrStep step = new EmrStep();
        step.setName("step1");
        step.setExecutionRoleArn(ROLE_ARN);
        cluster.setSteps(List.of(step));

        AwsException ex = assertThrows(AwsException.class, () -> service.runJobFlow(cluster, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void addJobFlowStepsRequiresPassRole() {
        EmrCluster cluster = new EmrCluster();
        cluster.setName("add-steps-cluster");
        EmrCluster created = service.runJobFlow(cluster, REGION);

        EmrStep step = new EmrStep();
        step.setName("added");
        step.setExecutionRoleArn(ROLE_ARN);
        service.addJobFlowSteps(created.getId(), List.of(step));

        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "elasticmapreduce.amazonaws.com", REGION);
    }
}
