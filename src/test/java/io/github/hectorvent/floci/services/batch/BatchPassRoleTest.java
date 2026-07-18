package io.github.hectorvent.floci.services.batch;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.batch.model.BatchComputeEnvironment;
import io.github.hectorvent.floci.services.batch.model.BatchJob;
import io.github.hectorvent.floci.services.batch.model.BatchJobDefinition;
import io.github.hectorvent.floci.services.batch.model.BatchJobQueue;
import io.github.hectorvent.floci.services.iam.ComputePassRoleGate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-01: Batch create paths must require iam:PassRole on service, job, and execution roles.
 */
@Tag("security-regression")
class BatchPassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String SERVICE_ROLE = "arn:aws:iam::000000000000:role/batch-service";
    private static final String JOB_ROLE = "arn:aws:iam::000000000000:role/batch-job";
    private static final String EXEC_ROLE = "arn:aws:iam::000000000000:role/batch-exec";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private ComputePassRoleGate passRoleGate;
    private BatchService service;

    @BeforeEach
    void setUp() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.BatchServiceConfig batch = mock(EmulatorConfig.BatchServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.batch()).thenReturn(batch);
        when(batch.runnerMode()).thenReturn("immediate");

        passRoleGate = mock(ComputePassRoleGate.class);
        service = new BatchService(
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new RegionResolver(REGION, ACCOUNT),
                config,
                objectMapper,
                mock(BatchDockerRunner.class),
                passRoleGate);
    }

    @Test
    void createComputeEnvironmentRequiresPassRoleOnServiceRole() throws Exception {
        service.createComputeEnvironment(json("""
                {
                  "computeEnvironmentName":"passrole-ce",
                  "type":"MANAGED",
                  "serviceRole":"%s"
                }
                """.formatted(SERVICE_ROLE)), REGION);

        verify(passRoleGate).authorizeBatchServiceRole(SERVICE_ROLE, REGION);
    }

    @Test
    void createComputeEnvironmentDeniesWhenPassRoleDenied() throws Exception {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeBatchServiceRole(eq(SERVICE_ROLE), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createComputeEnvironment(json("""
                        {
                          "computeEnvironmentName":"denied-ce",
                          "type":"MANAGED",
                          "serviceRole":"%s"
                        }
                        """.formatted(SERVICE_ROLE)), REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void registerJobDefinitionRequiresPassRoleOnJobAndExecutionRoles() throws Exception {
        service.registerJobDefinition(json("""
                {
                  "jobDefinitionName":"passrole-job",
                  "type":"container",
                  "containerProperties":{
                    "image":"public.ecr.aws/example/job:latest",
                    "jobRoleArn":"%s",
                    "executionRoleArn":"%s"
                  }
                }
                """.formatted(JOB_ROLE, EXEC_ROLE)), REGION);

        verify(passRoleGate).authorizeBatchJobRoles(JOB_ROLE, EXEC_ROLE, REGION);
    }

    @Test
    void registerJobDefinitionDeniesWhenPassRoleDenied() throws Exception {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeBatchJobRoles(eq(JOB_ROLE), eq(EXEC_ROLE), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.registerJobDefinition(json("""
                        {
                          "jobDefinitionName":"denied-job",
                          "type":"container",
                          "containerProperties":{
                            "image":"public.ecr.aws/example/job:latest",
                            "jobRoleArn":"%s",
                            "executionRoleArn":"%s"
                          }
                        }
                        """.formatted(JOB_ROLE, EXEC_ROLE)), REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    private ObjectNode json(String body) throws Exception {
        return (ObjectNode) objectMapper.readTree(body);
    }
}
