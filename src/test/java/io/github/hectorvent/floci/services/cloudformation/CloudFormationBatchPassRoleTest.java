package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.batch.BatchService;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * E-FO-10: CFN Batch ServiceRole PassRole before provision (EKS/EventBridge covered via
 * service-level gates that CFN inherits).
 */
@Tag("security-regression")
class CloudFormationBatchPassRoleTest {

    private static final String ACCOUNT_ID = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String SERVICE_ROLE = "arn:aws:iam::000000000000:role/batch-service";

    private final ObjectMapper mapper = new ObjectMapper();
    private InProcessIamAuthorizer iamAuthorizer;
    private BatchService batchService;
    private CloudFormationResourceProvisioner provisioner;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        batchService = mock(BatchService.class);
        ObjectNode response = mapper.createObjectNode();
        response.put("computeEnvironmentArn",
                "arn:aws:batch:" + REGION + ":" + ACCOUNT_ID + ":compute-environment/ce");
        doReturn(response).when(batchService).createComputeEnvironment(any(), eq(REGION));
        provisioner = new CloudFormationResourceProvisioner(
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                mapper,
                null, null, null, null, null, batchService, null,
                null, null, null, null, null, null, null,
                new CloudFormationResourceRegistry(List.of()),
                null, iamAuthorizer);
    }

    @Test
    void batchComputeEnvironmentRequiresPassRoleOnServiceRole() throws Exception {
        JsonNode props = mapper.readTree("""
                {
                  "Type": "MANAGED",
                  "ServiceRole": "%s"
                }
                """.formatted(SERVICE_ROLE));

        provisioner.provision("ComputeEnv", "AWS::Batch::ComputeEnvironment", props,
                engine(), REGION, ACCOUNT_ID, "stack");

        verify(iamAuthorizer).authorizePassRole(SERVICE_ROLE, "batch.amazonaws.com", REGION);
    }

    @Test
    void batchComputeEnvironmentDeniesWhenPassRoleDenied() throws Exception {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(SERVICE_ROLE), eq("batch.amazonaws.com"), eq(REGION));

        JsonNode props = mapper.readTree("""
                {
                  "Type": "MANAGED",
                  "ServiceRole": "%s"
                }
                """.formatted(SERVICE_ROLE));

        var resource = provisioner.provision("ComputeEnv", "AWS::Batch::ComputeEnvironment", props,
                engine(), REGION, ACCOUNT_ID, "stack");
        assertEquals("CREATE_FAILED", resource.getStatus());
        verify(batchService, never()).createComputeEnvironment(any(), eq(REGION));
    }

    private CloudFormationTemplateEngine engine() {
        return new CloudFormationTemplateEngine(ACCOUNT_ID, REGION, "my-stack",
                "stack/id", Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), mapper,
                (Function<String, String>) name -> null);
    }
}
