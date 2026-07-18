package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.services.cloudformation.CloudFormationTemplateEngine;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.ssm.SsmService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * SSM CFN provisioner lives on the registry path, separate from IAM create/attach arms.
 */
@Tag("security-regression")
class SsmCfnProvisionerTest {

    private final SsmService ssm = mock(SsmService.class);
    private final SsmCfnProvisioner provisioner = new SsmCfnProvisioner(ssm);
    private final ObjectMapper mapper = new ObjectMapper();

    private ProvisionContext ctx() {
        CloudFormationTemplateEngine engine = mock(CloudFormationTemplateEngine.class);
        when(engine.resolve(any())).thenAnswer(inv -> {
            JsonNode node = inv.getArgument(0);
            return node == null ? null : node.asText();
        });
        return new ProvisionContext(engine, "us-east-1", "000000000000", "my-stack");
    }

    @Test
    void parameterPutsValueAndSetsPhysicalId() {
        StackResource r = new StackResource();
        r.setLogicalId("MyParam");
        r.setResourceType("AWS::SSM::Parameter");
        r.setAttributes(new HashMap<>());
        ObjectNode props = mapper.createObjectNode()
                .put("Name", "/app/token")
                .put("Value", "secret")
                .put("Type", "SecureString");

        provisioner.provision(r, props, ctx());

        assertEquals("/app/token", r.getPhysicalId());
        verify(ssm).putParameter(eq("/app/token"), eq("secret"), eq("SecureString"),
                isNull(), eq(true), eq("us-east-1"));
    }

    @Test
    void deleteDelegatesToService() {
        provisioner.delete("AWS::SSM::Parameter", "/app/token", "us-east-1");
        verify(ssm).deleteParameter("/app/token", "us-east-1");
    }
}
