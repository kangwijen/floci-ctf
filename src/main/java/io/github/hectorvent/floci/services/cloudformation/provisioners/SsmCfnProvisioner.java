package io.github.hectorvent.floci.services.cloudformation.provisioners;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.ssm.SsmService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Set;

/**
 * CloudFormation provisioning for {@code AWS::SSM::Parameter}.
 * Extracted from {@code CloudFormationResourceProvisioner} so non-IAM registry arms do not share
 * the IAM create/attach code path.
 */
@ApplicationScoped
public class SsmCfnProvisioner implements CfnResourceProvisioner {

    private final SsmService ssmService;

    @Inject
    public SsmCfnProvisioner(SsmService ssmService) {
        this.ssmService = ssmService;
    }

    @Override
    public Set<String> resourceTypes() {
        return Set.of("AWS::SSM::Parameter");
    }

    @Override
    public void provision(StackResource r, JsonNode props, ProvisionContext ctx) {
        String name = ctx.resolveOptional(props, "Name");
        if (name == null || name.isBlank()) {
            name = ctx.generatePhysicalName(r.getLogicalId(), 2048, false);
        }
        String value = ctx.resolveOptional(props, "Value");
        if (value == null) {
            value = "";
        }
        String type = ctx.resolveOptional(props, "Type");
        if (type == null) {
            type = "String";
        }
        ssmService.putParameter(name, value, type, null, true, ctx.region());
        r.setPhysicalId(name);
    }

    @Override
    public void delete(String resourceType, String physicalId, String region) {
        ssmService.deleteParameter(physicalId, region);
    }
}
