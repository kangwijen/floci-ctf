package io.github.hectorvent.floci.services.cloudformation;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("security-regression")
class CfnIamConditionContextTest {

    @Test
    void calledViaCloudFormationSetsServicePrincipal() {
        assertEquals("cloudformation.amazonaws.com",
                CfnIamConditionContext.calledViaCloudFormation().get("aws:calledvia"));
    }
}
