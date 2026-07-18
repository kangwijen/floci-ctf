package io.github.hectorvent.floci.services.elbv2;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.OutboundUrlGuard;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * E-FO-11: instance-target proxyRequest must use OutboundUrlGuard like the IP-target path
 * when the target is not a registered EC2 instance (SSRF via fake instance id / IP).
 */
@Tag("security-regression")
class ElbV2InstanceTargetEgressDeniedTest {

    private ElbV2DataPlane dataPlane;
    private Ec2Service ec2Service;
    private OutboundUrlGuard guard;

    @BeforeEach
    void setUp() {
        dataPlane = new ElbV2DataPlane();
        ec2Service = mock(Ec2Service.class);
        dataPlane.ec2Service = ec2Service;
        guard = new OutboundUrlGuard(true, List.of(), false);
        dataPlane.outboundUrlGuard = guard;
    }

    @Test
    void instanceTargetWithoutRegisteredEc2RequiresEgressGuard() {
        TargetGroup tg = new TargetGroup();
        tg.setTargetType("instance");

        assertTrue(dataPlane.shouldGuardTargetEgress(tg, "169.254.169.254"));
        assertThrows(AwsException.class,
                () -> guard.validateHttpUrl("http://169.254.169.254"));
    }

    @Test
    void registeredInstanceBridgeIpSkipsEgressGuard() {
        TargetGroup tg = new TargetGroup();
        tg.setTargetType("instance");
        Instance instance = mock(Instance.class);
        when(ec2Service.findInstanceById("i-abc123")).thenReturn(instance);

        assertFalse(dataPlane.shouldGuardTargetEgress(tg, "i-abc123"));
    }

    @Test
    void ipTargetStillRequiresEgressGuard() {
        TargetGroup tg = new TargetGroup();
        tg.setTargetType("ip");

        assertTrue(dataPlane.shouldGuardTargetEgress(tg, "127.0.0.1"));
        assertThrows(AwsException.class, () -> guard.validateHttpUrl("http://127.0.0.1"));
    }
}
