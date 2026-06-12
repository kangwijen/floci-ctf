package io.github.hectorvent.floci.services.ec2;

public record FlowLogNetworkActivityEvent(
        String region,
        String vpcId,
        String subnetId,
        String networkInterfaceId
) {}
