package io.github.hectorvent.floci.services.ec2;

public record VpcFlowLogRecord(
        int version,
        String accountId,
        String interfaceId,
        String srcAddr,
        String dstAddr,
        int srcPort,
        int dstPort,
        int protocol,
        long packets,
        long bytes,
        long start,
        long end,
        String action,
        String logStatus
) {}
