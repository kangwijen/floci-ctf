package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.services.ec2.model.FlowLog;

/**
 * Formats VPC Flow Log records using the AWS default version 2 field order.
 */
public final class VpcFlowLogRecordFormatter {

    private VpcFlowLogRecordFormatter() {}

    public static String formatDefault(VpcFlowLogRecord record) {
        return String.join(" ",
                String.valueOf(record.version()),
                record.accountId(),
                record.interfaceId(),
                record.srcAddr(),
                record.dstAddr(),
                String.valueOf(record.srcPort()),
                String.valueOf(record.dstPort()),
                String.valueOf(record.protocol()),
                String.valueOf(record.packets()),
                String.valueOf(record.bytes()),
                String.valueOf(record.start()),
                String.valueOf(record.end()),
                record.action(),
                record.logStatus());
    }

    public static String format(FlowLog flowLog, VpcFlowLogRecord record) {
        String format = flowLog.getLogFormat();
        if (format == null || format.isBlank()
                || FlowLog.DEFAULT_LOG_FORMAT.equals(format)) {
            return formatDefault(record);
        }
        return format
                .replace("${version}", String.valueOf(record.version()))
                .replace("${account-id}", record.accountId())
                .replace("${interface-id}", record.interfaceId())
                .replace("${srcaddr}", record.srcAddr())
                .replace("${dstaddr}", record.dstAddr())
                .replace("${srcport}", String.valueOf(record.srcPort()))
                .replace("${dstport}", String.valueOf(record.dstPort()))
                .replace("${protocol}", String.valueOf(record.protocol()))
                .replace("${packets}", String.valueOf(record.packets()))
                .replace("${bytes}", String.valueOf(record.bytes()))
                .replace("${start}", String.valueOf(record.start()))
                .replace("${end}", String.valueOf(record.end()))
                .replace("${action}", record.action())
                .replace("${log-status}", record.logStatus());
    }
}
