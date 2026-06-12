package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.services.ec2.model.FlowLog;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VpcFlowLogRecordFormatterTest {

    @Test
    void formatsDefaultVersion2Record() {
        VpcFlowLogRecord record = new VpcFlowLogRecord(
                2,
                "123456789012",
                "eni-0abc1234",
                "10.0.1.5",
                "10.0.2.10",
                443,
                49734,
                6,
                14,
                892,
                1686835200L,
                1686835260L,
                "ACCEPT",
                "OK");

        String line = VpcFlowLogRecordFormatter.formatDefault(record);

        assertEquals(
                "2 123456789012 eni-0abc1234 10.0.1.5 10.0.2.10 443 49734 6 14 892 1686835200 1686835260 ACCEPT OK",
                line);
    }

    @Test
    void formatsCustomLogFormatFromFlowLog() {
        FlowLog flowLog = new FlowLog();
        flowLog.setLogFormat("${version} ${interface-id} ${action} ${log-status}");

        VpcFlowLogRecord record = new VpcFlowLogRecord(
                2, "000000000000", "eni-test", "1.2.3.4", "5.6.7.8",
                80, 8080, 6, 1, 64, 100, 200, "REJECT", "NODATA");

        assertEquals("2 eni-test REJECT NODATA", VpcFlowLogRecordFormatter.format(flowLog, record));
    }
}
