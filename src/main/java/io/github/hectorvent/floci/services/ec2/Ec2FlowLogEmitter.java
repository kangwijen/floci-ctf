package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.model.FlowLog;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceNetworkInterface;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.quarkus.runtime.ShutdownEvent;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Generates synthetic VPC Flow Log records for active flow logs and delivers them
 * to S3 or CloudWatch Logs.
 */
@ApplicationScoped
public class Ec2FlowLogEmitter {

    private static final Logger LOG = Logger.getLogger(Ec2FlowLogEmitter.class);
    private static final long EMIT_INTERVAL_SECONDS = 60L;

    private final Ec2Service ec2Service;
    private final S3Service s3Service;
    private final CloudWatchLogsService cloudWatchLogsService;
    private final String accountId;
    private final InProcessCloudTrailRecorder inProcessCloudTrailRecorder;
    private final InProcessTargetAuthorizer targetAuthorizer;
    private final Random random = new Random();

    private ScheduledExecutorService scheduler;

    @Inject
    public Ec2FlowLogEmitter(Ec2Service ec2Service,
                              S3Service s3Service,
                              CloudWatchLogsService cloudWatchLogsService,
                              EmulatorConfig config,
                              InProcessCloudTrailRecorder inProcessCloudTrailRecorder,
                              InProcessTargetAuthorizer targetAuthorizer) {
        this.ec2Service = ec2Service;
        this.s3Service = s3Service;
        this.cloudWatchLogsService = cloudWatchLogsService;
        this.accountId = config.defaultAccountId();
        this.inProcessCloudTrailRecorder = inProcessCloudTrailRecorder;
        this.targetAuthorizer = targetAuthorizer;
    }

    @PostConstruct
    void start() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ec2-flow-log-emitter");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::emitPeriodicRecords,
                EMIT_INTERVAL_SECONDS, EMIT_INTERVAL_SECONDS, TimeUnit.SECONDS);
    }

    void onShutdown(@Observes ShutdownEvent event) {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    void onFlowLogNetworkActivity(@Observes FlowLogNetworkActivityEvent event) {
        emitForNetworkActivity(event.region(), event.vpcId(), event.subnetId(), event.networkInterfaceId());
    }

    private void emitForNetworkActivity(String region, String vpcId, String subnetId, String networkInterfaceId) {
        for (FlowLog flowLog : ec2Service.getActiveFlowLogs(region)) {
            if (!matchesResource(flowLog, vpcId, subnetId, networkInterfaceId)) {
                continue;
            }
            List<MonitoredEni> enis = resolveMonitoredEnis(flowLog, region);
            for (MonitoredEni eni : enis) {
                if (networkInterfaceId != null && !networkInterfaceId.equals(eni.interfaceId())) {
                    continue;
                }
                deliver(flowLog, buildSyntheticRecord(eni, "ACCEPT"));
            }
        }
    }

    private void emitPeriodicRecords() {
        try {
            for (String region : ec2Service.getSeededRegions()) {
                for (FlowLog flowLog : ec2Service.getActiveFlowLogs(region)) {
                    List<MonitoredEni> enis = resolveMonitoredEnis(flowLog, region);
                    if (enis.isEmpty()) {
                        deliver(flowLog, buildPlaceholderRecord(flowLog));
                        continue;
                    }
                    int count = Math.min(2, enis.size());
                    for (int i = 0; i < count; i++) {
                        MonitoredEni eni = enis.get(i % enis.size());
                        String action = random.nextBoolean() ? "ACCEPT" : "ACCEPT";
                        deliver(flowLog, buildSyntheticRecord(eni, action));
                    }
                }
            }
        } catch (Exception e) {
            LOG.debugv("Periodic flow log emission failed: {0}", e.getMessage());
        }
    }

    private boolean matchesResource(FlowLog flowLog, String vpcId, String subnetId, String eniId) {
        return switch (flowLog.getResourceType()) {
            case "VPC" -> vpcId != null && vpcId.equals(flowLog.getResourceId());
            case "Subnet" -> subnetId != null && subnetId.equals(flowLog.getResourceId());
            case "NetworkInterface" -> eniId != null && eniId.equals(flowLog.getResourceId());
            default -> false;
        };
    }

    private List<MonitoredEni> resolveMonitoredEnis(FlowLog flowLog, String region) {
        List<MonitoredEni> result = new ArrayList<>();
        switch (flowLog.getResourceType()) {
            case "VPC" -> ec2Service.listInstances(region).stream()
                    .filter(inst -> flowLog.getResourceId().equals(inst.getVpcId()))
                    .forEach(inst -> addInstanceEnis(inst, result));
            case "Subnet" -> ec2Service.listInstances(region).stream()
                    .filter(inst -> flowLog.getResourceId().equals(inst.getSubnetId()))
                    .forEach(inst -> addInstanceEnis(inst, result));
            case "NetworkInterface" -> ec2Service.listInstances(region).stream()
                    .flatMap(inst -> inst.getNetworkInterfaces().stream()
                            .filter(eni -> flowLog.getResourceId().equals(eni.getNetworkInterfaceId()))
                            .map(eni -> toMonitoredEni(inst, eni)))
                    .forEach(result::add);
            default -> { }
        }
        return result;
    }

    private void addInstanceEnis(Instance inst, List<MonitoredEni> result) {
        for (InstanceNetworkInterface eni : inst.getNetworkInterfaces()) {
            result.add(toMonitoredEni(inst, eni));
        }
    }

    private MonitoredEni toMonitoredEni(Instance inst, InstanceNetworkInterface eni) {
        return new MonitoredEni(
                eni.getNetworkInterfaceId(),
                eni.getPrivateIpAddress(),
                inst.getVpcId(),
                inst.getSubnetId(),
                inst.getInstanceId());
    }

    private VpcFlowLogRecord buildPlaceholderRecord(FlowLog flowLog) {
        long now = Instant.now().getEpochSecond();
        return new VpcFlowLogRecord(
                2,
                accountId,
                "eni-" + flowLog.getFlowLogId().substring(3, Math.min(11, flowLog.getFlowLogId().length())),
                "10.0.0.1",
                "10.0.0.2",
                443,
                54321,
                6,
                1,
                52,
                now - 5,
                now,
                "ACCEPT",
                "OK");
    }

    private VpcFlowLogRecord buildSyntheticRecord(MonitoredEni eni, String action) {
        long now = Instant.now().getEpochSecond();
        String dst = randomPrivateIp();
        int srcPort = 1024 + random.nextInt(60000);
        int dstPort = pickDstPort();
        long packets = 1 + random.nextInt(20);
        long bytes = packets * (40 + random.nextInt(1400));
        return new VpcFlowLogRecord(
                2,
                accountId,
                eni.interfaceId(),
                eni.privateIp() != null ? eni.privateIp() : "10.0.0.1",
                dst,
                srcPort,
                dstPort,
                6,
                packets,
                bytes,
                now - random.nextInt(30) - 1,
                now,
                action,
                "OK");
    }

    private String randomPrivateIp() {
        return "10." + random.nextInt(256) + "." + random.nextInt(256) + "." + (1 + random.nextInt(254));
    }

    private int pickDstPort() {
        int[] common = {80, 443, 22, 53, 8080};
        return common[random.nextInt(common.length)];
    }

    private void deliver(FlowLog flowLog, VpcFlowLogRecord record) {
        if (!shouldDeliverAction(flowLog, record.action())) {
            return;
        }
        String line = VpcFlowLogRecordFormatter.format(flowLog, record);
        try {
            if ("s3".equals(flowLog.getLogDestinationType())) {
                deliverToS3(flowLog, line);
            } else if ("cloud-watch-logs".equals(flowLog.getLogDestinationType())) {
                deliverToCloudWatch(flowLog, record.interfaceId(), line);
            }
        } catch (Exception e) {
            LOG.debugv("Flow log delivery failed for {0}: {1}", flowLog.getFlowLogId(), e.getMessage());
            flowLog.setDeliverLogsStatus("FAILED");
        }
    }

    private boolean shouldDeliverAction(FlowLog flowLog, String action) {
        String trafficType = flowLog.getTrafficType();
        if (trafficType == null || "ALL".equals(trafficType)) {
            return true;
        }
        return trafficType.equals(action);
    }

    private void deliverToS3(FlowLog flowLog, String line) {
        S3Destination dest = parseS3Destination(flowLog.getLogDestination());
        String key = buildS3Key(flowLog, dest.prefix());
        byte[] payload;
        try {
            byte[] existing = s3Service.getObject(dest.bucket(), key).getData();
            String combined = new String(existing, StandardCharsets.UTF_8) + line + "\n";
            payload = combined.getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            payload = (line + "\n").getBytes(StandardCharsets.UTF_8);
        }
        targetAuthorizer.authorizeVpcFlowLogsS3Put(dest.bucket(), key, flowLog.getRegion());
        s3Service.putObject(dest.bucket(), key, payload, "text/plain", Map.of());
        recordFlowLogS3PutObject(flowLog.getRegion(), dest.bucket(), key);
        flowLog.setDeliverLogsStatus("SUCCESS");
    }

    private void recordFlowLogS3PutObject(String region, String bucket, String key) {
        String invokedBy = "ec2.amazonaws.com";
        inProcessCloudTrailRecorder.record(InProcessAuditContext.builder()
                .region(region)
                .eventSource("s3.amazonaws.com")
                .eventName("PutObject")
                .credentialScope("s3")
                .requestParameters(Map.of(
                        "bucketName", bucket,
                        "key", key))
                .invokedBy(invokedBy)
                .servicePrincipal(invokedBy)
                .managementEvent(false)
                .eventCategory("Data")
                .build());
    }

    private void deliverToCloudWatch(FlowLog flowLog, String interfaceId, String line) {
        String groupName = resolveLogGroupName(flowLog);
        String streamName = interfaceId != null ? interfaceId : flowLog.getFlowLogId();
        String region = flowLog.getRegion();
        if (cloudWatchLogsService.describeLogGroups(groupName, region).isEmpty()) {
            cloudWatchLogsService.createLogGroup(groupName, null, null, region);
        }
        if (cloudWatchLogsService.describeLogStreams(groupName, streamName, region).isEmpty()) {
            cloudWatchLogsService.createLogStream(groupName, streamName, region);
        }
        Map<String, Object> event = new HashMap<>();
        event.put("timestamp", System.currentTimeMillis());
        event.put("message", line);
        cloudWatchLogsService.putLogEvents(groupName, streamName, List.of(event), region);
        flowLog.setDeliverLogsStatus("SUCCESS");
    }

    private String resolveLogGroupName(FlowLog flowLog) {
        if (flowLog.getLogGroupName() != null && !flowLog.getLogGroupName().isBlank()) {
            return flowLog.getLogGroupName();
        }
        String dest = flowLog.getLogDestination();
        if (dest == null) {
            return "vpc-flow-logs";
        }
        int idx = dest.indexOf(":log-group:");
        if (idx >= 0) {
            String remainder = dest.substring(idx + ":log-group:".length());
            int end = remainder.indexOf(':');
            return end >= 0 ? remainder.substring(0, end) : remainder;
        }
        return dest;
    }

    private String buildS3Key(FlowLog flowLog, String prefix) {
        Instant now = Instant.now();
        String datePath = DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC).format(now);
        String dayStamp = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC).format(now);
        String base = "AWSLogs/" + accountId + "/vpcflowlogs/" + flowLog.getRegion() + "/" + datePath + "/"
                + accountId + "_vpcflowlogs_" + flowLog.getRegion() + "_" + dayStamp + "_"
                + flowLog.getFlowLogId() + ".log";
        if (prefix == null || prefix.isBlank()) {
            return base;
        }
        String normalized = prefix.endsWith("/") ? prefix : prefix + "/";
        return normalized + base;
    }

    private S3Destination parseS3Destination(String arn) {
        if (arn == null || arn.isBlank()) {
            throw new IllegalArgumentException("S3 log destination ARN is required");
        }
        String remainder = arn;
        if (arn.startsWith("arn:aws:s3:::")) {
            remainder = arn.substring("arn:aws:s3:::".length());
        } else if (arn.startsWith("arn:aws:s3:")) {
            int bucketStart = arn.indexOf(":::");
            remainder = bucketStart >= 0 ? arn.substring(bucketStart + 3) : arn;
        }
        int slash = remainder.indexOf('/');
        if (slash < 0) {
            return new S3Destination(remainder, "");
        }
        return new S3Destination(remainder.substring(0, slash), remainder.substring(slash + 1));
    }

    private record MonitoredEni(String interfaceId, String privateIp, String vpcId, String subnetId,
                                String instanceId) {}

    private record S3Destination(String bucket, String prefix) {}
}
