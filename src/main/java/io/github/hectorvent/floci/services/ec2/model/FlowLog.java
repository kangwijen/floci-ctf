package io.github.hectorvent.floci.services.ec2.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class FlowLog {

    public static final String DEFAULT_LOG_FORMAT =
            "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} "
                    + "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}";

    private String flowLogId;
    private String resourceId;
    private String resourceType;
    private String logDestinationType;
    private String logDestination;
    private String logGroupName;
    private String trafficType = "ALL";
    private String flowLogStatus = "ACTIVE";
    private String deliverLogsStatus = "SUCCESS";
    private String deliverLogsPermissionArn;
    private Instant creationTime;
    private String region;
    private int maxAggregationInterval = 600;
    private String logFormat = DEFAULT_LOG_FORMAT;
    private List<Tag> tags = new ArrayList<>();

    public FlowLog() {}

    public String getFlowLogId() { return flowLogId; }
    public void setFlowLogId(String flowLogId) { this.flowLogId = flowLogId; }

    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }

    public String getResourceType() { return resourceType; }
    public void setResourceType(String resourceType) { this.resourceType = resourceType; }

    public String getLogDestinationType() { return logDestinationType; }
    public void setLogDestinationType(String logDestinationType) { this.logDestinationType = logDestinationType; }

    public String getLogDestination() { return logDestination; }
    public void setLogDestination(String logDestination) { this.logDestination = logDestination; }

    public String getLogGroupName() { return logGroupName; }
    public void setLogGroupName(String logGroupName) { this.logGroupName = logGroupName; }

    public String getTrafficType() { return trafficType; }
    public void setTrafficType(String trafficType) { this.trafficType = trafficType; }

    public String getFlowLogStatus() { return flowLogStatus; }
    public void setFlowLogStatus(String flowLogStatus) { this.flowLogStatus = flowLogStatus; }

    public String getDeliverLogsStatus() { return deliverLogsStatus; }
    public void setDeliverLogsStatus(String deliverLogsStatus) { this.deliverLogsStatus = deliverLogsStatus; }

    public String getDeliverLogsPermissionArn() { return deliverLogsPermissionArn; }
    public void setDeliverLogsPermissionArn(String deliverLogsPermissionArn) {
        this.deliverLogsPermissionArn = deliverLogsPermissionArn;
    }

    public Instant getCreationTime() { return creationTime; }
    public void setCreationTime(Instant creationTime) { this.creationTime = creationTime; }

    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }

    public int getMaxAggregationInterval() { return maxAggregationInterval; }
    public void setMaxAggregationInterval(int maxAggregationInterval) {
        this.maxAggregationInterval = maxAggregationInterval;
    }

    public String getLogFormat() { return logFormat; }
    public void setLogFormat(String logFormat) { this.logFormat = logFormat; }

    public List<Tag> getTags() { return tags; }
    public void setTags(List<Tag> tags) { this.tags = tags; }
}
