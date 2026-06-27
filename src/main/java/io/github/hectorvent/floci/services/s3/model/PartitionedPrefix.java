package io.github.hectorvent.floci.services.s3.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class PartitionedPrefix {

    /** {@code EventTime} (default) or {@code DeliveryTime}. */
    private String partitionDateSource = "EventTime";

    public PartitionedPrefix() {
    }

    public PartitionedPrefix(String partitionDateSource) {
        this.partitionDateSource = partitionDateSource != null && !partitionDateSource.isBlank()
                ? partitionDateSource : "EventTime";
    }

    public String getPartitionDateSource() {
        return partitionDateSource;
    }

    public void setPartitionDateSource(String partitionDateSource) {
        this.partitionDateSource = partitionDateSource;
    }

    public boolean isDeliveryTime() {
        return "DeliveryTime".equalsIgnoreCase(partitionDateSource);
    }
}
