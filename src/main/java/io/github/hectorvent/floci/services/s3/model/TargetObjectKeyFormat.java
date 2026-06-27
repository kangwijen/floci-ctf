package io.github.hectorvent.floci.services.s3.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * AWS {@code TargetObjectKeyFormat}: exactly one of {@link #simplePrefix} or {@link #partitionedPrefix}.
 */
@RegisterForReflection
public class TargetObjectKeyFormat {

    private boolean simplePrefix;
    private PartitionedPrefix partitionedPrefix;

    public static TargetObjectKeyFormat simplePrefix() {
        TargetObjectKeyFormat format = new TargetObjectKeyFormat();
        format.simplePrefix = true;
        return format;
    }

    public static TargetObjectKeyFormat partitionedPrefix(PartitionedPrefix partitionedPrefix) {
        TargetObjectKeyFormat format = new TargetObjectKeyFormat();
        format.partitionedPrefix = partitionedPrefix != null ? partitionedPrefix : new PartitionedPrefix();
        return format;
    }

    public boolean isSimplePrefix() {
        return simplePrefix || partitionedPrefix == null;
    }

    public void setSimplePrefix(boolean simplePrefix) {
        this.simplePrefix = simplePrefix;
        if (simplePrefix) {
            this.partitionedPrefix = null;
        }
    }

    public PartitionedPrefix getPartitionedPrefix() {
        return partitionedPrefix;
    }

    public void setPartitionedPrefix(PartitionedPrefix partitionedPrefix) {
        this.partitionedPrefix = partitionedPrefix;
        if (partitionedPrefix != null) {
            this.simplePrefix = false;
        }
    }
}
